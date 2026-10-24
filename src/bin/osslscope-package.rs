// SPDX-License-Identifier: GPL-3.0-or-later
//! Separate source-sealing entrypoint. No capture, load, attach or acquisition path.
use osslscope::package::{
    PackageError,
    inventory::verify_closure,
    records::sha256,
    source::{SealingRequest, SourceTree, seal_source},
};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};

fn usage() -> ! {
    eprintln!(
        "usage: osslscope-package seal-source --root DIR --inputs DIR --request FILE|- --output NEW_DIR"
    );
    std::process::exit(2)
}
fn run() -> Result<(), PackageError> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("seal-source") {
        usage();
    }
    let mut values = BTreeMap::new();
    while let Some(key) = args.next() {
        if !matches!(
            key.as_str(),
            "--root" | "--inputs" | "--request" | "--output"
        ) || values.contains_key(&key)
        {
            usage();
        }
        let value = args.next().unwrap_or_else(|| usage());
        values.insert(key, value);
    }
    if values.len() != 4 {
        usage();
    }
    let root = PathBuf::from(&values["--root"]);
    let inputs = PathBuf::from(&values["--inputs"]);
    let output = PathBuf::from(&values["--output"]);
    let mut bytes = Vec::new();
    if values["--request"] == "-" {
        std::io::stdin()
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|e| PackageError::unreadable(e.to_string()))?;
    } else {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&values["--request"])
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    PackageError::unavailable("source sealing request")
                } else {
                    PackageError::unreadable(e.to_string())
                }
            })?;
        if !file
            .metadata()
            .map_err(|e| PackageError::unreadable(e.to_string()))?
            .is_file()
        {
            return Err(PackageError::invalid("request is not regular file"));
        }
        file.take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|e| PackageError::unreadable(e.to_string()))?;
    }
    let request = SealingRequest::parse_json(&inputs, &bytes)?;
    let tree = SourceTree::open(&root)?;
    let sealed = seal_source(
        &tree,
        &request.config,
        &request.dependencies,
        &request.tools,
    )?;
    verify_closure(&sealed)?;
    // Output creation happens only after source/closure admission. This is an
    // owned source-kit directory, never an installation transaction.
    let parent = output
        .parent()
        .ok_or_else(|| PackageError::invalid("output requires parent directory"))?
        .canonicalize()
        .map_err(|e| PackageError::unreadable(e.to_string()))?;
    let leaf = output
        .file_name()
        .ok_or_else(|| PackageError::invalid("output requires new directory name"))?;
    let destination = parent.join(leaf);
    if destination.starts_with(
        root.canonicalize()
            .map_err(|e| PackageError::unreadable(e.to_string()))?,
    ) || destination.starts_with(
        inputs
            .canonicalize()
            .map_err(|e| PackageError::unreadable(e.to_string()))?,
    ) || destination.exists()
    {
        return Err(PackageError::invalid(
            "output must be a new directory outside source and input roots",
        ));
    }
    fs::create_dir(&destination).map_err(|e| PackageError::unreadable(e.to_string()))?;
    let result = (|| {
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o755))
            .map_err(|e| PackageError::unreadable(e.to_string()))?;
        for (path, data) in sealed.retained_assets().chain(std::iter::once((
            "build-inputs.json",
            sealed.input_bytes.as_slice(),
        ))) {
            let full = destination.join(path);
            let directory = full.parent().unwrap();
            fs::create_dir_all(directory).map_err(|e| PackageError::unreadable(e.to_string()))?;
            let mut current = directory;
            while current != destination {
                fs::set_permissions(current, fs::Permissions::from_mode(0o755))
                    .map_err(|e| PackageError::unreadable(e.to_string()))?;
                current = current.parent().unwrap();
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .custom_flags(libc::O_NOFOLLOW)
                .open(full)
                .map_err(|e| PackageError::unreadable(e.to_string()))?;
            file.write_all(data)
                .map_err(|e| PackageError::unreadable(e.to_string()))?;
            file.set_permissions(fs::Permissions::from_mode(0o644))
                .map_err(|e| PackageError::unreadable(e.to_string()))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&destination);
    }
    result?;
    println!("sealed-source input_id={}", sha256(&sealed.input_bytes));
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(if matches!(error, PackageError::Unavailable { .. }) {
            3
        } else {
            1
        });
    }
}
