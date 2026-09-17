// sleepable_probe.c — P0-14 availability probe: is BPF_F_SLEEPABLE
// accepted on uprobe_multi link_create for this kernel? Loads a trivial
// kprobe-type prog, then attempts the link twice: control (flags=0, must
// succeed — proves the harness) and probe (flags=BPF_F_SLEEPABLE).
// Prints: SLEEPABLE control=<ok|ERRNO> flags16=<ok|ERRNO>
// Exit 0 iff the control succeeds (probe outcome is data, not failure).
// No kernel headers needed: UAPI values mirrored from bpf-sys/src/lib.rs.
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define BPF_PROG_LOAD 5
#define BPF_LINK_CREATE 28
#define BPF_PROG_TYPE_KPROBE 2
#define BPF_TRACE_UPROBE_MULTI 48
#define BPF_F_SLEEPABLE 16

struct prog_attr {
    uint32_t prog_type, insn_cnt;
    uint64_t insns, license;
    uint32_t log_level, log_size;
    uint64_t log_buf;
    uint32_t kern_version, prog_flags;
    char prog_name[16];
    uint32_t prog_ifindex, expected_attach_type;
};

struct link_attr {
    uint32_t prog_fd, target_fd, attach_type, flags;
    uint64_t path, offsets, ref_ctr_offsets, cookies;
    uint32_t cnt, mflags, pid;
};

struct bpf_insn { uint8_t code, dst_src; int16_t off; int32_t imm; };

static int bpf(int cmd, void *attr, unsigned size) {
    return (int)syscall(__NR_bpf, cmd, attr, size);
}

static const char *errname(int e) {
    switch (e) {
    case 0: return "ok";
    case EINVAL: return "EINVAL";
    case EPERM: return "EPERM";
    case EACCES: return "EACCES";
    case ENOENT: return "ENOENT";
    case ENOSYS: return "ENOSYS";
    default: return "OTHER";
    }
}

static int try_link(int prog_fd, const char *path, uint64_t *offs, uint64_t *cookies, uint32_t flags) {
    struct link_attr a;
    memset(&a, 0, sizeof a);
    a.prog_fd = (uint32_t)prog_fd;
    a.attach_type = BPF_TRACE_UPROBE_MULTI;
    a.path = (uint64_t)path;
    a.offsets = (uint64_t)offs;
    a.cookies = (uint64_t)cookies;
    a.cnt = 1;
    a.mflags = flags;
    a.pid = 0;
    int fd = bpf(BPF_LINK_CREATE, &a, sizeof a);
    if (fd >= 0) close(fd);
    return fd >= 0 ? 0 : errno;
}

int main(void) {
    struct bpf_insn insns[2] = {
        { 0xb7, 0x00, 0, 0 }, /* r0 = 0 */
        { 0x95, 0x00, 0, 0 }, /* exit */
    };
    struct prog_attr p;
    memset(&p, 0, sizeof p);
    p.prog_type = BPF_PROG_TYPE_KPROBE;
    p.expected_attach_type = BPF_TRACE_UPROBE_MULTI;
    p.insn_cnt = 2;
    p.insns = (uint64_t)insns;
    p.license = (uint64_t)"GPL";
    int prog = bpf(BPF_PROG_LOAD, &p, sizeof p);
    if (prog < 0) {
        printf("SLEEPABLE control=LOAD-%s flags16=unprobed\n", errname(errno));
        return 1;
    }
    /* /bin/true exists on all lanes; 0x1000 is inside the file. */
    uint64_t offs[1] = { 0x1000 }, cookies[1] = { 0 };
    int c = try_link(prog, "/bin/true", offs, cookies, 0);
    int s = try_link(prog, "/bin/true", offs, cookies, BPF_F_SLEEPABLE);
    printf("SLEEPABLE control=%s flags16=%s\n", errname(c), errname(s));
    close(prog);
    return c == 0 ? 0 : 1;
}
