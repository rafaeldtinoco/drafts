//go:build exclude

#include <vmlinux.h>
#include <headers.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN                   16
#define PERF_EVENT_ARRAY_MAX_ENTRIES    1024
#define HASHMAP_MAX_ENTRIES             1024
#define PERCPU_HASHMAP_MAX_ENTRIES      1024
#define LRU_PERCPU_HASHAMAP_MAX_ENTRIES 102400

enum event_type {
    EVENT_CGROUP_SKB_INGRESS = 1,
    EVENT_CGROUP_SKB_EGRESS,
    EVENT_KPROBE_SOCK_ALLOC_FILE,
    EVENT_KRETPROBE_SOCK_ALLOC_FILE,
    EVENT_KPROBE_CGROUP_BPF_FILTER_SKB,
    EVENT_KRETPROBE_CGROUP_BPF_FILTER_SKB,
};

//
// internal stuff
//

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, PERF_EVENT_ARRAY_MAX_ENTRIES);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} perfbuffer SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HASHMAP_MAX_ENTRIES);
    __type(key, u32);  // key = event_type
    __type(value, u8); // value = 0|1 = enabled/disabled
} enabled SEC(".maps");

static __always_inline u32 event_enabled(u32 type)
{
    u8 *value = bpf_map_lookup_elem(&enabled, &type);
    if (!value)
        return 0;

    return 1;
}

typedef struct entry {
    long unsigned int args[6];
} entry_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH); // enter & exit syscall in same cpu
    __uint(max_entries, PERCPU_HASHMAP_MAX_ENTRIES);
    __type(key, u32); // tgid
    __type(value, struct entry);
} entrymap SEC(".maps");

typedef struct task_info {
    u64 start_time;           // task start time
    u32 pid;                  // host process id
    u32 tgid;                 // host thread group id
    u32 ppid;                 // host parent process id
    u32 uid;                  // user id
    u32 gid;                  // group id
    char comm[TASK_COMM_LEN]; // command line
    u32 padding;              // padding
} task_info_t;

struct net_info {
    u32 family;
    u32 type;
    u32 protocol;
    u32 src_ipv4;
    u32 dst_ipv4;
	u16 src_port;
	u16 dst_port;
    u64 socket_cookie;
} netinfo_t;

struct event_data {
    struct task_info task;
    u32 event_type;
    u32 padding;
    u64 event_timestamp;
    struct net_info net;
} event_data_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, PERCPU_HASHMAP_MAX_ENTRIES);
    __type(key, u8); // single entry == 0
    //__type(value, u64); // inode TODO: save the task_info directly instead of inode
    __type(value, struct event_data); // inode TODO: save the task_info directly instead of inode
} cgrpctxmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HASHMAP_MAX_ENTRIES);
    __type(key, u64); // socket inode number
    __type(value, struct task_info);
} inodemap SEC(".maps");

//
// helper functions
//

static __always_inline struct task_struct *get_task_struct()
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    return task;
}

static __always_inline u32 get_uid()
{
    u64 id = bpf_get_current_uid_gid();
    u32 uid = id;
    return uid;
}
static __always_inline u32 get_uid_alternative(struct task_struct *task)
{
    // bpf_get_current_uid_gid() provides namespace resolved uid
    // this approach gets uid from root namespace only
    // (TODO: from_kgid()/from_kuid() logic here)
    kuid_t uid = BPF_CORE_READ(task, cred, uid);
    return uid.val;
}

static __always_inline u32 get_gid()
{
    u64 id = bpf_get_current_uid_gid();
    u32 gid = id >> 32;
    return gid;
}
static __always_inline u32 get_gid_alternative(struct task_struct *task)
{
    // bpf_get_current_uid_gid() provides namespace resolved uid
    // this approach gets uid from root namespace only
    // (TODO: from_kgid()/from_kuid() logic here)
    kgid_t gid = BPF_CORE_READ(task, cred, gid);
    return gid.val;
}

static __always_inline u32 get_pid()
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    return pid;
}
static __always_inline u32 get_pid_alternative(struct task_struct *task)
{
    pid_t pid = BPF_CORE_READ(task, pid);
    return pid;
}

static __always_inline u32 get_tgid()
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    return tgid;
}
static __always_inline u32 get_tgid_alternative(struct task_struct *task)
{
    pid_t tgid = BPF_CORE_READ(task, tgid);
    return tgid;
}

static __always_inline u32 get_ppid(struct task_struct *child)
{
    struct task_struct *parent;
    parent = BPF_CORE_READ(child, real_parent);
    u32 ptgid = BPF_CORE_READ(parent, tgid);
    return ptgid;
}

static __always_inline void get_task_info(struct task_info *info)
{
    struct task_struct *task = get_task_struct();

    info->tgid = get_tgid();
    info->pid = get_pid();
    info->uid = get_uid();
    info->gid = get_gid();
    info->ppid = get_ppid(task);

    bpf_probe_read_kernel_str(info->comm, TASK_COMM_LEN, task->comm);
}
static __always_inline void get_task_info_alternative(struct task_info *info)
{
    struct task_struct *task = get_task_struct();

    info->tgid = get_tgid_alternative(task);
    info->pid = get_pid_alternative(task);
    info->uid = get_uid_alternative(task);
    info->gid = get_gid_alternative(task);
    info->ppid = get_ppid(task);

    bpf_probe_read_kernel_str(info->comm, TASK_COMM_LEN, task->comm);
}

static __always_inline void
get_event_data(u32 orig, struct task_info *info, struct event_data *data)
{
    data->event_timestamp = bpf_ktime_get_ns();
    data->event_type = orig;

    data->task.tgid = info->tgid;
    data->task.pid = info->pid;
    data->task.uid = info->uid;
    data->task.gid = info->gid;
    data->task.ppid = info->ppid;

    __builtin_memcpy(data->task.comm, info->comm, TASK_COMM_LEN);
}

static __always_inline bool should_trace(struct task_info *info)
{
    if (info->comm[0] != 'n' || info->comm[1] != 'c' ||
        info->comm[2] != '\0')
        return 0;

    return 1;
}

//
// eBPF programs
//

SEC("kprobe/sock_alloc_file")
int BPF_KPROBE(sock_alloc_file)
{
    if (!event_enabled(EVENT_KPROBE_SOCK_ALLOC_FILE))
        return 0;

    struct task_info info = {0};
    struct event_data data = {0};
    struct entry entry = {0};

    get_task_info(&info);
    get_event_data(EVENT_KPROBE_SOCK_ALLOC_FILE, &info, &data);

    if (!should_trace(&info))
        return 0;

    entry.args[0] = PT_REGS_PARM1(ctx); // struct socket *sock
    entry.args[1] = PT_REGS_PARM2(ctx); // int flags
    entry.args[2] = PT_REGS_PARM2(ctx); // char *dname

    // prepare for kretprobe using entrymap
    bpf_map_update_elem(&entrymap, &info.tgid, &entry, BPF_ANY);

    // submit socket creation event (entry)
    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

SEC("kretprobe/sock_alloc_file")
int BPF_KRETPROBE(ret_sock_alloc_file)
{
    // runs after cgroup/sock_create

    if (!event_enabled(EVENT_KRETPROBE_SOCK_ALLOC_FILE))
        return 0;

    struct task_info info = {0};
    struct event_data data = {0};

    get_task_info(&info);
    get_event_data(EVENT_KRETPROBE_SOCK_ALLOC_FILE, &info, &data);

    if (!should_trace(&info)) // faster than a lookup, try it first
        return 0;

    struct entry *entry = bpf_map_lookup_elem(&entrymap, &info.tgid);
    if (!entry) // no entry == no tracing
        return 0;

    struct socket *sock = (void *) entry->args[0];
    int flags = entry->args[1];
    char *dname = (void *) entry->args[2];
    struct file *sock_file = (void *) PT_REGS_RC(ctx);

    if (!sock_file)
        return 0; // socket() failed ?

    // TODO: fix this for 5.4 kernels (type relocations)

    // u16 type = BPF_CORE_READ(sock, sk, sk_type);
    // switch (type) {
    //     case SOCK_STREAM:
    //     case SOCK_DGRAM:
    //         break;
    //     default:
    //         return 0;
    // }
    // u16 protocol = BPF_CORE_READ(sock, sk, sk_protocol);
    // switch (protocol) {
    //     case IPPROTO_TCP:
    //     case IPPROTO_UDP:
    //         break;
    //     default:
    //         return 0;
    // }

    u64 inode = BPF_CORE_READ(sock_file, f_inode, i_ino);
    if (inode == 0)
        return 0;

    // submit socket creation event (return)
    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    // update inodemap correlating inode <=> task
    bpf_map_update_elem(&inodemap, &inode, &info, BPF_ANY);

    return 0;
}

SEC("kprobe/__cgroup_bpf_run_filter_skb")
int BPF_KPROBE(__cgroup_bpf_run_filter_skb)
{
    if (!event_enabled(EVENT_KPROBE_CGROUP_BPF_FILTER_SKB))
        return 0;

    struct task_info info = {0};
    struct event_data data = {0};

    get_task_info(&info);
    get_event_data(EVENT_KPROBE_CGROUP_BPF_FILTER_SKB, &info, &data);

    struct sock *sk = (void *) PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (void *) PT_REGS_PARM2(ctx);
    int type = PT_REGS_PARM3(ctx);

    switch (type) {
        case BPF_CGROUP_INET_INGRESS:
        case BPF_CGROUP_INET_EGRESS:
            break;
        default:
            // wrong bpf attachment type
            return 0;
    }

    // obtain socket inode
    u64 inode = BPF_CORE_READ(sk, sk_socket, file, f_inode, i_ino);
    if (inode == 0)
        return 0;

    // pick original task from socket inode
    struct task_info *ti = bpf_map_lookup_elem(&inodemap, &inode);
    if (!ti)
        return 0;

    // submit the kprobe event first (before cgroup/skb program)
    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    // prepare stuff for skb program
    struct event_data orig_data = {0};
    struct task_info orig_info = {0};

    u8 single = 1;
    bpf_core_read(&orig_info, sizeof(struct task_info), ti);
    switch (type) {
        case BPF_CGROUP_INET_INGRESS:
            get_event_data(EVENT_CGROUP_SKB_INGRESS, &orig_info, &orig_data);
            break;
        case BPF_CGROUP_INET_EGRESS:
            get_event_data(EVENT_CGROUP_SKB_EGRESS, &orig_info, &orig_data);
            break;
    }
    bpf_map_update_elem(&cgrpctxmap, &single, &orig_data, BPF_NOEXIST);

    return 0;
}

SEC("kretprobe/__cgroup_bpf_run_filter_skb")
int BPF_KRETPROBE(ret___cgroup_bpf_run_filter_skb)
{
    if (!event_enabled(EVENT_KRETPROBE_CGROUP_BPF_FILTER_SKB))
        return 0;

    // delete inode after cgroup ebpf program runs
    u8 single = 1;
    bpf_map_delete_elem(&cgrpctxmap, &single);

    return 0;
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SKB_INGRESS))
       return 1;

    u8 single = 1;
    struct event_data *d = bpf_map_lookup_elem(&cgrpctxmap, &single);
    if (!d)
        return 1;

    // add skb payload to the event
    u64 flags = BPF_F_CURRENT_CPU;
    flags |= (u64) ctx->len << 32;

    // submit event with payload to userland (after event data)
    bpf_perf_event_output(ctx, &perfbuffer, flags, d, sizeof(struct event_data));

    return 1;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SKB_EGRESS))
       return 1;

    u8 single = 1;
    struct event_data *d = bpf_map_lookup_elem(&cgrpctxmap, &single);
    if (!d)
        return 1;

    // add skb payload to the event
    u64 flags = BPF_F_CURRENT_CPU;
    flags |= (u64) ctx->len << 32;

    // submit event with payload to userland (after event data)
    bpf_perf_event_output(ctx, &perfbuffer, flags, d, sizeof(struct event_data));

    return 1;
}
