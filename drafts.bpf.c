//go:build exclude

#include <vmlinux.h>
#include <headers.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN                16
#define PERF_EVENT_ARRAY_MAX_ENTRIES 1024
#define HASHMAP_MAX_ENTRIES          1024
#define PERCPU_HASHMAP_MAX_ENTRIES   1024

enum event_type {
    EVENT_CGROUP_SOCKET_CREATE = 1,
    EVENT_CGROUP_SKB_INGRESS,
    EVENT_CGROUP_SKB_EGRESS,
    EVENT_KPROBE_CGROUP_BPF_FILTER_SK,
    EVENT_KRETPROBE_CGROUP_BPF_FILTER_SK,
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
    //__uint(max_entries, PERCPU_HASHMAP_MAX_ENTRIES);
    __uint(max_entries, 1);
    __type(key, u32);
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
    //__uint(max_entries, PERCPU_HASHMAP_MAX_ENTRIES);
    __uint(max_entries, 1);
    __type(key, u8); // always 0 =D
    __type(value, struct event_data);
} cgrpctxmap SEC(".maps");

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

SEC("cgroup/sock_create")
int cgroup_sock_create(struct bpf_sock *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SOCKET_CREATE))
       return 1;

    return 1;
}

SEC("kprobe/__cgroup_bpf_run_filter_sk")
int BPF_KPROBE(__cgroup_bpf_run_filter_sk)
{
    // runs before cgroup/sock_create

    if (!event_enabled(EVENT_KPROBE_CGROUP_BPF_FILTER_SK))
        return 0;

    struct task_info info = {0};
    struct event_data data = {0};
    struct entry entry = {0};

    get_task_info(&info);
    get_event_data(EVENT_KPROBE_CGROUP_BPF_FILTER_SK, &info, &data);

    if (!should_trace(&info))
        return 0;

    entry.args[0] = PT_REGS_PARM1(ctx); // struct sock *sk
    entry.args[1] = PT_REGS_PARM2(ctx); // int (enum cgroup_bpf_attach_type)

    bpf_map_update_elem(&entrymap, &info.tgid, &entry, BPF_ANY);

    return 0;
}

SEC("kretprobe/__cgroup_bpf_run_filter_sk")
int BPF_KRETPROBE(ret___cgroup_bpf_run_filter_sk)
{
    // runs after cgroup/sock_create

    if (!event_enabled(EVENT_KRETPROBE_CGROUP_BPF_FILTER_SK))
        return 0;

    struct task_info info = {};
    struct event_data data = {};

    get_task_info(&info);
    get_event_data(EVENT_KRETPROBE_CGROUP_BPF_FILTER_SK, &info, &data);

    if (!should_trace(&info))
        return 0;

    struct entry *entry = bpf_map_lookup_elem(&entrymap, &info.tgid);
    if (entry == NULL)
        return 0;

    struct sock *sk = (void *) entry->args[0];
    int type = entry->args[1];
    int ret = PT_REGS_RC(ctx);

    switch (type) {
        case BPF_CGROUP_INET_SOCK_CREATE:
            bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));
            break;
        default:
            return 0;
    }

    return 0;
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *ctx)
{

    //cgrpctxmap


    // if (!event_enabled(EVENT_CGROUP_SKB_INGRESS))
    //     return 1;

    // struct bpf_sock *sk = ctx->sk;
    // if (!sk)
    //     return 1;

    // sk = bpf_sk_fullsock(sk);
    // if (!sk)
    //     return 1;

    // struct task_info info = {0};
    // struct event_data data = {0};
    // struct entry entry = {0};

    // get_task_info_alternative(&info);
    // get_event_data(EVENT_CGROUP_SKB_INGRESS, &info, &data);

    // if (!should_trace(&info))
    //     return 1;

    // //struct bpf_sock_tuple tuple = {0};
    // //bpf_sk_lookup_tcp(ctx, &tuple, sizeof(tuple), -1, 0);

    // //u64 cgroup_id = bpf_get_current_cgroup_id(); CANNOT USE

    // bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 1;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *ctx)
{
    u8 zero = 0;

    if (!event_enabled(EVENT_CGROUP_SKB_EGRESS))
        return 1;

    struct event_data *d, data = {0};
    struct task_info *info = &data.task;

    // if entry exists it means should_trace()
    d = bpf_map_lookup_elem(&cgrpctxmap, &zero);
    if (d == NULL)
        return 1;

    __builtin_memcpy(&data, d, sizeof(struct event_data));
    data.event_type = EVENT_CGROUP_SKB_EGRESS;

    // submit event (and skb if needed) to userland
    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(struct event_data));

    return 1;
}

SEC("kprobe/__cgroup_bpf_run_filter_skb")
int BPF_KPROBE(__cgroup_bpf_run_filter_skb)
{
    // runs before cgroup_skb/{ingress,egress}
    u8 zero = 0;

    if (!event_enabled(EVENT_KPROBE_CGROUP_BPF_FILTER_SKB))
        return 0;

    struct task_info info = {0};
    struct event_data data = {0};
    struct entry entry = {0};

    get_task_info(&info);
    get_event_data(EVENT_KPROBE_CGROUP_BPF_FILTER_SKB, &info, &data);

    if (!should_trace(&info))
        return 0;

    entry.args[0] = PT_REGS_PARM1(ctx); // struct sock *sk
    entry.args[1] = PT_REGS_PARM2(ctx); // struct sk_buff *skb
    entry.args[2] = PT_REGS_PARM3(ctx); // int (enum cgroup_bpf_attach_type)

    bpf_map_update_elem(&entrymap, &info.tgid, &entry, BPF_ANY); // kprobe entry
    bpf_map_update_elem(&cgrpctxmap, &zero, &data, BPF_ANY); // cgroup skb entry

    return 0;
}

SEC("kretprobe/__cgroup_bpf_run_filter_skb")
int BPF_KRETPROBE(ret___cgroup_bpf_run_filter_skb)
{
    // runs after cgroup_skb/{ingress,egress}
    u8 zero = 0;

    if (!event_enabled(EVENT_KRETPROBE_CGROUP_BPF_FILTER_SKB))
        return 0;

    struct task_info info = {};
    struct event_data data = {};

    get_task_info(&info);
    get_event_data(EVENT_KRETPROBE_CGROUP_BPF_FILTER_SKB, &info, &data);

    if (!should_trace(&info))
        return 0;

    struct entry *entry = bpf_map_lookup_elem(&entrymap, &info.tgid);
    if (entry == NULL) {
        bpf_printk("could not find entrymap entry");
        return 0;
    }

    struct sock *sk = (void *) entry->args[0];
    struct sk_buff *skb = (void *) entry->args[1];
    int type = entry->args[2];
    int ret = PT_REGS_RC(ctx);

    switch (type) {
        case BPF_CGROUP_INET_INGRESS:
        case BPF_CGROUP_INET_EGRESS:
            bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));
            break;
        default:
            bpf_printk("wrong bpf attach type: %d", type);
    }

    bpf_map_delete_elem(&entrymap, &info.tgid);
    bpf_map_delete_elem(&cgrpctxmap, &zero);

    return 0;
}
