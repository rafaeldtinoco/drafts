//go:build exclude

#include <vmlinux.h>
#include <headers.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define FILENAME_MAX                 64
#define STR_PARSER_LEN               32
#define TASK_COMM_LEN                16
#define PERF_EVENT_ARRAY_MAX_ENTRIES 1024
#define HASHMAP_MAX_ENTRIES          1024
#define PERCPU_HASHMAP_MAX_ENTRIES   1024

//
// EXAMPLES: eBPF programs
//

// BPF_PROG_TYPE_SOCKET_FILTER
// BPF_PROG_TYPE_KPROBE                         done
// BPF_PROG_TYPE_SCHED_CLS
// BPF_PROG_TYPE_SCHED_ACT
// BPF_PROG_TYPE_TRACEPOINT                     done
// BPF_PROG_TYPE_XDP
// BPF_PROG_TYPE_PERF_EVENT
// BPF_PROG_TYPE_CGROUP_SKB                     done
// BPF_PROG_TYPE_CGROUP_SOCK                    done
// BPF_PROG_TYPE_LWT_IN
// BPF_PROG_TYPE_LWT_OUT
// BPF_PROG_TYPE_LWT_XMIT
// BPF_PROG_TYPE_SOCK_OPS
// BPF_PROG_TYPE_SK_SKB
// BPF_PROG_TYPE_CGROUP_DEVICE
// BPF_PROG_TYPE_SK_MSG
// BPF_PROG_TYPE_RAW_TRACEPOINT
// BPF_PROG_TYPE_CGROUP_SOCK_ADDR               done
// BPF_PROG_TYPE_LWT_SEG6LOCAL
// BPF_PROG_TYPE_LIRC_MODE2
// BPF_PROG_TYPE_SK_REUSEPORT
// BPF_PROG_TYPE_FLOW_DISSECTOR
// BPF_PROG_TYPE_CGROUP_SYSCTL
// BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
// BPF_PROG_TYPE_CGROUP_SOCKOPT
// BPF_PROG_TYPE_TRACING
// BPF_PROG_TYPE_STRUCT_OPS
// BPF_PROG_TYPE_EXT
// BPF_PROG_TYPE_LSM
// BPF_PROG_TYPE_SK_LOOKUP
// BPF_PROG_TYPE_SYSCALL

//
// EXAMPLES: eBPF map types
//

// BPF_MAP_TYPE_HASH                            done
// BPF_MAP_TYPE_ARRAY
// BPF_MAP_TYPE_PROG_ARRAY
// BPF_MAP_TYPE_PERF_EVENT_ARRAY                done
// BPF_MAP_TYPE_PERCPU_HASH                     done
// BPF_MAP_TYPE_PERCPU_ARRAY
// BPF_MAP_TYPE_STACK_TRACE
// BPF_MAP_TYPE_CGROUP_ARRAY
// BPF_MAP_TYPE_LRU_HASH = 9,
// BPF_MAP_TYPE_LRU_PERCPU_HASH
// BPF_MAP_TYPE_LPM_TRIE
// BPF_MAP_TYPE_ARRAY_OF_MAPS
// BPF_MAP_TYPE_HASH_OF_MAPS
// BPF_MAP_TYPE_DEVMAP
// BPF_MAP_TYPE_SOCKMAP
// BPF_MAP_TYPE_CPUMAP
// BPF_MAP_TYPE_XSKMAP
// BPF_MAP_TYPE_SOCKHASH
// BPF_MAP_TYPE_CGROUP_STORAGE
// BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
// BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
// BPF_MAP_TYPE_QUEUE
// BPF_MAP_TYPE_STACK
// BPF_MAP_TYPE_SK_STORAGE
// BPF_MAP_TYPE_DEVMAP_HASH
// BPF_MAP_TYPE_STRUCT_OPS
// BPF_MAP_TYPE_RINGBUF
// BPF_MAP_TYPE_INODE_STORAGE
// BPF_MAP_TYPE_TASK_STORAGE
// BPF_MAP_TYPE_BLOOM_FILTER

//
// EXAMPLES: eBPF attachment types
//

// BPF_CGROUP_INET_INGRESS                      done 
// BPF_CGROUP_INET_EGRESS                       done
// BPF_CGROUP_INET_SOCK_CREATE                  done
// BPF_CGROUP_SOCK_OPS
// BPF_SK_SKB_STREAM_PARSER
// BPF_SK_SKB_STREAM_VERDICT
// BPF_CGROUP_DEVICE
// BPF_SK_MSG_VERDICT
// BPF_CGROUP_INET4_BIND                        done
// BPF_CGROUP_INET6_BIND
// BPF_CGROUP_INET4_CONNECT
// BPF_CGROUP_INET6_CONNECT
// BPF_CGROUP_INET4_POST_BIND
// BPF_CGROUP_INET6_POST_BIND
// BPF_CGROUP_UDP4_SENDMSG
// BPF_CGROUP_UDP6_SENDMSG
// BPF_LIRC_MODE2
// BPF_FLOW_DISSECTOR
// BPF_CGROUP_SYSCTL
// BPF_CGROUP_UDP4_RECVMSG
// BPF_CGROUP_UDP6_RECVMSG
// BPF_CGROUP_GETSOCKOPT
// BPF_CGROUP_SETSOCKOPT
// BPF_TRACE_RAW_TP
// BPF_TRACE_FENTRY
// BPF_TRACE_FEXIT
// BPF_MODIFY_RETURN
// BPF_LSM_MAC
// BPF_TRACE_ITER
// BPF_CGROUP_INET4_GETPEERNAME
// BPF_CGROUP_INET6_GETPEERNAME
// BPF_CGROUP_INET4_GETSOCKNAME
// BPF_CGROUP_INET6_GETSOCKNAME
// BPF_XDP_DEVMAP
// BPF_CGROUP_INET_SOCK_RELEASE
// BPF_XDP_CPUMAP
// BPF_SK_LOOKUP
// BPF_XDP
// BPF_SK_SKB_VERDICT
// BPF_SK_REUSEPORT_SELECT
// BPF_SK_REUSEPORT_SELECT_OR_MIGRATE
// BPF_PERF_EVENT                               done
// BPF_TRACE_KPROBE_MULTI

//
// eBPF maps (general)
//

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, PERF_EVENT_ARRAY_MAX_ENTRIES); // used by perfbuffer
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} perfbuffer SEC(".maps");

//
// other functions
//

// TODO: compute_hash

//
// helper functions
//

// get current task "task_struct" structure
static __always_inline struct task_struct *get_task_struct()
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    return task;
}

// get current task user id
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

// get current task group id
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

// get current task process id
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

// get current thread group id
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

// get current task parent process id
static __always_inline u32 get_ppid(struct task_struct *child)
{
    struct task_struct *parent;
    parent = BPF_CORE_READ(child, real_parent);
    u32 ptgid = BPF_CORE_READ(parent, tgid);
    return ptgid;
}

//
// internal functions
//

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HASHMAP_MAX_ENTRIES);
    __type(key, u32);  // key = event_type
    __type(value, u8); // value = 0|1 = enabled/disabled
} enabled SEC(".maps");

// check if the event type is enabled or not
static __always_inline u32 event_enabled(u32 type)
{
    u8 *value = bpf_map_lookup_elem(&enabled, &type);
    if (!value)
        return 0;

    return 1;
}

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

// return an internal structured called task_info with current task information
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

// return an internal structured called task_info with current task information
// (this alternative version doesn't rely in bpf helpers as they might not be
// available, depending on the caller bpf program type).
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

enum event_type {
    EVENT_KPROBE_SYNC = 1,
    EVENT_KPROBE_SYNC_MAP,
    EVENT_TP_SYNC,
    EVENT_TP_OPENAT,
    EVENT_TP_OPENAT_EXIT,
    EVENT_CGROUP_SOCKET_CREATE,
    EVENT_CGROUP_SOCKET_RELEASE,
    EVENT_CGROUP_SOCKET_POST_BIND4,
    EVENT_CGROUP_SOCK_ADDR_BIND4,
    EVENT_CGROUP_SOCK_ADDR_SENDMSG4,
    EVENT_CGROUP_SOCK_ADDR_RECVMSG4,
    EVENT_CGROUP_SKB_INGRESS,
    EVENT_CGROUP_SKB_EGRESS,
};

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

// return a structure to be sent through perfbuffer to userland
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

//
// EXAMPLES: eBPF program types (each function is a different eBPF program)
//

// BPF_PROG_TYPE_KPROBE
//
// SYSCALL_DEFINE0(sync) at sync.c
//
// Story: I want to probe a kernel kprobe and send info to userland in 2
//        different ways: through perf buffer, as an event, and through an
//        eBPF map, that will be read in userland.

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HASHMAP_MAX_ENTRIES);
    __type(key, u32);                 // key = tgid
    __type(value, struct event_data); // value = event_data
} sync_hashmap SEC(".maps");

SEC("kprobe/ksys_sync")
int BPF_KPROBE(ksys_sync)
{
    if (!event_enabled(EVENT_KPROBE_SYNC))
        return 0;

    struct task_info info = {};
    struct event_data data = {};

    get_task_info(&info);
    get_event_data(EVENT_KPROBE_SYNC, &info, &data);

    // EXAMPLE: same information shared with userland in 2 different ways

    // eBPF MAP: save event_data to the sync_hashmap
    bpf_map_update_elem(&sync_hashmap, &info.tgid, &data, BPF_ANY);

    // send a perf event to userland (with event_data)
    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

// BPF_PROG_TYPE_TRACEPOINT (no arguments)
//
// sys_enter_sync (/sys/kernel/debug/tracing/events/syscalls/sys_enter_sync)
//
// Story: I want to probe a kernel tracepoint, since the interface is stable and
//        arguments for tracepoint won't change often, and send info to
//        userland.

SEC("tracepoint/syscalls/sys_enter_sync")
int tracepoint__syscalls__sys_enter_sync(struct trace_event_raw_sys_enter *ctx)
{
    if (!event_enabled(EVENT_TP_SYNC))
        return 0;

    struct task_info info = {};
    struct event_data data = {};

    get_task_info(&info);
    get_event_data(EVENT_TP_SYNC, &info, &data);

    // send a perf event to userland (with event_data)
    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

// BPF_PROG_TYPE_TRACEPOINT (has args, save syscall enter flags, event on exit)
//
// sys_enter_openat (/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat)
// sys_exit_openat (/sys/kernel/debug/tracing/events/syscalls/sys_exit_openat)
//
// Story: I want probe a kernel tracepoint, to know the arguments given to it,
//        and also if it was successful or not (through the ret code), and I
//        want to send the info to userland. Instead of sending through a perf
//        buffer event, I would like to send the shared information through
//        a eBPF map, but tied to the event information sent through the
//        perfbuffer. The information should be deleted in userland.

// save openat syscall entry context and use it on syscall exit

typedef struct openat_entry {
    long unsigned int args[6]; // args given to syscall openat
    u32 ret;                   // openat return value at exit
    u32 padding;
} openat_entry_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH); // enter & exit syscall in same cpu
    __uint(max_entries, PERCPU_HASHMAP_MAX_ENTRIES);
    __type(key, u32);                   // key = tgid
    __type(value, struct openat_entry); // value = openat_entry
} openat_entrymap SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    if (!event_enabled(EVENT_TP_OPENAT))
        return 0;

    struct task_info info = {};
    struct event_data data = {};
    struct openat_entry entry = {};

    get_task_info(&info);
    get_event_data(EVENT_TP_OPENAT, &info, &data);

    entry.args[1] = ctx->args[1]; // pathname (user vm address space)
    entry.args[2] = ctx->args[2]; // flags

    // save syscall entry args, indexed by current process pid, to use on exit
    bpf_map_update_elem(&openat_entrymap, &info.tgid, &entry, BPF_ANY);

    return 0;
}

// share event data with userland through a map, use perfbuffer as event trigger

struct openat_key {
    u64 event_timestamp;
    u32 tgid;
    u32 padding;
};

struct openat_value {
    int flags;
    int ret;
    char filename[FILENAME_MAX];
} openat_value_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HASHMAP_MAX_ENTRIES);
    __type(key, struct openat_key);
    //__type(key, u64);
    __type(value, struct openat_value);
} openat_hashmap SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    if (!event_enabled(EVENT_TP_OPENAT))
        return 0;

    struct task_info info = {};
    struct event_data data = {};
    struct openat_entry *entry;

    get_task_info(&info);
    get_event_data(EVENT_TP_OPENAT, &info, &data);

    entry = bpf_map_lookup_elem(&openat_entrymap, &info.tgid);
    if (entry == NULL) {
        bpf_printk("ERROR: tracepoint/syscalls/sys_exit_openat: could not get openat_entrymap");
        return 1;
    }

    // pick arguments saved from syscall entry

    void *pathname = (void *) entry->args[1]; // saved at syscall entry
    int *flags = (void *) entry->args[2];     // saved at syscall entry

    // map key {timestamp, tgid}
    struct openat_key key = {.event_timestamp = data.event_timestamp, .tgid = data.task.tgid};

    // map value {flags, retcode, filename}
    struct openat_value value = {};
    bpf_core_read(&value.flags, sizeof(u32), flags);
    value.ret = ctx->ret; // ret code from current context (syscall exit)
    bpf_core_read_user_str(&value.filename, FILENAME_MAX, pathname);

    // only filter openat event for files at /etc/ directory for now
    if (value.filename[0] == '/' &&
        value.filename[1] == 'e' &&
        value.filename[2] == 't' &&
        value.filename[3] == 'c' &&
        value.filename[4] == '/') {
        // eBPF MAP: create an entry for userland to read
        bpf_map_update_elem(&openat_hashmap, &key, &value, BPF_ANY);

        // send a perf event as a trigger to userland
        bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }

    // cleanup stored data from syscall entry
    bpf_map_delete_elem(&openat_entrymap, &info.tgid);

    return 0;
}

//
// WORK IN PROGRESS
//

// BPF_PROG_TYPE_CGROUP_SOCK
//
// cgroupv2 directory (/sys/fs/cgroup/unified for root cgroup directory)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HASHMAP_MAX_ENTRIES);
    __type(key, u64);                // socket cookie
    __type(value, struct task_info); // task_info containing socket
} cookie_hashmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HASHMAP_MAX_ENTRIES);
    __type(key, struct bpf_sock_tuple); // socket tuple
    __type(value, u64);                 // associated socket cookie
} tuple_hashmap SEC(".maps");

static __always_inline bool sock_is_supported_type(struct bpf_sock *ctx)
{
    switch (ctx->type) {
        case SOCK_STREAM:
        case SOCK_DGRAM:
            break;
        default:
            return false;
    }
    switch (ctx->family) {
        case AF_INET:
            break;
        default:
            return false;
    }
    switch (ctx->protocol) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            break;
        default:
            return false;
    }
    return true;
}

SEC("cgroup/sock_create")
int cgroup__sock_create(struct bpf_sock *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SOCKET_CREATE))
       return 1;

    if (!sock_is_supported_type(ctx))
        return 1;

    struct task_info info = {};
    struct event_data data = {};

    get_task_info_alternative(&info); // missing bpf helpers <= 5.4 kernels
    get_event_data(EVENT_CGROUP_SOCKET_CREATE, &info, &data);

    if (info.comm[0] != 'n' || info.comm[1] != 'c' || info.comm[2] != '\0') {
        return 1;
    }

    u64 cookie = bpf_get_socket_cookie(ctx);
    bpf_map_update_elem(&cookie_hashmap, &cookie, &info, BPF_ANY);

    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 1; // allow socket to continue
}

SEC("cgroup/sock_release")
int cgroup__sock_release(struct bpf_sock *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SOCKET_RELEASE))
       return 1;

    if (!sock_is_supported_type(ctx))
        return 1;

    struct task_info info = {};
    struct event_data data = {};

    get_task_info_alternative(&info); // missing bpf helpers <= 5.4 kernels
    get_event_data(EVENT_CGROUP_SOCKET_RELEASE, &info, &data);

    u64 cookie = bpf_get_socket_cookie(ctx);
    if (!bpf_map_lookup_elem(&cookie_hashmap, &cookie))
        return 1;
    bpf_map_delete_elem(&cookie_hashmap, &cookie);

    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 1;
}

SEC("cgroup/post_bind4")
int cgroup__sock_post_bind4(struct bpf_sock *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SOCKET_POST_BIND4))
        return 1;

    struct task_info info = {};
    struct event_data data = {};

    get_task_info_alternative(&info); // missing bpf helpers <= 5.4 kernels
    get_event_data(EVENT_CGROUP_SOCKET_POST_BIND4, &info, &data);

    u64 cookie = bpf_get_socket_cookie(ctx);
    if (!bpf_map_lookup_elem(&cookie_hashmap, &cookie))
        return 1;

    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 1;
}

// BPF_PROG_TYPE_CGROUP_SOCK_ADDR
//
// cgroupv2 directory (/sys/fs/cgroup/unified for root cgroup directory)

SEC("cgroup/bind4")
int cgroup__sock_addr_bind4(struct bpf_sock_addr *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SOCK_ADDR_BIND4))
        return 1;

    struct task_info info = {};
    struct event_data data = {};

    get_task_info_alternative(&info); // missing bpf helpers <= 5.4 kernels
    get_event_data(EVENT_CGROUP_SOCK_ADDR_BIND4, &info, &data);

    u64 cookie = bpf_get_socket_cookie(ctx);
    if (!bpf_map_lookup_elem(&cookie_hashmap, &cookie))
        return 1;

    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 1;
}

SEC("cgroup/sendmsg4")
int cgroup__sock_addr_sendmsg4(struct bpf_sock_addr *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SOCK_ADDR_SENDMSG4))
        return 1;

    struct task_info info = {};
    struct event_data data = {};

    get_task_info_alternative(&info); // missing bpf helpers <= 5.4 kernels
    get_event_data(EVENT_CGROUP_SOCK_ADDR_BIND4, &info, &data);

    u64 cookie = bpf_get_socket_cookie(ctx);
    if (!bpf_map_lookup_elem(&cookie_hashmap, &cookie))
        return 1;

    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 1;
}

SEC("cgroup/recvmsg4")
int cgroup__sock_addr_recvmsg4(struct bpf_sock_addr *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SOCK_ADDR_RECVMSG4))
        return 1;

    struct task_info info = {};
    struct event_data data = {};

    get_task_info_alternative(&info); // missing bpf helpers <= 5.4 kernels
    get_event_data(EVENT_CGROUP_SOCK_ADDR_BIND4, &info, &data);

    u64 cookie = bpf_get_socket_cookie(ctx);
    if (!bpf_map_lookup_elem(&cookie_hashmap, &cookie))
        return 1;

    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 1;
}

// BPF_PROG_TYPE_CGROUP_SKB
//
// cgroupv2 directory (/sys/fs/cgroup/unified for root cgroup directory)

SEC("cgroup_skb/ingress")
int cgroup__skb_ingress(struct __sk_buff *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SKB_INGRESS))
        return 1;

    if (ctx->protocol != bpf_htons(ETH_P_IP)) // ethernet (IP) only
        return 1;

    struct task_info *orig_info, info = {0};
    struct event_data data = {0};

    // INFO: ingress context is usually a kernel thread or a running task
    get_task_info_alternative(&info); // missing bpf helpers, needs alternative

    struct bpf_sock *sk = ctx->sk;
    if (!sk) {
        bpf_printk("ERROR: cgroup_skb/ingress: could not get bpf_sock");
        return 1;
    }

    u64 cookie = bpf_get_socket_cookie(ctx);

    bool info_exists = 1;
    orig_info = bpf_map_lookup_elem(&cookie_hashmap, &cookie);
    if (!orig_info) {
        orig_info = &info;
        info_exists = 0;
    }

    sk = bpf_sk_fullsock(sk);
    if (!sk) {
        bpf_printk("ERROR: cgroup_skb/ingress: could not get full bpf_sock");
        return 1;
    }

    struct iphdr ip;
    if (bpf_skb_load_bytes_relative(ctx, 0, &ip, sizeof(ip), BPF_HDR_START_NET))
        return 1;

    struct tcphdr tcp = {0};
    struct udphdr udp = {0};

    struct bpf_sock_tuple tuple = {};
    tuple.ipv4.daddr = ip.daddr;
    tuple.ipv4.saddr = ip.saddr;

    switch (ip.protocol) {
        case IPPROTO_TCP:
            if (bpf_skb_load_bytes_relative(ctx,
                                            sizeof(ip),
                                            &tcp,
                                            sizeof(struct tcphdr),
                                            BPF_HDR_START_NET))
                return 1;
            tuple.ipv4.sport = tcp.source;
            tuple.ipv4.dport = tcp.dest;
            break;
        case IPPROTO_UDP:
            if (bpf_skb_load_bytes_relative(ctx,
                                            sizeof(ip),
                                            &udp,
                                            sizeof(struct udphdr),
                                            BPF_HDR_START_NET))
                return 1;
            tuple.ipv4.sport = udp.source;
            tuple.ipv4.dport = udp.dest;
            break;
        default:
            return 1;
    }

    bool orig_info_found = 0;
    if (ip.protocol == IPPROTO_TCP) {
        //
        // If a socket cookie exists but the ctx->remote_port is 0, it means
        // that packet is an incoming connection to an already known bound
        // socket. In this case, we save the tuple for a near future: when a
        // packet arrives with the same tuple and from an unknown socket (the
        // one created by accept()).
        // 
        // By having the tuple saved we can add this new socket cookie into the
        // list of known cookies for the task we're tracing  (netcat) and remove
        // the tuple from the existing tuples map. This new socket cookie will
        // be released by sock_release() program.
        //
        if (!info_exists) {
            u64 *orig_cookie = bpf_map_lookup_elem(&tuple_hashmap, &tuple);
            if (orig_cookie) {
                orig_info = bpf_map_lookup_elem(&cookie_hashmap, orig_cookie);
                if (orig_info) {
                    orig_info_found = 1;
                    bpf_printk("> cgroup_skb/ingress: mapping cookie: %u", cookie);
                }
            }

            if (!orig_info_found)
                return 1; // can't tie current socket with known task

            // link the unknown socket with the task being traced
            bpf_map_update_elem(&cookie_hashmap, &cookie, orig_info, BPF_ANY);
            bpf_map_delete_elem(&tuple_hashmap, &tuple); // clean tuple map
        }

        if (info_exists && bpf_ntohl(ctx->remote_port) == 0) {
            // socket just received a connection, save tupple to further
            // identify socket (next ingress calls) created by accept()
            bpf_map_update_elem(&tuple_hashmap, &tuple, &cookie, BPF_ANY);
        }
    }
    
    if (ip.protocol == IPPROTO_UDP) {
        if (!orig_info_found)
            return 1;
    }

    // get event data with correct "info" (owner of socket)
    get_event_data(EVENT_CGROUP_SKB_INGRESS, orig_info, &data);

    // construct net_info in event data
    data.net.socket_cookie = cookie;
    data.net.family = sk->family;
    data.net.type = sk->type;
    data.net.protocol = sk->protocol;
    data.net.src_ipv4 = bpf_ntohl(tuple.ipv4.saddr);
    data.net.dst_ipv4 = bpf_ntohl(tuple.ipv4.daddr);
    data.net.src_port = bpf_ntohs(tuple.ipv4.sport);
    data.net.dst_port = bpf_ntohs(tuple.ipv4.dport);

    // emit a sock_create event due to new socket (from accept())
    if (orig_info_found) {
        struct event_data create = {0};
        __builtin_memcpy(&create, &data, sizeof(data));
        create.event_type = EVENT_CGROUP_SOCKET_CREATE;
        bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &create, sizeof(create));
    }

    u64 flags = BPF_F_CURRENT_CPU;
    flags |= (u64) ctx->len << 32;

    // emit the ingress event
    bpf_perf_event_output(ctx, &perfbuffer, flags, &data, sizeof(data));

    return 1;
}

SEC("cgroup_skb/egress")
int cgroup__skb_egress(struct __sk_buff *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SKB_EGRESS))
        return 1;

    if (ctx->protocol != bpf_htons(ETH_P_IP)) // ethernet (IP) only
        return 1;

    struct task_info *orig_info, info = {0};
    struct event_data data = {0};

    get_task_info_alternative(&info); // missing bpf helpers, needs alternative

    struct bpf_sock *sk = ctx->sk;
    if (!sk) {
        bpf_printk("ERROR: cgroup_skb/egress: could not get bpf_sock");
        return 1;
    }

    u64 cookie = bpf_get_socket_cookie(ctx);

    bool info_exists = 1;
    orig_info = bpf_map_lookup_elem(&cookie_hashmap, &cookie);
    if (!orig_info) {
        orig_info = &info;
        info_exists = 0;
    }

    sk = bpf_sk_fullsock(sk);
    if (!sk) {
        bpf_printk("ERROR: cgroup_skb/egress: could not get full bpf_sock");
        return 1;
    }

    struct iphdr ip;
    if (bpf_skb_load_bytes_relative(ctx, 0, &ip, sizeof(ip), BPF_HDR_START_NET))
        return 1;

    struct tcphdr tcp = {0};
    struct udphdr udp = {0};

    struct bpf_sock_tuple tuple = {};
    tuple.ipv4.daddr = ip.daddr;
    tuple.ipv4.saddr = ip.saddr;

    switch (ip.protocol) {
        case IPPROTO_TCP:
            if (bpf_skb_load_bytes_relative(ctx,
                                            sizeof(ip),
                                            &tcp,
                                            sizeof(struct tcphdr),
                                            BPF_HDR_START_NET))
                return 1;
            tuple.ipv4.sport = tcp.source;
            tuple.ipv4.dport = tcp.dest;
            break;
        case IPPROTO_UDP:
            if (bpf_skb_load_bytes_relative(ctx,
                                            sizeof(ip),
                                            &udp,
                                            sizeof(struct udphdr),
                                            BPF_HDR_START_NET))
                return 1;
            tuple.ipv4.sport = udp.source;
            tuple.ipv4.dport = udp.dest;
            break;
        default:
            return 1;
    }

    bool socket_created = 0;

    // only trace netcat processes
    if (!info_exists) {
        if (info.comm[0] != 'n' ||
            info.comm[1] != 'c' ||
            info.comm[2] != '\0')
            return 1;

        // link unknown (task already runnning) socket with task being traced
        bpf_map_update_elem(&cookie_hashmap, &cookie, &info, BPF_ANY);
        socket_created = 1;
    }

    // get event data with correct "info" (owner of socket)
    get_event_data(EVENT_CGROUP_SKB_EGRESS, orig_info, &data);

    // construct net_info in event data
    data.net.socket_cookie = cookie;
    data.net.family = sk->family;
    data.net.type = sk->type;
    data.net.protocol = sk->protocol;
    data.net.src_ipv4 = bpf_ntohl(tuple.ipv4.saddr);
    data.net.dst_ipv4 = bpf_ntohl(tuple.ipv4.daddr);
    data.net.src_port = bpf_ntohs(tuple.ipv4.sport);
    data.net.dst_port = bpf_ntohs(tuple.ipv4.dport);

    u64 flags = BPF_F_CURRENT_CPU;
    flags |= (u64) ctx->len << 32;

    // emit a sock_create event when new socket detected (task already running)
    if (socket_created) {
        struct event_data create = {0};
        __builtin_memcpy(&create, &data, sizeof(data));
        create.event_type = EVENT_CGROUP_SOCKET_CREATE;
        bpf_perf_event_output(ctx, &perfbuffer, flags, &create, sizeof(create));
    }

    // emit the egress event
    bpf_perf_event_output(ctx, &perfbuffer, flags, &data, sizeof(data));

    return 1;
}

// END OF EXAMPLES
