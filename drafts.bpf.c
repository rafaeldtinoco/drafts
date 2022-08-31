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

enum event_type {
    // KPROBES
	EVENT_KPROBE_UDP_SENDMSG = 1,
	EVENT_KRETPROBE_UDP_SENDMSG,
    EVENT_KPROBE_UDP_DISCONNECT,
    EVENT_KRETPROBE_UDP_DISCONNECT,
    EVENT_KPROBE_UDP_DESTROY_SOCK,
    EVENT_KRETPROBE_UDP_DESTROY_SOCK,
    EVENT_KPROBE_TCP_CONNECT,
    EVENT_KRETPROBE_TCP_CONNECT,
	// KPROBES (SECURITY)
    EVENT_KPROBE_SECURITY_SOCKET_CREATE,
    EVENT_KPROBE_SECURITY_SOCKET_LISTEN,
    EVENT_KPROBE_SECURITY_SOCKET_CONNECT,
    EVENT_KPROBE_SECURITY_SOCKET_ACCEPT,
    EVENT_KPROBE_SECURITY_SOCKET_BIND,
    // TRACEPOINTS
    EVENT_TP_INET_SOCK_SET_STATE,
    EVENT_TP_INET_SOCK_SET_STATE_EXIT,
    EVENT_TP_SOCKET,
    EVENT_TP_SOCKET_EXIT,
    EVENT_TP_LISTEN,
    EVENT_TP_LISTEN_EXIT,
    EVENT_TP_CONNECT,
    EVENT_TP_CONNECT_EXIT,
    EVENT_TP_ACCEPT,
    EVENT_TP_ACCEPT_EXIT,
    EVENT_TP_BIND,
    EVENT_TP_BIND_EXIT,
    // CGROUP SOCKET
    EVENT_CGROUP_SOCKET_CREATE,
    EVENT_CGROUP_SOCKET_POST_BIND4,
    // CGROUP SOCKADDR
    EVENT_CGROUP_SOCKADDR_CONNECT4,
    EVENT_CGROUP_SOCKADDR_SENDMSG4,
    EVENT_CGROUP_SOCKADDR_RECVMSG4,
    // CGROUP SKB
    EVENT_CGROUP_SKB_INGRESS,
    EVENT_CGROUP_SKB_EGRESS,
};

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

// NETWORKING CODE

static __always_inline bool is_sock_supported(struct bpf_sock *ctx)
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

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, int);
} sk_storage_map SEC(".maps");

typedef struct net_entry {
    long unsigned int args[6];
    u32 ret;
    u32 padding;
} net_entry_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH); // enter & exit syscall in same cpu
    __uint(max_entries, PERCPU_HASHMAP_MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct net_entry);
} net_entrymap SEC(".maps");

// KPROBES

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg)
{
    return 0;
}

SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(ret_udp_sendmsg)
{
    return 0;
}

SEC("kprobe/__udp_disconnect")
int BPF_KPROBE(udp_disconnect)
{
    return 0;
}

SEC("kretprobe/__udp_disconnect")
int BPF_KPROBE(ret_udp_disconnect)
{
    return 0;
}

SEC("kprobe/udp_destroy_sock")
int BPF_KPROBE(udp_destroy_sock)
{
    return 0;
}

SEC("kretprobe/udp_destroy_sock")
int BPF_KPROBE(ret_udp_destroy_sock)
{
    return 0;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect)
{
    return 0;
}

SEC("kretprobe/tcp_connect")
int BPF_KPROBE(ret_tcp_connect)
{
    return 0;
}

// KPROBES (SECURITY)

SEC("kprobe/security_socket_create")
int BPF_KPROBE(security_socket_create)
{
    return 0;
}

SEC("kprobe/security_socket_listen")
int BPF_KPROBE(security_socket_listen)
{
    return 0;
}

SEC("kprobe/security_socket_connect")
int BPF_KPROBE(security_socket_connect)
{
    return 0;
}

SEC("kprobe/security_socket_accept")
int BPF_KPROBE(security_socket_accept)
{
    return 0;
}

SEC("kprobe/security_socket_bind")
int BPF_KPROBE(security_socket_bind)
{
    return 0;
}


// TRACEPOINTS

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_sys_enter *ctx)
{
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int sys_enter_socket(struct trace_event_raw_sys_enter *ctx)
{
    if (!event_enabled(EVENT_TP_SOCKET))
        return 0;

    struct task_info info = {0};
    struct event_data data = {0};
    struct net_entry entry = {0};

    get_task_info(&info);
    get_event_data(EVENT_TP_SOCKET, &info, &data);

    entry.args[0] = ctx->args[0]; // int domain
    entry.args[1] = ctx->args[1]; // int type
    entry.args[2] = ctx->args[2]; // int protocol
    bpf_map_update_elem(&net_entrymap, &info.tgid, &entry, BPF_ANY);

    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int sys_exit_socket(struct trace_event_raw_sys_exit *ctx)
{
    if (!event_enabled(EVENT_TP_SOCKET_EXIT))
        return 0;

    struct task_info info = {};
    struct event_data data = {};

    get_task_info(&info);
    get_event_data(EVENT_TP_SOCKET_EXIT, &info, &data);

    struct net_entry *entry = bpf_map_lookup_elem(&net_entrymap, &info.tgid);
    if (entry == NULL)
        return 0;

    // pick arguments saved from syscall entry
    int *domain = (void *) entry->args[0];
    int *type = (void *) entry->args[1];
    int *proto = (void *) entry->args[2];

    bpf_printk("domain: %d, type: %d, proto: %d", domain, type, proto);

    // send a perf event to userland (with event_data)
    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_listen")
int sys_enter_listen(struct trace_event_raw_sys_enter *ctx)
{
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_listen")
int sys_exit_listen(struct trace_event_raw_sys_exit *ctx)
{
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int sys_exit_connect(struct trace_event_raw_sys_exit *ctx)
{
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int sys_enter_accept(struct trace_event_raw_sys_enter *ctx)
{
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int sys_exit_accept(struct trace_event_raw_sys_exit *ctx)
{
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int sys_enter_bind(struct trace_event_raw_sys_enter *ctx)
{
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_bind")
int sys_exit_bind(struct trace_event_raw_sys_exit *ctx)
{
    return 0;
}


// CGROUP SOCKET

SEC("cgroup/sock_create")
int cgroup_sock_create(struct bpf_sock *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SOCKET_CREATE))
       return 1;

    if (!is_sock_supported(ctx))
        return 1;

    return 1;
}

SEC("cgroup/post_bind4")
int cgroup_sock_post_bind4(struct bpf_sock *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SOCKET_POST_BIND4))
        return 1;

    if (!is_sock_supported(ctx))
        return 1;

    return 1;
}

// CGROUP SOCKADDR

SEC("cgroup/connect4")
int cgroup_sockaddr_connect4(struct bpf_sock_addr *ctx)
{
    return 1;
}

SEC("cgroup/sendmsg4")
int cgroup_sockaddr_sendmsg4(struct bpf_sock_addr *ctx)
{
    return 1;
}

SEC("cgroup/recvmsg4")
int cgroup_sockaddr_recvmsg4(struct bpf_sock_addr *ctx)
{
    return 1;
}

// CGROUP SKB

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SKB_INGRESS))
        return 1;

    struct bpf_sock *sk = ctx->sk;
    if (!sk)
        return 1;

    sk = bpf_sk_fullsock(sk);
    if (!sk)
        return 1;

    return 1;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SKB_EGRESS))
        return 1;

    struct bpf_sock *sk = ctx->sk;
    if (!sk)
        return 1;

    sk = bpf_sk_fullsock(sk);
    if (!sk)
        return 1;

    return 1;
}