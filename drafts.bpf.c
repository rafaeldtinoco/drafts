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

// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
//     __uint(max_entries, PERCPU_HASHMAP_MAX_ENTRIES);
//     __type(key, u8); // single entry == 0
//     //__type(value, u64); // inode TODO: save the task_info directly instead of inode
//     __type(value, struct event_data); // inode TODO: save the task_info directly instead of inode
// } cgrpctxmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HASHMAP_MAX_ENTRIES);
    __type(key, u64); // sk_buff timestamp
    __type(value, struct event_data); // event data for skb ebpf prog
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
    if ((info->comm[0] != 'n' || info->comm[1] != 'c' || info->comm[2] != '\0')
        && (info->comm[0] != 'p' || info->comm[1] != 'i' || info->comm[2] != 'n')) {
        return 0;
    }

    return 1;
}

//
// eBPF programs
//

// There are multiple ways to follow ingress/egress for a task. One way is
// to try to track all flows within network interfaces and keep a map of
// addresses tuples and translations. OR, sk_storage and socket cookies might
// help in understanding which sock/sk_buff context the bpf program is dealing
// with but, at the end, the need is always to tie a flow to a task (specially
// when hooking ingress skb bpf programs, when the current task is a
// kernel thread most of the times).

// Unfortunately that gets even more complicated in older kernels: the cgroup
// skb programs have almost no bpf helpers to use, and most of common code
// causes verifier to fail. With that in mind, this approach uses a technique
// of kprobing the function responsible for calling the cgroup/skb programs.

// All the work that should be done by the cgroup/skb programs is done by this
// kprobe/kretprobe hook logic (right before and right after the cgroup/skb
// program runs). This way, all work that cgroup/skb program needs to do is
// a bpf map lookup and a return.

// Obviously this has some cons: this kprobe->cgroup/skb->kretprobe execution
// flow does not have preemption disabled, so the map used in between the 3
// hooks need to use something that is available to all 3 of them.

// At the end, the logic is simple: every time a socket is created an inode
// is also created. The task owning the socket is indexed by the socket inode
// so everytime this socket is used we know which task it belongs to (specially
// during ingress hook).

static __always_inline bool is_socket_supported(struct socket *sock)
{
    struct sock_common *common = (void *) BPF_CORE_READ(sock, sk);
    struct sock *sk = (void *) BPF_CORE_READ(sock, sk);

    u8 family = BPF_CORE_READ(common, skc_family);
    switch (family) {
        case PF_INET:
        case PF_INET6:
        //case PF_IB:
            break;
        default:
            return 0;
    }
    u16 type = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_type);
    switch (type) {
        case SOCK_STREAM:
        case SOCK_DGRAM:
            break;
        default:
            return 0;
    }
    u16 protocol = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
    switch (protocol) {
        case IPPROTO_IP:
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        //case IPPROTO_UDPLITE:
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
        //case IPPROTO_IPIP:
        //case IPPROTO_IPV6:
        //case IPPROTO_DCCP:
        //case IPPROTO_SCTP:
            break;
        default:
            return 0;
    }

    return 1;
}

//
// Socket Creation: keep track of created socket inodes per traced task
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

    // cleanup entrymap
    bpf_map_delete_elem(&entrymap, &info.tgid);

    if (!sock_file)
        return 0; // socket() failed ?

    if (!is_socket_supported(sock))
        return 0;

    u64 inode = BPF_CORE_READ(sock_file, f_inode, i_ino);
    if (inode == 0)
        return 0;

    // submit socket creation event (return)
    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    // update inodemap correlating inode <=> task
    bpf_map_update_elem(&inodemap, &inode, &info, BPF_ANY);

    return 0;
}

//
// Socket Ingress/Egress eBPF program loader (right before and right after eBPF)
//

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
            return 0; // wrong attachment type
    }

    struct entry entry = {0};
    entry.args[0] = PT_REGS_PARM1(ctx); // struct sock *sk
    entry.args[1] = PT_REGS_PARM2(ctx); // struct sk_buff *skb

    // prepare for kretprobe using entrymap
    bpf_map_update_elem(&entrymap, &info.tgid, &entry, BPF_ANY);

    // obtain socket inode
    u64 inode = BPF_CORE_READ(sk, sk_socket, file, f_inode, i_ino);
    if (inode == 0)
        return 0;

    // pick original task from socket inode
    struct task_info *ti = bpf_map_lookup_elem(&inodemap, &inode);
    if (!ti) {
        // if not a traced inode: check if task should be traced...
        switch (type) {
            case BPF_CGROUP_INET_EGRESS: // ingress is usually a kernel thread
               if (should_trace(&info)) {
                    // ... then update inodemap correlating existing inode <=> task
                    bpf_map_update_elem(&inodemap, &inode, &info, BPF_ANY);
                    break;
                }
                // do not break here
            default:
                return 0;
        }
    }

    // use skb timestamp as the key for cgroup/skb program context
    u64 skbts = BPF_CORE_READ(skb, tstamp);

    // submit the kprobe event first (before cgroup/skb program)
    bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &data, sizeof(data));

    // prepare stuff for skb program
    struct event_data orig_data = {0};
    struct task_info orig_info = {0};

    // inform userland about protocol family (for correct parsing, L3 and on)
    struct sock_common *common = (void *) sk;
    u8 family = BPF_CORE_READ(common, skc_family);
    orig_data.net.family = family;

    bpf_core_read(&orig_info, sizeof(struct task_info), ti);
    switch (type) {
        case BPF_CGROUP_INET_INGRESS:
            get_event_data(EVENT_CGROUP_SKB_INGRESS, &orig_info, &orig_data);
            break;
        case BPF_CGROUP_INET_EGRESS:
            get_event_data(EVENT_CGROUP_SKB_EGRESS, &orig_info, &orig_data);
            break;
    }

    // Use skb timestamp as the key for a map shared between this kprobe and the
    // skb ebpf program: this is **NOT SUPER** BUT, for older kernels, that
    // don't provide absolute no eBPF helpers in cgroup/skb programs, it does
    // its job: pre-process everything the cgroup/skb program can use.
    //
    // Explanation: The cgroup/skb eBPF program is called right after this
    // kprobe but preemption is enabled. If preemption wasn't enabled, we could
    // simply populate the map with a single item and pick it inside cgroup/skb
    // BUT we might have a preemption in between the kprobe and the BPF program
    // run. SO, instead, we index map items using the skb timestamp, which is
    // a value that is shared among this kprobe AND the cgroup/skb program
    // context (through its skbuf copy).
    //
    // Theoretically, map collisions might occur, BUT very unlikely due to:
    //
    // kprobe (map update) -> cgroup/skb (consume) -> kretprobe (map delete)

    bpf_map_update_elem(&cgrpctxmap, &skbts, &orig_data, BPF_NOEXIST);

    return 0;
}

SEC("kretprobe/__cgroup_bpf_run_filter_skb")
int BPF_KRETPROBE(ret___cgroup_bpf_run_filter_skb)
{
    if (!event_enabled(EVENT_KRETPROBE_CGROUP_BPF_FILTER_SKB))
        return 0;

    struct task_info info = {0};
    get_task_info(&info);

    struct entry *entry = bpf_map_lookup_elem(&entrymap, &info.tgid);
    if (!entry) // no entry == no tracing
        return 0;

    struct sock *sk = (void *) entry->args[0];
    struct sk_buff *skb = (void *) entry->args[1];

    // cleanup entrymap
    bpf_map_delete_elem(&entrymap, &info.tgid);

    // use skb timestamp as the key for cgroup/skb program context
    u64 skbts = BPF_CORE_READ(skb, tstamp);

    // only continue if cgrpctxmap entry exists
    struct event_data *d = bpf_map_lookup_elem(&cgrpctxmap, &skbts);
    if (!d)
        return 1;

    // delete inode after cgroup ebpf program runs
    bpf_map_delete_elem(&cgrpctxmap, &skbts);

    return 0;
}

//
// Type definitions and prototypes for protocol parsing:
//

typedef union iphdrs_t {
    struct iphdr iphdr;
    struct ipv6hdr ipv6hdr;
} iphdrs;

typedef union protohdrs_t {
    struct tcphdr tcphdr;
    struct udphdr udphdr;
    struct icmphdr icmphdr;
    struct icmp6hdr icmp6hdr;
} protohdrs;

static __always_inline u32 cgroup_skb_handle_family(struct __sk_buff *, iphdrs *, protohdrs *);
static __always_inline u32 cgroup_skb_handle_proto(struct __sk_buff *, iphdrs *, protohdrs *);
static __always_inline u32 cgroup_skb_handle_proto_tcp(struct __sk_buff *, iphdrs *, protohdrs *);
static __always_inline u32 cgroup_skb_handle_proto_udp(struct __sk_buff *, iphdrs *, protohdrs *);
static __always_inline u32 cgroup_skb_handle_proto_icmp(struct __sk_buff *, iphdrs *, protohdrs *);
static __always_inline u32 cgroup_skb_handle_proto_icmpv6(struct __sk_buff *, iphdrs *, protohdrs *);

//
// SKB eBPF programs
//

static __always_inline u32 cgroup_skb_generic(struct __sk_buff *ctx)
{
    // use skb timestamp as the key for cgroup/skb program context
    u64 skbts = ctx->tstamp;

    struct event_data *d = bpf_map_lookup_elem(&cgrpctxmap, &skbts);
    if (!d)
        return 1;

    // add skb payload to the event
    u64 flags = BPF_F_CURRENT_CPU;
    flags |= (u64) ctx->len << 32;

    // submit event with payload to userland (after event data)
    bpf_perf_event_output(ctx, &perfbuffer, flags, d, sizeof(struct event_data));

    struct bpf_sock *sk = ctx->sk;
    if (!sk) {
        bpf_printk("ERROR: could not get bpf_sock");
        return 1;
    }

    sk = bpf_sk_fullsock(sk);
    if (!sk) {
        bpf_printk("ERROR: could not get full bpf_sock");
        return 1;
    }

    iphdrs iphdrs = {0};
    protohdrs protohdrs = {0};

    // process protocols and needed events
    cgroup_skb_handle_family(ctx, &iphdrs, &protohdrs);

    return 1; // allow OR disallow traffic
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SKB_INGRESS))
       return 1;

    return cgroup_skb_generic(ctx);
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *ctx)
{
    if (!event_enabled(EVENT_CGROUP_SKB_EGRESS))
       return 1;

    return cgroup_skb_generic(ctx);
}

// The functions bellow exist so packets can be parsed inside ingress and egress
// eBPF programs and send specific events, such as DNS QUERY, or HTTP REQUEST.

#define UDP_PORT_DNS 8090 // TODO: change to 53
#define TCP_PORT_DNS 8090 // TODO: change to 53

// TODO: remove unneededed static inline function arguments

// cgroup_skb_handle_proto_{tcp,udp,icmp}_{dns,http}:

static __always_inline u32 cgroup_skb_handle_proto_tcp_dns(struct __sk_buff *ctx,
                                                           iphdrs *iphdrs,
                                                           protohdrs *protohdrs)
{
    // TODO: submit DNS event to userland

    bpf_printk("YOU GOT yourself a TCP DNS packet");

    return 0;
}

static __always_inline u32 cgroup_skb_handle_proto_udp_dns(struct __sk_buff *ctx,
                                                           iphdrs *iphdrs,
                                                           protohdrs *protohdrs)
{
    // TODO: submit DNS events to userland

    bpf_printk("YOU GOT yourself an UDP DNS packet");

    return 0;
}

// cgroup_skb_handle_proto_{tcp,udp,icmp}:

static __always_inline u32 cgroup_skb_handle_proto_tcp(struct __sk_buff *ctx,
                                                       iphdrs *iphdrs,
                                                       protohdrs *protohdrs)
{
    u16 source = bpf_ntohs(protohdrs->tcphdr.source);
    u16 dest = bpf_ntohs(protohdrs->tcphdr.dest);

    switch (source < dest ? source : dest) {
        case TCP_PORT_DNS:
            return cgroup_skb_handle_proto_tcp_dns(ctx, iphdrs, protohdrs);
    }

    return 0;
}

static __always_inline u32 cgroup_skb_handle_proto_udp(struct __sk_buff *ctx,
                                                       iphdrs *iphdrs,
                                                       protohdrs *protohdrs)
{
    u16 source = bpf_ntohs(protohdrs->udphdr.source);
    u16 dest = bpf_ntohs(protohdrs->udphdr.dest);

    switch (source < dest ? source : dest) {
        case UDP_PORT_DNS:
            return cgroup_skb_handle_proto_udp_dns(ctx, iphdrs, protohdrs);
    }

    return 0;
}

static __always_inline u32 cgroup_skb_handle_proto_icmp(struct __sk_buff *ctx,
                                                        iphdrs *iphdrs,
                                                        protohdrs *protohdrs)
{
    return 0;
}

static __always_inline u32 cgroup_skb_handle_proto_icmpv6(struct __sk_buff *ctx,
                                                          iphdrs *iphdrs,
                                                          protohdrs *protohdrs)
{
    return 0;
}

// cgroup_skb_handle_proto:

static __always_inline u32 cgroup_skb_handle_proto(struct __sk_buff *ctx,
                                                   iphdrs *iphdrs,
                                                   protohdrs *protohdrs)
{
    char *fmt = "ERROR: proto: could not load relative packet bytes";

    void *dest;
    u32 iphdr_size;
    u32 protohdr_size;

    // sanity checks for supported protocol families
    switch (ctx->family) {
        case PF_INET:
            if (iphdrs->iphdr.version != 4)
                return 1;
            iphdr_size = sizeof(struct iphdr);
            break;
        case PF_INET6:
            if (iphdrs->ipv6hdr.version != 6)
                return 1;
            iphdr_size = sizeof(struct ipv6hdr);
            break;
        default:
            return 0; // other families are not an error
    }

    // load specific protocol headers
    switch (iphdrs->iphdr.protocol) {
        case IPPROTO_TCP:
            dest = &protohdrs->tcphdr;
            protohdr_size = sizeof(struct tcphdr);
            break;
        case IPPROTO_UDP:
            dest = &protohdrs->udphdr;
            protohdr_size = sizeof(struct udphdr);
            break;
        case IPPROTO_ICMP:
            dest = &protohdrs->icmphdr;
            protohdr_size = sizeof(struct icmphdr);
            break;
        case IPPROTO_ICMPV6:
            dest = &protohdrs->icmp6hdr;
            protohdr_size = sizeof(struct icmp6hdr);
            break;
        default:
            return 0; // other protocols are not an error
    }

    // load protocol (tcp, udp, icmp) header into its buffer
    if (bpf_skb_load_bytes_relative(ctx, iphdr_size, dest, protohdr_size, BPF_HDR_START_NET)) {
        bpf_trace_printk(fmt, sizeof(fmt));
        return 1;
    }

    // call appropriate protocol handler
    switch (iphdrs->iphdr.protocol) {
        case IPPROTO_TCP:
            return cgroup_skb_handle_proto_tcp(ctx, iphdrs, protohdrs);
        case IPPROTO_UDP:
            return cgroup_skb_handle_proto_udp(ctx, iphdrs, protohdrs);
        case IPPROTO_ICMP:
            return cgroup_skb_handle_proto_icmp(ctx, iphdrs, protohdrs);
        case IPPROTO_ICMPV6:
            return cgroup_skb_handle_proto_icmpv6(ctx, iphdrs, protohdrs);
    }

    return 0;
}

// cgroup_skb_handle_family

static __always_inline u32 cgroup_skb_handle_family(struct __sk_buff *ctx,
                                                    iphdrs *iphdrs,
                                                    protohdrs *protohdrs)
{
    char *fmt = "ERROR: family: could not load relative packet bytes";

    void *dest;
    u32 size;

    switch (ctx->family) {
        case PF_INET:
            dest = &iphdrs->iphdr;
            size = sizeof(struct iphdr);
            break;
        case PF_INET6:
            dest = &iphdrs->ipv6hdr;
            size = sizeof(struct ipv6hdr);
            break;
        default:
            return 0;
    }

    // load IP header into its buffer
    if (bpf_skb_load_bytes_relative(ctx, 0, dest, size, BPF_HDR_START_NET)) {
        bpf_trace_printk(fmt, sizeof(fmt));
        return 1;
    }

    return cgroup_skb_handle_proto(ctx, iphdrs, protohdrs);
}

