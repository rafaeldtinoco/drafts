# Drafts: A starting point for my eBPF applications

## What is this ?

If you want to start coding in eBPF and Golang, use this as a simple skeleton.

All you have to do is to change:

- drafts.bpf.c (adding your eBPF programs, removing existing ones)
- drafts.go (receiving the events, reading the maps)

> Check [libbpf-tools]/*.bpf.c for examples.

## eBPF Programs

There is an example for the following eBPF program types:

- BPF_PROG_TYPE_KPROBE
- BPF_PROG_TYPE_TRACEPOINT
- BPF_PROG_TYPE_CGROUP_SKB
- BPF_PROG_TYPE_CGROUP_SOCK
- BPF_PROG_TYPE_CGROUP_SOCK_ADDR

You will find each eBPF program type was introduced to satisfy a "story"
described in the file `drafts.bpf.c`.

## eBPF Maps

There is an example for the following eBPF map types:

- BPF_MAP_TYPE_HASH
- BPF_MAP_TYPE_PERF_EVENT_ARRAY
- BPF_MAP_TYPE_PERCPU_HASH

## TODOs

1. To add at least 1 example for each existing eBPF program type.
1. To add at least 1 example for each existing eBPF map type.

## Compile and Run

```
$ make clean
$ make all

$ sudo ./drafts
Listening for events, <Ctrl-C> or or SIG_TERM to end it.
Tip: execute "sync" command somewhere =)
(origin: Tracepoint Sync Event) sync (pid: 187206, tgid: 187206, ppid: 3517756, uid: 1000, gid: 1000)
(origin: Kprobe Sync Event) sync (pid: 187206, tgid: 187206, ppid: 3517756, uid: 1000, gid: 1000)
(origin: Kprobe Sync Event From Hashmap) sync (pid: 187206, tgid: 187206, ppid: 3517756, uid: 1000, gid: 1000)
Cleaning up
```

## Credits

This code uses:

- libbpfgo (https://github.com/aquasecurity/libbpfgo)
- libbpf (https://github.com/libbpf/libbpf)

Have fun!

[tracee]: https://github.com/aquasecurity/tracee
[libbpf-tools]: https://github.com/iovisor/bcc/tree/master/libbpf-tools
