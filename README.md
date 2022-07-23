# Drafts: A starting point for my eBPF applications

## What is this ?

If you want to start coding in eBPF and Golang, use this as a simple skeleton.

All you have to do is to change:

- drafts.bpf.c (adding your eBPF programs, removing existing ones)
- drafts.go (receiving the events, reading the maps)

> Check [libbpf-tools]/*.bpf.c for examples.

## eBPF Programs

For now I have included only 2 eBPF program types:

- Kprobe
- Tracepoint

Both attached to "sync()" function in kernel. Whenever their programs run, when
their hooks are triggered, they send an event to userland through perfbuffer.

## eBPF Maps

I have also added an eBPF map example. When the Kprobe event is received, I use
it as a trigger to read the entry that was added by the eBPF program in an eBPF
hash map. This shows a different way of sharing data: instead of using
perfbuffer or ringbuffer, to simply read data from the eBPF maps directly from
userland.

## Future

1. I'll add 1 example to each existing eBPF program type.
1. I'll also add capability to select from perfbuffer or ringbuffer.

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
