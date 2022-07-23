package main

import "C"

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

// Each eBPF program in drafts.bpf.c (search for "eBPF program types") is
// described as one event to userland code. Each event can be enabled/disabled.
// If enabled, the eBPF program will generate an event to userland and the event
// will be displayed.
//
// For you: pick the event most similar to what you need and duplicate it in
// drafts.bpf.c. Make sure to rename the eBPF program name (the function name)
// and extend the event types with the type you just created. You can disable
// all other events and only enable the one you're creating. You can also
// extend the "data" struct to submit more data from eBPF to userland (make
// sure to check struct padding if you do so).

// existing eBPF events

type EventType uint32

const (
	EventKprobeSync EventType = iota + 1
	EventKprobeSyncMap
	EventTpSync
	EventTpOpenat
	EventTpOpenatExit
	EventCgroupSocket
	EventCgroupSkbEgress
)

func NewEventType(eventNum uint32) EventType {
	m := map[uint32]EventType{
		1: EventKprobeSync,
		2: EventKprobeSyncMap,
		3: EventTpSync,
		4: EventTpOpenat,
		5: EventTpOpenatExit,
		6: EventCgroupSocket,
		7: EventCgroupSkbEgress,
	}

	return m[eventNum]
}

func (e EventType) String() string {
	m := map[EventType]string{
		EventKprobeSync:      "Kprobe Sync Event",
		EventKprobeSyncMap:   "Kprobe Sync Event From Hashmap",
		EventTpSync:          "Tracepoint Sync Event",
		EventTpOpenat:        "Tracepoint Openat Event",
		EventTpOpenatExit:    "Tracepoint Openat(Exit) Event",
		EventCgroupSocket:    "Socket Created/Released",
		EventCgroupSkbEgress: "Network Packet Sent",
	}

	return m[e]
}

//
// data structure sent from kernel to userland (add more types as needed)
//

// data the way eBPF programs see
type data struct {
	// task_info struct
	StartTime uint64   // 08 bytes: 000-063 : task start time
	Pid       uint32   // 04 bytes: 064-095 : host process id
	Tgid      uint32   // 04 bytes: 096-127: host thread group id
	Ppid      uint32   // 04 bytes: 128-159: host parent process id
	Uid       uint32   // 04 bytes: 160-191: user id
	Gid       uint32   // 04 bytes: 192-223: group id
	Comm      [16]byte // 16 bytes: 224-351: command (task_comm_len)
	Padding   uint32   // 04 bytes: 352-383: padding/empty
	// end of task_info struct
	EventType      uint32 // 04 bytes: 384-415: eBPF program that generated event
	Padding2       uint32 // 04 bytes: 416-447: padding/empty
	EventTimestamp uint64 // 08 bytes: 448-512: event timestamp
}

// data the way userland golang program sees
type goData struct {
	StartTime      uint
	Pid            uint
	Tgid           uint
	Ppid           uint
	Uid            uint
	Gid            uint
	Comm           string
	EventType      EventType
	EventTimestamp uint
}

// TODO: check padding and pick elem from userland, delete elem from map

// data the way eBPF programs see
type openatKey struct {
	EventTimestamp uint64
	Tgid           uint32
}
type openatValue struct {
	Flags    uint32
	Retcode  int32
	Filename [64]byte
}

// data the way userland golang program sees
// type goOpenAtKey struct {
// 	Timesatmp uint
// 	Pid       uint
// }
type goOpenAtValue struct {
	Flags    uint
	Retcode  int
	Filename string
}

// =D

func main() {
	// For cgroup attachments:
	cgroupRootDir := "/sys/fs/cgroup/unified"
	if _, err := os.Stat(cgroupRootDir); os.IsNotExist(err) {
		cgroupRootDir = "/sys/fs/cgroup"
	}

	// create an eBPF module using eBPF object file from filesystem
	// bpfModule, err = bpf.NewModuleFromFile("drafts.bpf.core.o")
	// OR, much better, unpack the embedded eBPF object file into memory
	b, err := EmbeddedBPF.ReadFile("build/drafts.bpf.core.o")
	if err != nil {
		Error(err)
	}

	// create an eBPF module (using eBPF object file from memory)
	bpfModule, err := bpf.NewModuleFromBuffer(b, "drafts.bpf.core.o")
	if err != nil {
		Error(err)
	}
	defer bpfModule.Close()

	// get the eBPF map object from the unloaded eBPF object
	bpfMapEvents, err := bpfModule.GetMap("perfbuffer")
	if err != nil {
		Error(err)
	}

	// ... and resize it (default: 1024) before loading eBPF object into kernel
	err = bpfMapEvents.Resize(10240) // 10k events possible in perf buffer map
	if err != nil {
		Error(err)
	}

	// load the eBPF object into kernel
	if err = bpfModule.BPFLoadObject(); err != nil {
		Error(err)
	}

	// enable/disable events

	AllEvents := map[EventType]bool{
		EventKprobeSync:      true, // EventKprobeSyncMap set EventKprobeSync
		EventTpSync:          true,
		EventTpOpenat:        true, // Real event is at OpenatExit
		EventTpOpenatExit:    true, // Needs both TpOpenAt events to be enabled
		EventCgroupSocket:    false,
		EventCgroupSkbEgress: false,
	}

	bpfMapEnabled, err := bpfModule.GetMap("enabled")
	if err != nil {
		Error(err)
	}

	for k, v := range AllEvents {
		if v {
			key := uint32(k)
			value := uint8(1)
			bpfMapEnabled.Update(unsafe.Pointer(&key), unsafe.Pointer(&value))
		}
	}

	////
	//// EXAMPLES: eBPF program types (big monolithic on purpose for now)
	////

	//// EventKprobeSync ------------------------------------------------------

	// BPF_PROG_TYPE_KPROBE:
	// sync (SYSCALL_DEFINE0(sync) at sync.c)

	bpfProgKprobeSync, err := bpfModule.GetProgram("ksys_sync")
	if err != nil {
		Error(err)
	}

	// attach eBPF program to the kprobe and get an eBPF link
	bpfLinkKprobeSync, err := bpfProgKprobeSync.AttachKprobe("ksys_sync")
	if err != nil {
		Error(err)
	}

	bpfHashMapSync, err := bpfModule.GetMap("sync_hashmap")
	if err != nil {
		Error(err)
	}

	//// EventTpSync ----------------------------------------------------------

	// BPF_PROG_TYPE_TRACEPOINT
	// sys_enter_sync (/sys/kernel/debug/tracing/events/syscalls/sys_enter_sync)

	bpfProgTpSync, err := bpfModule.GetProgram("tracepoint__syscalls__sys_enter_sync")
	if err != nil {
		Error(err)
	}

	// attach eBPF program to the tracepoint and get an eBPF link
	bpfLinkTpSync, err := bpfProgTpSync.AttachTracepoint(
		"syscalls", "sys_enter_sync",
	)
	if err != nil {
		Error(err)
	}

	//// EventTpOpenat, EventTpOpenatExit -------------------------------------

	// BPF_PROG_TYPE_TRACEPOINT
	// sys_enter_openat (/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat)

	bpfProgTpOpenat, err := bpfModule.GetProgram("tracepoint__syscalls__sys_enter_openat")
	if err != nil {
		Error(err)
	}

	// attach eBPF program to the tracepoint and get an eBPF link
	bpfLinkTpOpenat, err := bpfProgTpOpenat.AttachTracepoint(
		"syscalls", "sys_enter_openat",
	)
	if err != nil {
		Error(err)
	}

	bpfHashMapOpenat, err := bpfModule.GetMap("openat_hashmap")
	if err != nil {
		Error(err)
	}

	// BPF_PROG_TYPE_TRACEPOINT
	// sys_exit_openat (/sys/kernel/debug/tracing/events/syscalls/sys_exit_openat)

	bpfProgTpOpenatExit, err := bpfModule.GetProgram("tracepoint__syscalls__sys_exit_openat")
	if err != nil {
		Error(err)
	}

	// attach eBPF program to the tracepoint and get an eBPF link
	bpfLinkTpOpenatExit, err := bpfProgTpOpenatExit.AttachTracepoint(
		"syscalls", "sys_exit_openat",
	)
	if err != nil {
		Error(err)
	}

	//// EventCgroupSocket ----------------------------------------------------

	// BPF_PROG_TYPE_CGROUP_SOCK (https://github.com/aquasecurity/libbpfgo/pull/196)
	// cgroupv2 directory (/sys/fs/cgroup/unified for root cgroup directory)

	bpfProgSocket, err := bpfModule.GetProgram("cgroup__socket_create")
	if err != nil {
		Error(err)
	}

	bpfLinkSocket, err := bpfProgSocket.AttachCgroup(cgroupRootDir)
	if err != nil {
		Error(err)
	}

	//// EventCgroupSkbEgress -------------------------------------------------

	// BPF_PROG_TYPE_CGROUP_SKB (egress)
	// cgroupv2 directory (/sys/fs/cgroup/unified for root cgroup directory)

	bpfProgSkbEgress, err := bpfModule.GetProgram("cgroup__skb_egress")
	if err != nil {
		Error(err)
	}

	bpfLinkSkbEgress, err := bpfProgSkbEgress.AttachCgroup(cgroupRootDir)
	if err != nil {
		Error(err)
	}

	////
	//// END OF EXAMPLES (common event handler logic now...)
	////

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)

	// initialize an eBPF perf buffer to receive events
	bpfPerfBuffer, err := bpfModule.InitPerfBuf(
		"perfbuffer", eventsChannel, lostChannel, 1,
	)
	if err != nil {
		Error(err)
	}

	// start eBPF perf buffer event polling
	bpfPerfBuffer.Start()

	// signal handling
	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	// event machine

	fmt.Println("Listening for events, <Ctrl-C> or or SIG_TERM to end it.")
	fmt.Println("Tip: execute \"sync\" command somewhere =)")

LOOP:
	for {
		select {
		case dataRaw := <-eventsChannel:
			data := parseEvent(dataRaw)
			printEvent(data)

			switch data.EventType { // check for specific eBPF event received

			case EventKprobeSync:
				// EXAMPLE: eBPF HASHMAP. For EventKprobeSync only: use
				// perfbuffer event as a trigger and pick data from the hashmap
				// as well (data is indexed by pid)

				// pick bytes from the eBPF hashmap
				tgid := uint32(data.Tgid)
				dataRawFromMap, err := bpfHashMapSync.GetValue(unsafe.Pointer(&tgid))
				bpfHashMapSync.DeleteKey(unsafe.Pointer(&tgid)) // cleanup if entry exists
				if err != nil {
					Warning(err)
					continue
				}

				dataFromMap := parseEvent(dataRawFromMap)
				dataFromMap.EventType = EventKprobeSyncMap // change type
				printEvent(dataFromMap)

			case EventTpOpenat:
				// perf-buffer event as trigger for the eBPF map read/update
				key := openatKey{
					EventTimestamp: uint64(data.EventTimestamp),
					Tgid:           uint32(data.Tgid),
				}
				dataRawFromMap, err := bpfHashMapOpenat.GetValue(unsafe.Pointer(&key))
				bpfHashMapOpenat.DeleteKey(unsafe.Pointer(&key)) // cleanup if entry exists
				if err != nil {
					Warning(err)
					continue
				}

				dataFromMap := parseOpenAtValue(dataRawFromMap)
				printOpenAtValue(dataFromMap)
			}

		case lostEvents := <-lostChannel:
			fmt.Fprintf(os.Stdout, "lost %d events\n", lostEvents)

		case <-ctx.Done():
			break LOOP
		}
	}

	// cleanup
	fmt.Println("Cleaning up")

	errors := map[EventType]error{
		EventKprobeSync:      bpfLinkKprobeSync.Destroy(),
		EventTpSync:          bpfLinkTpSync.Destroy(),
		EventTpOpenat:        bpfLinkTpOpenat.Destroy(),
		EventTpOpenatExit:    bpfLinkTpOpenatExit.Destroy(),
		EventCgroupSocket:    bpfLinkSocket.Destroy(),
		EventCgroupSkbEgress: bpfLinkSkbEgress.Destroy(),
	}

	for event, err := range errors {
		if err != nil {
			fmt.Fprintf(os.Stderr, "error event=%s, %v\n", event, err)
		}
	}

	os.Exit(0)
}

func parseEvent(raw []byte) goData {
	var err error
	var dt data

	buffer := bytes.NewBuffer(raw)
	err = binary.Read(buffer, binary.LittleEndian, &dt)
	if err != nil {
		Warning(err)
		return goData{}
	}

	goData := goData{
		StartTime:      uint(dt.StartTime),
		Pid:            uint(dt.Pid),
		Tgid:           uint(dt.Tgid),
		Ppid:           uint(dt.Ppid),
		Uid:            uint(dt.Uid),
		Gid:            uint(dt.Gid),
		Comm:           string(bytes.TrimRight(dt.Comm[:], "\x00")),
		EventType:      NewEventType(dt.EventType),
		EventTimestamp: uint(dt.EventTimestamp),
	}

	return goData
}

func parseOpenAtValue(raw []byte) goOpenAtValue {
	var err error
	var dt openatValue

	buffer := bytes.NewBuffer(raw)
	err = binary.Read(buffer, binary.LittleEndian, &dt)
	if err != nil {
		Warning(err)
		return goOpenAtValue{}
	}

	goOpenAtValue := goOpenAtValue{
		Filename: string(bytes.TrimRight(dt.Filename[:], "\x00")),
		Flags:    uint(dt.Flags),
		Retcode:  int(dt.Retcode),
	}

	return goOpenAtValue
}

func printEvent(goData goData) {
	fmt.Printf(
		"(%s) %s (pid: %d, tgid: %d, ppid: %d, uid: %d, gid: %d)\n",
		goData.EventType,
		goData.Comm,
		goData.Pid,
		goData.Tgid,
		goData.Ppid,
		goData.Uid,
		goData.Gid,
	)
}

func printOpenAtValue(goOpenAtValue goOpenAtValue) {
	fmt.Printf("Openat (filename: %s, flags: %d), retcode: %d\n",
		goOpenAtValue.Filename,
		goOpenAtValue.Flags,
		goOpenAtValue.Retcode,
	)
}

func Warning(err error) {
	_, fn, line, _ := runtime.Caller(1)
	log.Printf("WARNING: %s:%d %v\n", fn, line, err)
}

func Error(err error) {
	_, fn, line, _ := runtime.Caller(1)
	log.Printf("ERROR: %s:%d %v\n", fn, line, err)
	os.Exit(1)
}
