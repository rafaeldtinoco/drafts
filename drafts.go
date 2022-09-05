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
	"strings"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ProbeType uint32

const (
	Kprobe ProbeType = iota + 1
	Kretprobe
	Tracepoint
	CgroupLegacy
)

type EventType uint32

type Event struct {
	eventType  EventType
	desc       string
	enabled    bool
	progName   string
	probeType  ProbeType
	prog       *bpf.BPFProg
	link       *bpf.BPFLink
	traceClass string
	attachType bpf.BPFAttachType
}

func (e Event) String() string {
	return e.desc
}

const (
	EventCgroupSkbIngress EventType = iota + 1
	EventCgroupSkbEgress
	EventKprobeSockAllocFile
	EventKretprobeSockAllocFile
	EventKprobeCgroupBPFFilterSKB
	EventKretprobeCgroupBPFFilterSKB
)

type Events map[EventType]*Event

func AllEvents() Events {
	return Events{
		EventCgroupSkbIngress:            {probeType: CgroupLegacy, progName: "cgroup_skb_ingress", attachType: bpf.BPFAttachTypeCgroupInetIngress, desc: "(cgroup skb) ingress", enabled: true},
		EventCgroupSkbEgress:             {probeType: CgroupLegacy, progName: "cgroup_skb_egress", attachType: bpf.BPFAttachTypeCgroupInetEgress, desc: "(cgroup skb) egress", enabled: true},
		EventKprobeSockAllocFile:         {probeType: Kprobe, progName: "sock_alloc_file", desc: "(kprobe) sock_alloc_file", enabled: true},
		EventKretprobeSockAllocFile:      {probeType: Kretprobe, progName: "ret_sock_alloc_file", desc: "(kretprobe) sock_alloc_file", enabled: true},
		EventKprobeCgroupBPFFilterSKB:    {probeType: Kprobe, progName: "__cgroup_bpf_run_filter_skb", desc: "(cgroup_before) skb", enabled: true},
		EventKretprobeCgroupBPFFilterSKB: {probeType: Kretprobe, progName: "ret___cgroup_bpf_run_filter_skb", desc: "(cgroup_after) skb", enabled: true},
	}
}

func (e Events) GetEvent(eType EventType) *Event {
	return e[eType]
}

func (e Events) GetEventUint32(eType uint32) *Event {
	for n, e := range e {
		if uint32(n) == eType {
			return e
		}
	}
	return nil
}

//
// data structure sent from kernel to userland (add more types as needed)
//

// data the way eBPF programs see (net_info is all zeroed for non network events)
type data struct {
	// task_info struct
	StartTime      uint64   // 08 bytes: 000-063: TASK_INFO BEGIN, task start time
	Pid            uint32   // 04 bytes: 064-095: host process id
	Tgid           uint32   // 04 bytes: 096-127: host thread group id
	Ppid           uint32   // 04 bytes: 128-159: host parent process id
	Uid            uint32   // 04 bytes: 160-191: user id
	Gid            uint32   // 04 bytes: 192-223: group id
	Comm           [16]byte // 16 bytes: 224-351: command (task_comm_len)
	Padding        uint32   // 04 bytes: 352-383: TASK_INFO END, padding/empty
	EventType      uint32   // 04 bytes: 384-415: eBPF program that generated event
	Padding2       uint32   // 04 bytes: 416-447: padding/empty
	EventTimestamp uint64   // 08 bytes: 448-512: event timestamp
	Family         uint32   // 04 bytes: 513-544: NET_INFO BEGIN, socket family
	Type           uint32   // 04 bytes: 545-576: socket type
	Protocol       uint32   // 04 bytes: 577-608: socket protocol
	IPv4Src        uint32   // 04 bytes: 609-640: ipv4 source address
	IPv4Dst        uint32   // 04 bytes: 641-672: ipv4 dest address
	PortSrc        uint16   // 04 bytes: 673-704: source port
	PortDst        uint16   // 04 bytes: 705-736: dest port
	SocketCookie   uint64   // 08 bytes: 737-800: NET_INFO END, socket cookie
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
	EventType      uint
	EventTimestamp uint
}

// data the way userland golang program sees for network related events
type goNetData struct {
	StartTime      uint
	Pid            uint
	Tgid           uint
	Ppid           uint
	Uid            uint
	Gid            uint
	Comm           string
	EventType      uint
	EventTimestamp uint
	Family         uint
	Type           uint
	Protocol       uint
	IPv4Src        uint
	IPv4Dst        uint
	PortSrc        uint
	PortDst        uint
	SocketCookie   uint
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
	err = bpfMapEvents.Resize(10240 * 100) // 1000k events possible in perf buffer map
	if err != nil {
		Error(err)
	}

	// load the eBPF object into kernel
	if err = bpfModule.BPFLoadObject(); err != nil {
		Error(err)
	}

	// enabled map
	bpfMapEnabled, err := bpfModule.GetMap("enabled")
	if err != nil {
		Error(err)
	}

	all := AllEvents()

	// attach all events based on their probe types
	for id, event := range all {
		if event.enabled {
			key := uint32(id)
			value := uint8(1)
			bpfMapEnabled.Update(unsafe.Pointer(&key), unsafe.Pointer(&value))

			event.prog, err = bpfModule.GetProgram(event.progName)
			if err != nil {
				fmt.Printf("progName: %s\n", event.progName)
				Error(err)
			}

			switch event.probeType {
			case Kprobe:
				event.link, err = event.prog.AttachKprobe(event.progName)
			case Kretprobe:
				progName := strings.Replace(event.progName, "ret_", "", 1)
				event.link, err = event.prog.AttachKretprobe(progName)
			case Tracepoint:
				event.link, err = event.prog.AttachTracepoint(event.traceClass, event.progName)
			case CgroupLegacy:
				event.link, err = event.prog.AttachCgroupLegacy(cgroupRootDir, event.attachType)
			}

			if err != nil {
				Error(err)
			}
		}
	}

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
			event := all.GetEventUint32(uint32(data.EventType))
			printEvent(event, data)
			switch EventType(data.EventType) {
			case EventCgroupSkbIngress, EventCgroupSkbEgress:
				// obtaining the packet payload right after event
				packet := gopacket.NewPacket(
					dataRaw[96:],
					layers.LayerTypeIPv4,
					gopacket.Default,
				)
				if packet == nil {
					Warning(fmt.Errorf("could not parse the packet"))
					continue
				}
				//fmt.Printf("%s", packet.Dump())
				fmt.Printf("%s", packet.String())
			}
		case lostEvents := <-lostChannel:
			fmt.Fprintf(os.Stdout, "lost %d events\n", lostEvents)

		case <-ctx.Done():
			break LOOP
		}
	}

	// cleanup
	fmt.Println("Cleaning up")

	// destroy links
	for _, event := range all {
		if event.enabled {
			event.link.Destroy()
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
		EventType:      uint(dt.EventType),
		EventTimestamp: uint(dt.EventTimestamp),
	}

	return goData
}

func parseNetEvent(raw []byte) goNetData {
	var err error
	var dt data

	buffer := bytes.NewBuffer(raw)
	err = binary.Read(buffer, binary.LittleEndian, &dt)
	if err != nil {
		Warning(err)
		return goNetData{}
	}

	goData := goNetData{
		StartTime:      uint(dt.StartTime),
		Pid:            uint(dt.Pid),
		Tgid:           uint(dt.Tgid),
		Ppid:           uint(dt.Ppid),
		Uid:            uint(dt.Uid),
		Gid:            uint(dt.Gid),
		Comm:           string(bytes.TrimRight(dt.Comm[:], "\x00")),
		EventType:      uint(dt.EventType),
		EventTimestamp: uint(dt.EventTimestamp),
		Family:         uint(dt.Family),
		Type:           uint(dt.Type),
		Protocol:       uint(dt.Protocol),
		IPv4Src:        uint(dt.IPv4Src),
		IPv4Dst:        uint(dt.IPv4Dst),
		PortSrc:        uint(dt.PortSrc),
		PortDst:        uint(dt.PortDst),
		SocketCookie:   uint(dt.SocketCookie),
	}

	return goData
}

func printEvent(e *Event, goData goData) {
	fmt.Printf(
		"(%s) %s (pid: %d, tgid: %d, ppid: %d, uid: %d, gid: %d)\n",
		e,
		goData.Comm,
		goData.Pid,
		goData.Tgid,
		goData.Ppid,
		goData.Uid,
		goData.Gid,
	)
}

func inet_ntoa(val uint) string {
	a := byte(val >> 24)
	b := byte(val >> 16)
	c := byte(val >> 8)
	d := byte(val)
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}

func printNetEvent(e *Event, goNetData goNetData) {
	fmt.Printf(
		"    Network Packet:\n"+
			"      cookie: %d\n"+
			"      family: %d type: %d proto: %d\n"+
			"      src addr: %s dst addr: %s\n"+
			"      src port: %d dst port: %d)\n",
		goNetData.SocketCookie,
		goNetData.Family,
		goNetData.Type,
		goNetData.Protocol,
		inet_ntoa(goNetData.IPv4Src),
		inet_ntoa(goNetData.IPv4Dst),
		goNetData.PortSrc,
		goNetData.PortDst,
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
