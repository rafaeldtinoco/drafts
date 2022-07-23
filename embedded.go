package main

import (
	"embed"
)

//go:embed "build/drafts.bpf.core.o"

var EmbeddedBPF embed.FS
