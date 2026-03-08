package main

import "testing"

// commString tests

func TestCommString_NullTerminated(t *testing.T) {
	var comm [16]int8
	for i, c := range "nginx" {
		comm[i] = int8(c)
	}
	if got := commString(comm); got != "nginx" {
		t.Errorf("got %q, want %q", got, "nginx")
	}
}

func TestCommString_FullLength(t *testing.T) {
	// 16-character name with no null terminator — all bytes used.
	var comm [16]int8
	for i := range comm {
		comm[i] = int8('a')
	}
	want := "aaaaaaaaaaaaaaaa"
	if got := commString(comm); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCommString_Empty(t *testing.T) {
	var comm [16]int8
	if got := commString(comm); got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

// protoLabel tests

func TestProtoLabel_TCP(t *testing.T) {
	if got := protoLabel(protoTCP); got != "tcp" {
		t.Errorf("got %q, want %q", got, "tcp")
	}
}

func TestProtoLabel_UDP(t *testing.T) {
	if got := protoLabel(protoUDP); got != "udp" {
		t.Errorf("got %q, want %q", got, "udp")
	}
}

func TestProtoLabel_Unknown(t *testing.T) {
	if got := protoLabel(99); got != "proto99" {
		t.Errorf("got %q, want %q", got, "proto99")
	}
}

// dirLabel tests

func TestDirLabel_RX(t *testing.T) {
	if got := dirLabel(dirRX); got != "rx" {
		t.Errorf("got %q, want %q", got, "rx")
	}
}

func TestDirLabel_TX(t *testing.T) {
	if got := dirLabel(dirTX); got != "tx" {
		t.Errorf("got %q, want %q", got, "tx")
	}
}

func TestDirLabel_Unknown(t *testing.T) {
	if got := dirLabel(99); got != "dir99" {
		t.Errorf("got %q, want %q", got, "dir99")
	}
}

// ifaceName tests

func TestIfaceName_Zero(t *testing.T) {
	if got := ifaceName(0); got != "any" {
		t.Errorf("got %q, want %q", got, "any")
	}
}

func TestIfaceName_UnknownIndex(t *testing.T) {
	// Use an ifindex that cannot exist on any real system.
	if got := ifaceName(99999); got != "if99999" {
		t.Errorf("got %q, want %q", got, "if99999")
	}
}
