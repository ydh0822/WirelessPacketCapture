package main

import (
	"fmt"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	fmt.Println("test")
	WPC_()
}

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

func WPC_() {
	fmt.Println("__start WPC__")
	handle, err := pcap.OpenLive("mon0", defaultSnapLen, true,
		pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// if err := handle.SetBPFFilter("port 3030"); err != nil {
	// 	panic(err)
	// }

	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	for pkt := range packets {
		// Your analysis here!
		fmt.Println(pkt)
	}
}
