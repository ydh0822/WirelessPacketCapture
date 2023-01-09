package main

import (
	"fmt"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	WPC_()
}

func (p *PacketSource) H4uN_Packets(int channels) chan Packet {
	if p.c == nil {
		p.c = make(chan Packet, 1000)
		go p.packetsToChannel()
	}
	return p.c
}

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

func WPC_() {
	fmt.Println("__start WPC__")
	var name string
	fmt.Printf("Input Wireless interface Name : ")
	fmt.Scanln(&name)
	handle, err := pcap.OpenLive(name, defaultSnapLen, true,
		pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	println(handle)
	fmt.Println("========================================")
	defer handle.Close()

	// if err := handle.SetBPFFilter("port 3030"); err != nil {
	// 	panic(err)
	// }
	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).H4uN_Packets()

	fmt.Println(packets)
	fmt.Println("========================================")
	for pkt := range packets {
		// fmt.Print("\033[H\033[2J")
		fmt.Println(pkt)
		pkt.
		// time.Sleep(time.Second * 1)
	}
}
