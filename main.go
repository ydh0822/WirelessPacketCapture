package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	WPC_()
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
	defer handle.Close()

	// if err := handle.SetBPFFilter("port 3030"); err != nil {
	// 	panic(err)
	// }

	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	for pkt := range packets {
		// Your analysis here!
		fmt.Print("\033[H\033[2J")
		fmt.Println(pkt)
		fmt.Print("1.")
		fmt.Println(pkt.Layers())
		fmt.Print("2.")
		fmt.Println(pkt.Metadata().AncillaryData...)
		fmt.Print("3.")
		fmt.Println(pkt.Data())
		fmt.Print("4.")
		fmt.Println(pkt.Dump())
		fmt.Print("5.")
		fmt.Println(pkt.Metadata())
		fmt.Print("6.")
		fmt.Println(pkt.String())
		fmt.Print("7.")
		fmt.Println(pkt.NetworkLayer())
		fmt.Print("8.")
		time.Sleep(time.Second * 1)
	}
}
