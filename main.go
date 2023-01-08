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

	if err := handle.SetLinkType(2); err != nil {
		panic(err)
	}

	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	for pkt := range packets {
		// Your analysis here!
		fmt.Print("\033[H\033[2J")
		fmt.Println(pkt)
		fmt.Print("Contents = ")
		fmt.Println(pkt.Layer(4).LayerContents())
		fmt.Print("Payload = ")
		fmt.Println(pkt.Layer(4).LayerPayload())
		fmt.Println(pkt.Layer(1).LayerType())

		time.Sleep(time.Second * 1)
	}
}
