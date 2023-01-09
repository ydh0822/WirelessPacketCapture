package main

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"strconv"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	WPC_()
}

func ExcuteCMD(script string, arg ...string) {
	cmd := exec.Command(script, arg...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(output))
		fmt.Println((err))
	} else {
		fmt.Println(string(output))
	}
}

const (
	defaultSnapLen = 262144
)

type H4uN_packet struct {
	Radiotap                  [9]byte
	Dot11_Frame_Control_Field []byte
	Inner_data                []byte
}

func New_H4uN_packet() *H4uN_packet {
	New_pack := H4uN_packet{}
	s_temp := "08000000"
	data, err := hex.DecodeString(s_temp)
	if err != nil {
		panic(err)
	}
	New_pack.Dot11_Frame_Control_Field = data
	return &New_pack
}

func CheckEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func WPC_() {
	fmt.Println("__start WPC__")
	var name string
	var CH int
	fmt.Printf("Input Wireless interface Name : ")
	fmt.Scanln(&name)
	fmt.Printf("Input Packet Channel : (Hopping=0)")
	fmt.Scanln(&CH)

	if CH != 0 {
		CH_str := strconv.Itoa(CH)
		ExcuteCMD("sudo", "iwconfig", name, CH_str)
	}

	H_pack := New_H4uN_packet()
	fmt.Println("H_pack파싱")
	fmt.Println(H_pack)

	handle, err := pcap.OpenLive(name, defaultSnapLen, true,
		pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	for pkt := range packets {
		// fmt.Print("\033[H\033[2J")
		fmt.Println("pkt========================================")
		// fmt.Println(pkt)
		fmt.Println(pkt.Data())
		Pkt_Frame := []byte{pkt.Data()[9], pkt.Data()[10], pkt.Data()[11], pkt.Data()[12]}
		fmt.Println(Pkt_Frame)
		fmt.Println(H_pack.Dot11_Frame_Control_Field)

		if CheckEq(H_pack.Dot11_Frame_Control_Field, Pkt_Frame) {
			fmt.Println("correct!!")
		}
		fmt.Println(CheckEq(H_pack.Dot11_Frame_Control_Field, Pkt_Frame))
		fmt.Println("========================================")
		// time.Sleep(time.Second * 1)
	}
}
