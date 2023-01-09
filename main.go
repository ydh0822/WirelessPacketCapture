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
	ESSID_Footter             []byte
}

type H4uN_Com_packet struct {
	ESSID     string
	ESSID_LEN int
	BSSID     string
}

func New_H4uN_packet() *H4uN_packet {
	New_pack := H4uN_packet{}
	s_Dot11_Sig := "08000000"
	s_SSID_Footer := "01088284"
	data1, err := hex.DecodeString(s_Dot11_Sig)
	if err != nil {
		panic(err)
	}
	data2, err := hex.DecodeString(s_SSID_Footer)
	if err != nil {
		panic(err)
	}
	New_pack.Dot11_Frame_Control_Field = data1
	New_pack.ESSID_Footter = data2
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
		if CheckEq(H_pack.Dot11_Frame_Control_Field, Pkt_Frame) {
			fmt.Println("Find 0x08000000!! It is 802.11 Packet")
			CheckVal := 62 + int(pkt.Data()[61])
			Name_Footer_Frame := []byte{pkt.Data()[CheckVal], pkt.Data()[CheckVal+1], pkt.Data()[CheckVal+2], pkt.Data()[CheckVal+3]}
			fmt.Println(Name_Footer_Frame)
			if CheckEq(H_pack.ESSID_Footter, Name_Footer_Frame) {
				fmt.Println("Find 0x01088284!! It is name Field!!")
				temp_Frame := []byte{}
				for i := 0; i < int(pkt.Data()[61]); i++ {
					temp_Frame = append(temp_Frame, pkt.Data()[62+i])
				}
				fmt.Println(temp_Frame)
				Name_Frame_Data := string(temp_Frame[:])
				fmt.Println("ESSID =", Name_Frame_Data, "ESSID_LEN = ", int(pkt.Data()[61]))

				temp_BSSID_Frame := []int64{}
				BSSID_Frame := []string{}
				for j := 0; j < 6; j++ {
					temp_BSSID_Frame = append(temp_BSSID_Frame, int64(pkt.Data()[34+j]))
					if j%2 != 0 {
						BSSID_Frame[j] = ":"
					}
					BSSID_Frame[j*2] = strconv.FormatInt(temp_BSSID_Frame[j], 16)
				}
				fmt.Println(temp_BSSID_Frame)
				fmt.Println(BSSID_Frame)

			} else {
				continue
			}
		} else {
			fmt.Println("Can't Find ESSID!!")
			continue
		}
		fmt.Println("========================================")
		// time.Sleep(time.Second * 1)
	}
}
