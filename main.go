package main

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

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

func center(s string, n int, fill string) string {
	div := n / 2

	return strings.Repeat(fill, div) + s + strings.Repeat(fill, div)
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
	// fmt.Println("H_pack파싱")
	// fmt.Println(H_pack)

	handle, err := pcap.OpenLive(name, defaultSnapLen, true,
		pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	packets_list := []H4uN_Com_packet{}

	for pkt := range packets {
		if len(pkt.Data()) < 150 {
			continue
		}
		temp_pkt_list := H4uN_Com_packet{
			ESSID:     "",
			ESSID_LEN: 0,
			BSSID:     "",
		}

		// fmt.Println(pkt)
		fmt.Print("\033[H\033[2J")
		fmt.Println("======Raw Data Stream======")
		fmt.Println(pkt.Data())
		fmt.Println("===========================")
		Pkt_Frame := []byte{pkt.Data()[9], pkt.Data()[10], pkt.Data()[11], pkt.Data()[12]}
		if CheckEq(H_pack.Dot11_Frame_Control_Field, Pkt_Frame) {
			// fmt.Println("Find 0x08000000!! It is 802.11 Packet")
			CheckVal := 62 + int(pkt.Data()[61])
			Name_Footer_Frame := []byte{pkt.Data()[CheckVal], pkt.Data()[CheckVal+1], pkt.Data()[CheckVal+2], pkt.Data()[CheckVal+3]}
			// fmt.Println(Name_Footer_Frame)
			if CheckEq(H_pack.ESSID_Footter, Name_Footer_Frame) {
				// fmt.Println("Find 0x01088284!! It is name Field!!")
				temp_Frame := []byte{}
				for i := 0; i < int(pkt.Data()[61]); i++ {
					temp_Frame = append(temp_Frame, pkt.Data()[62+i])
				}
				// fmt.Println(temp_Frame)
				Name_Frame_Data := string(temp_Frame[:])
				temp_pkt_list.ESSID = Name_Frame_Data
				temp_pkt_list.ESSID_LEN = int(pkt.Data()[61])
				// fmt.Println("ESSID =", Name_Frame_Data, "ESSID_LEN = ", int(pkt.Data()[61]))

				temp_BSSID_Frame := []int64{}
				tmp_BSSID_Frame := []string{}
				for j := 0; j < 6; j++ {
					temp_BSSID_Frame = append(temp_BSSID_Frame, int64(pkt.Data()[34+j]))
					tmp_BSSID_Frame = append(tmp_BSSID_Frame, fmt.Sprintf("%02x", temp_BSSID_Frame[j]))
					// BSSID_Frame = append(BSSID_Frame, strconv.FormatInt(temp_BSSID_Frame[j], 16))
					if j != 5 {
						tmp_BSSID_Frame = append(tmp_BSSID_Frame, ":")
					}

				}
				// fmt.Println(temp_BSSID_Frame)
				BSSID_Frame := strings.Join(tmp_BSSID_Frame, "")
				temp_pkt_list.BSSID = BSSID_Frame
				// fmt.Println("BSSID = ", BSSID_Frame)
				flag := 0
				for w := 0; w < len(packets_list); w++ {
					if temp_pkt_list.ESSID == packets_list[w].ESSID {
						packets_list[w].BSSID = temp_pkt_list.BSSID
						packets_list[w].ESSID = temp_pkt_list.ESSID
						packets_list[w].ESSID_LEN = temp_pkt_list.ESSID_LEN
						flag++
					}
				}
				if flag == 0 {
					packets_list = append(packets_list, temp_pkt_list)
				}
				fmt.Println(center("BSSID", 25, " "), center("ESSID", 25, " "), center("ESSID LENGTH", 18, " "))
				for k := 0; k < len(packets_list); k++ {
					tmp_int := strconv.FormatInt(int64(packets_list[k].ESSID_LEN), 10)
					fmt.Println(center(packets_list[k].BSSID, 30-len(packets_list[k].BSSID), " "), center(packets_list[k].ESSID, 30-len(packets_list[k].ESSID), " "), center(tmp_int, 30, " "))
				}
				time.Sleep(time.Second * 1)
			} else {
				continue
			}
		} else {
			// fmt.Println("Can't Find ESSID!!")
			continue
		}
	}
}
