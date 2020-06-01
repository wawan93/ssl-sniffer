package main

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"time"

	"github.com/google/gopacket"
)

func main() {
	live, err := pcap.OpenLive("eth0", 1500, false, time.Minute)
	if err != nil {
		log.Fatalf("can't open live: %v", err)
	}
	log.Printf("open live")
	defer live.Close()

	err = live.SetBPFFilter("(dst port 443)")
	if err != nil {
		log.Fatalf("can't set filter: %v", err)
	}

	psrc := gopacket.NewPacketSource(live, live.LinkType())

	for packet := range psrc.Packets() {
		go packetInfo(packet)
	}

	// TODO: detect SSL handshake packets
	// TODO: Print to stdout each detection in the following format:
	// IP_SRC,TCP_SRC,IP_DST,TCP_DST,COUNT(TCP_OPTIONS)
}

func packetInfo(packet gopacket.Packet) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)
	decodedLayers := make([]gopacket.LayerType, 0, 10)
	err := parser.DecodeLayers(packet.Data(), &decodedLayers)
	fmt.Println(ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort) // TODO: options
	if err != nil {
		fmt.Println("error encountered:", err)
	}
}
