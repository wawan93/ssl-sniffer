package sniff

import (
	"context"
	"fmt"
	"runtime"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func Sniff(ctx context.Context, device string) (<-chan string, error) {
	messages := make(chan string)

	live, err := pcap.OpenLive(device, 1600, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("can't open live device %s: %v", device, err)
	}

	// detect SSL handshake packets
	err = live.SetBPFFilter("tcp port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16)")
	if err != nil {
		live.Close()
		return nil, fmt.Errorf("can't set filter: %v", err)
	}

	psrc := gopacket.NewPacketSource(live, live.LinkType())

	packetsCh := psrc.Packets()
	go func() {
		messages <- "start sniffing"
		for {
			select {
			case packet := <-packetsCh:
				go PacketInfo(packet, messages)
			case <-ctx.Done():
				close(messages)
				live.Close()
			default:
				runtime.Gosched()
			}
		}
	}()

	return messages, nil
}

func PacketInfo(packet gopacket.Packet, messages chan<- string) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)
	decodedLayers := make([]gopacket.LayerType, 0, 10)
	err := parser.DecodeLayers(packet.Data(), &decodedLayers)
	if err != nil {
		messages <- fmt.Sprint("error encountered:", err)
	}

	// print to stdout each detection in the following format:
	// IP_SRC,TCP_SRC,IP_DST,TCP_DST,COUNT(TCP_OPTIONS)
	messages <- fmt.Sprintf("%s\t%s\t%s\t%s\t%d", ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort, len(tcp.Options))
}
