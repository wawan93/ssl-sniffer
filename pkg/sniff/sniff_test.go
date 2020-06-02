package sniff_test

import (
	"testing"

	"github.com/google/gopacket"

	"sniffer/pkg/sniff"
)

func TestPacketInfo(t *testing.T) {
	data := []byte{2, 66, 172, 17, 0, 2, 2, 66, 50, 6, 118, 1, 8, 0, 69, 0, 0, 60, 72, 251, 64, 0, 64, 6, 153, 155, 172, 17, 0, 1, 172, 17, 0, 2, 170, 166, 1, 187, 172, 243, 252, 105, 0, 0, 0, 0, 160, 2, 114, 16, 88, 84, 0, 0, 2, 4, 5, 180, 4, 2, 8, 10, 158, 115, 109, 161, 0, 0, 0, 0, 1, 3, 3, 7}
	p := packet{
		data: data,
	}
	ch := make(chan string, 1)
	sniff.PacketInfo(p, ch)
	msg := <-ch

	expected := "172.17.0.1\t43686\t172.17.0.2\t443(https)\t5"
	if msg != expected {
		t.Errorf(`unexpected msg: want "%s", got "%s"`, expected, msg)
	}
}

type packet struct {
	data []byte
}

func (p packet) Data() []byte {
	return p.data
}

func (p packet) String() string {
	panic("implement me")
}

func (p packet) Dump() string {
	panic("implement me")
}

func (p packet) Layers() []gopacket.Layer {
	panic("implement me")
}

func (p packet) Layer(layerType gopacket.LayerType) gopacket.Layer {
	panic("implement me")
}

func (p packet) LayerClass(class gopacket.LayerClass) gopacket.Layer {
	panic("implement me")
}

func (p packet) LinkLayer() gopacket.LinkLayer {
	panic("implement me")
}

func (p packet) NetworkLayer() gopacket.NetworkLayer {
	panic("implement me")
}

func (p packet) TransportLayer() gopacket.TransportLayer {
	panic("implement me")
}

func (p packet) ApplicationLayer() gopacket.ApplicationLayer {
	panic("implement me")
}

func (p packet) ErrorLayer() gopacket.ErrorLayer {
	panic("implement me")
}

func (p packet) Metadata() *gopacket.PacketMetadata {
	panic("implement me")
}
