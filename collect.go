package sniff

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"strings"
)

func CollectTo(hostDb HostDatabase, packets chan gopacket.Packet) {
	for packet := range packets {
		hostDb.NotifyPackage()
		ethernetLayer, _ := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		if ethernetLayer != nil {
			hostDb.NotifyEthernetPackage(ethernetLayer.SrcMAC)
		}

		if handleArp(hostDb, packet) {
			continue
		}
		//if ipLayer != nil {
		//	var ip net.IP
		//	var inSubnet = false
		//	ip = ipLayer.SrcIP
		//	for _, network := range networks {
		//		if network.Contains(ip) {
		//			inSubnet = true
		//			break
		//		}
		//		if inSubnet {
		//			hostDb.AddIp(ethernetLayer.SrcMAC, ip)
		//		}
		//	}
		//}

		if handleMDNS(hostDb, packet) {
			continue
		}

		if handleDNS(hostDb, packet) {
			continue
		}

	}
}
func handleDNS(hostDb HostDatabase, packet gopacket.Packet) bool {
	dnsLayer, _ := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if dnsLayer == nil {
		return false
	}
	for _, answer := range dnsLayer.Answers {
		switch answer.Type {
		case layers.DNSTypeA:
			{
				hostDb.AddHostnameByIp(answer.IP, string(answer.Name))
			}
		case layers.DNSTypeAAAA:
			{
				hostDb.AddHostnameByIp(answer.IP, string(answer.Name))
			}

		case layers.DNSTypePTR:
			{
				ip, err := ReverseDomainToIp(string(answer.Name))
				if err == nil {
					hostDb.AddHostnameByIp(ip, string(answer.PTR))
				}
			}
		}
	}
	return true
}

func handleMDNS(hostDb HostDatabase, packet gopacket.Packet) bool {
	udpLayer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.UDP)
	if udpLayer != nil && udpLayer.SrcPort == 5353 && udpLayer.DstPort == 5353 {
		return false
	}

	//ethernetLayer, _ := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	//ip4Layer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	//ip6Layer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv6)
	//var sourceIp net.IP
	//if ip6Layer != nil {
	//	sourceIp = ip6Layer.SrcIP
	//	//if !bytes.Equal(ipLayer.DstIP, multicastIpv4) || !bytes.Equal(ipLayer.DstIP, multicastIpv6) {
	//	//	return false
	//	//}
	//} else if ip4Layer != nil {
	//	sourceIp = ip4Layer.SrcIP
	//} else {
	//	return false
	//}

	dnsLayer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.DNS)
	if dnsLayer == nil {
		return false
	}

	//multicastIpv4 := net.IPv4(224, 0, 0, 251)
	//multicastIpv6 := net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	for _, answer := range dnsLayer.Answers {
		switch answer.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			hostname := strings.TrimSuffix(string(answer.Name), ".local")
			hostDb.AddHostnameByIp(answer.IP, hostname)
		}
	}
	return true
}

func handleArp(hostDb HostDatabase, packet gopacket.Packet) bool {
	arpLayer, _ := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
	if arpLayer == nil {
		return false
	}
	if arpLayer.Operation == layers.ARPReply {
		const ArpProtocolIpv4 = 0x800
		if arpLayer.Protocol == ArpProtocolIpv4 && arpLayer.ProtAddressSize == 4 && arpLayer.HwAddressSize == 6 {
			hostDb.AddIp(arpLayer.SourceHwAddress, arpLayer.SourceProtAddress)
			hostDb.AddIp(arpLayer.DstHwAddress, arpLayer.DstProtAddress)
		}
	}
	return true
}
