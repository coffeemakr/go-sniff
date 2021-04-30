package main

import (
	"fmt"
	"github.com/coffeemakr/sniff"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
	"net"
	"os"
)

func init() {
	layers.RegisterUDPPortLayerType(5353, layers.LayerTypeDNS)
}

var rootCmd = &cobra.Command{
	Use:   "sniff interface",
	Run: func(cmd *cobra.Command, args []string) {
		startSniff(args[0])
	},
	Args: cobra.ExactArgs(1),
}

func startSniff(iface string) {
	var hostDb = sniff.NewInMemoryHostDB()
	macVendorDatabase, err := sniff.NewMacVendorDatabase("oui.txt")
	if err != nil {
		panic(err)
	}
	macVendorDatabase = sniff.CacheMacVendorDatabase(macVendorDatabase, 256)
	ui := sniff.NewUIController(macVendorDatabase, hostDb)

	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	var usedInterface *net.Interface
	for _, inte := range interfaces {
		if inte.Name == iface {
			usedInterface = &inte
			break
		}
	}
	if usedInterface == nil {
		fmt.Printf("interface %s does not exist\n", iface)
		os.Exit(130)
	}

	addresses, err := usedInterface.Addrs()
	if err != nil {
		panic(err)
	}
	ourIps := make([]net.IP, 0)
	networks := make([]*net.IPNet, 0)
	for _, address := range addresses {
		ip, network, err := net.ParseCIDR(address.String())
		if err != nil {
			panic(err)
		}
		ourIps = append(ourIps, ip)
		networks = append(networks, network)
	}

	handle, err := pcap.OpenLive(usedInterface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("error captering: %s\n", err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	go func() {
		sniff.CollectTo(hostDb, packets)
	}()

	ui.UiLoop()
	close(packets)

	fmt.Println("end")
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}