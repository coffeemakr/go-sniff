package sniff

import (
	"bytes"
	"net"
	"sort"
	"time"
)

type SortableIps []net.IP

func (s SortableIps) Len() int {
	return len(s)
}
func (s SortableIps) Less(i, j int) bool {
	return bytes.Compare(s[i], s[j]) < 0
}
func (s SortableIps) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type SortableHosts []HostInfos

func (s SortableHosts) Len() int {
	return len(s)
}

func (s SortableHosts) Less(i, j int) bool {
	firstIps := s[i].IPAddresses
	secondIps := s[j].IPAddresses
	sort.Sort(SortableIps(firstIps))
	sort.Sort(SortableIps(secondIps))
	if len(firstIps) == 0 && len(secondIps) == 0 {
		return bytes.Compare(s[i].HardwareAddresses[0], s[j].HardwareAddresses[0]) < 0
	} else if len(firstIps) > 0 && len(secondIps) == 0 {
		return true
	} else if len(firstIps) == 0 && len(secondIps) > 0 {
		return false
	} else {
		return bytes.Compare(firstIps[0], secondIps[0]) < 0
	}
}

func (s SortableHosts) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type SortableHwAddrs []net.HardwareAddr

func (s SortableHwAddrs) Len() int {
	return len(s)
}
func (s SortableHwAddrs) Less(i, j int) bool {
	return bytes.Compare(s[i], s[j]) < 0
}
func (s SortableHwAddrs) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type HostInfos struct {
	HardwareAddresses []net.HardwareAddr
	IPAddresses       []net.IP
	Hostnames         []string
	PackagesCount     int
	LastPackage       time.Time
}

func (hostInfo *HostInfos) AddIp(ip net.IP) {
	for _, existingIp := range hostInfo.IPAddresses {
		if bytes.Equal(existingIp, ip) {
			return
		}
	}
	hostInfo.IPAddresses = append(hostInfo.IPAddresses, ip)
	sort.Sort(SortableIps(hostInfo.IPAddresses))
}

func (hostInfo *HostInfos) AddHostname(hostname string) {
	for _, existing := range hostInfo.Hostnames {
		if existing == hostname {
			return
		}
	}
	hostInfo.Hostnames = append(hostInfo.Hostnames, hostname)
	sort.Strings(hostInfo.Hostnames)
}

func (hostInfo *HostInfos) AddHardwareAddress(addr net.HardwareAddr) {
	for _, existing := range hostInfo.HardwareAddresses {
		if bytes.Equal(addr, existing) {
			return
		}
	}
	hostInfo.HardwareAddresses = append(hostInfo.HardwareAddresses, addr)
	sort.Sort(SortableHwAddrs(hostInfo.HardwareAddresses))
}

func (hostInfo *HostInfos) CopyFrom(other *HostInfos) {
	if other == nil {
		return
	}
	for _, ip := range other.IPAddresses {
		hostInfo.AddIp(ip)
	}
	for _, hw := range other.HardwareAddresses {
		hostInfo.AddHardwareAddress(hw)
	}
	for _, hostname := range other.Hostnames {
		hostInfo.AddHostname(hostname)
	}
}

func (hostInfo *HostInfos) CountPackage() {
	hostInfo.PackagesCount++
	hostInfo.LastPackage = time.Now()
}
