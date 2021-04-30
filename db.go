package sniff

import (
	"net"
	"sync"
	"time"
)

type HostStats struct {
	EthernetPackageCount int
	PackageCount         int
	HostsCount           int
}

type HostDatabase interface {
	Hosts() []HostInfos
	AddIp(hw net.HardwareAddr, ip net.IP)
	AddHostname(hwAddr net.HardwareAddr, hostname string)
	AddHostnameByIp(ip net.IP, hostname string)
	NotifyEthernetPackage(net.HardwareAddr)
	Stat() *HostStats
	NotifyPackage()
}

type inMemoryDatabase struct {
	lock       sync.RWMutex
	hosts      []*HostInfos
	hostsByMac map[string]*HostInfos
	hostsByIP  map[string]*HostInfos
	updated    chan []*HostInfos
	stats      HostStats
}

func (db *inMemoryDatabase) Stat() *HostStats {
	stats := db.stats
	stats.HostsCount = len(db.hosts)
	return &stats
}

func (db *inMemoryDatabase) NotifyPackage() {
	db.stats.PackageCount++
}

func (db *inMemoryDatabase) NotifyEthernetPackage(hwAddr net.HardwareAddr) {
	db.lock.Lock()
	host := db.findOrCreateByMac(hwAddr)
	host.CountPackage()
	db.stats.EthernetPackageCount++
	db.lock.Unlock()
}

func (db *inMemoryDatabase) PollHosts(time.Duration) chan []*HostInfos {
	return db.updated
}

func (db *inMemoryDatabase) Hosts() []HostInfos {
	db.lock.RLock()
	defer db.lock.RUnlock()
	result := make([]HostInfos, len(db.hosts))
	for i, host := range db.hosts {
		result[i] = *host
	}
	return result
}

func (db *inMemoryDatabase) findOrCreateByMac(hwAddr net.HardwareAddr) *HostInfos {
	host := db.hostsByMac[bytesToIndex(hwAddr)]
	if host == nil {
		host = &HostInfos{
			HardwareAddresses: []net.HardwareAddr{hwAddr},
		}
		db.add(host)
	}
	return host
}

func (db *inMemoryDatabase) notifyUpdated() {
}

func (db *inMemoryDatabase) AddIp(hw net.HardwareAddr, ip net.IP) {
	db.lock.Lock()
	infoByHw := db.hostsByMac[bytesToIndex(hw)]
	infoByIp := db.hostsByIP[bytesToIndex(ip)]
	if infoByHw == nil && infoByIp == nil {
		info := &HostInfos{
			IPAddresses:       []net.IP{ip},
			HardwareAddresses: []net.HardwareAddr{hw},
		}
		db.add(info)
	} else if infoByIp != nil {
		if infoByHw == nil {
			infoByIp.AddHardwareAddress(hw)
		} else {
			infoByIp.CopyFrom(infoByHw)
			db.remove(infoByHw)
		}
		db.update(infoByIp)
	} else {
		infoByHw.AddIp(ip)
		db.update(infoByHw)
	}
	db.lock.Unlock()
	db.notifyUpdated()
}

func (db *inMemoryDatabase) AddHostname(hwAddr net.HardwareAddr, hostname string) {
	db.lock.Lock()
	hostInfo := db.findOrCreateByMac(hwAddr)
	hostInfo.AddHostname(hostname)
	db.lock.Unlock()
	db.notifyUpdated()
}

func (db *inMemoryDatabase) AddHostnameByIp(ip net.IP, hostname string) {
	db.lock.Lock()
	hostInfo := db.findOrCreateByIp(ip)
	hostInfo.AddHostname(hostname)
	db.lock.Unlock()
	db.notifyUpdated()
}

func (db *inMemoryDatabase) findOrCreateByIp(ip net.IP) *HostInfos {
	host := db.hostsByIP[bytesToIndex(ip)]
	if host == nil {
		host = &HostInfos{
			IPAddresses: []net.IP{ip},
		}
		db.add(host)
	}
	return host
}

func (db *inMemoryDatabase) remove(hw *HostInfos) {
	if hw == nil {
		return
	}
	for _, key := range hw.IPAddresses {
		delete(db.hostsByIP, bytesToIndex(key))
	}
	for _, key := range hw.HardwareAddresses {
		delete(db.hostsByMac, bytesToIndex(key))
	}
}

func (db *inMemoryDatabase) update(hw *HostInfos) {
	for _, key := range hw.IPAddresses {
		db.hostsByIP[bytesToIndex(key)] = hw
	}
	for _, key := range hw.HardwareAddresses {
		db.hostsByMac[bytesToIndex(key)] = hw
	}
}

func (db *inMemoryDatabase) add(info *HostInfos) {
	db.hosts = append(db.hosts, info)
	db.update(info)
}

func NewInMemoryHostDB() HostDatabase {
	return &inMemoryDatabase{
		hostsByMac: make(map[string]*HostInfos),
		hostsByIP:  make(map[string]*HostInfos),
		updated:    make(chan []*HostInfos),
	}
}

func bytesToIndex(b []byte) string {
	return string(b)
}
