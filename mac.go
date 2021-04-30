package sniff

import (
	"errors"
	ouidb "github.com/dutchcoders/go-ouitools"
	lru "github.com/hashicorp/golang-lru"
	"net"
)

type MacVendor struct {
	ShortName    string
	Name         string
	PrefixLength int
}

type MacVendorDatabase interface {
	Lookup(addr net.HardwareAddr) *MacVendor
}

type cachingOuiDb struct {
	cache     *lru.Cache
	forwardDb MacVendorDatabase
}

func (c *cachingOuiDb) Lookup(addr net.HardwareAddr) *MacVendor {
	cachedResult, ok := c.cache.Get(bytesToIndex(addr))
	if ok {
		return cachedResult.(*MacVendor)
	}
	result := c.forwardDb.Lookup(addr)
	c.cache.Add(bytesToIndex(addr), result)
	return result
}

func CacheMacVendorDatabase(db MacVendorDatabase, size int) MacVendorDatabase {
	cache, err := lru.New(128)
	if err != nil {
		panic(err)
	}
	return &cachingOuiDb{
		cache:     cache,
		forwardDb: db,
	}
}

type wiresharkOuiDb struct {
	DB *ouidb.OuiDb
}

func NewMacVendorDatabase(wiresharkFile string) (MacVendorDatabase, error) {
	ouiDb := ouidb.New(wiresharkFile)
	if ouiDb == nil {
		return nil, errors.New("error creating database")
	}
	return &wiresharkOuiDb{
		DB: ouiDb,
	}, nil
}

func (wDb wiresharkOuiDb) Lookup(mac net.HardwareAddr) *MacVendor {
	block := wDb.DB.Lookup(ouidb.HardwareAddr(mac))
	if block == nil {
		return nil
	}
	return &MacVendor{
		ShortName:    block.Organization,
		PrefixLength: block.Mask,
		Name:         block.Organization,
	}
}
