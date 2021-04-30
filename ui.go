package sniff

import (
	"fmt"
	"github.com/gdamore/tcell/v2"
	"github.com/mattn/go-runewidth"
	"net"
	"os"
	"sort"
	"time"
)

func emitStr(s tcell.Screen, x, y int, style tcell.Style, str string) {
	if str == "" {
		return
	}
	for _, c := range str {
		var comb []rune
		w := runewidth.RuneWidth(c)
		if w == 0 {
			comb = []rune{c}
			c = ' '
			w = 1
		}
		s.SetContent(x, y, c, comb, style)
		x += w
	}
}

type UIController struct {
	rowOffset         int
	rowSelected       int
	HostDatabase      HostDatabase
	PacketCounter     int
	Updated           chan interface{}
	MacVendorDatabase MacVendorDatabase
}

func NewUIController(macVendorDatabase MacVendorDatabase, hostDatabase HostDatabase) *UIController {
	return &UIController{
		Updated:           make(chan interface{}),
		MacVendorDatabase: macVendorDatabase,
		HostDatabase:      hostDatabase,
	}
}

func (c *UIController) SelectRow(row int) {
	c.rowSelected = row
	c.Updated <- true
}

func (c *UIController) NextRow() {
	c.rowSelected++
	c.Updated <- true
}

func (c *UIController) PreviousRow() {
	c.rowSelected = c.rowSelected - 1
	if c.rowSelected < 0 {
		c.rowSelected = 0
	}
	c.Updated <- true
}

func (c *UIController) ShowHosts(s tcell.Screen, x, y, width, height int) {
	lines := 0
	width = MinInt(100, width)
	tableRows := make([][]string, 0)
	tableRows = append(tableRows, []string{"hwAddress", "ipAddress", "hostname"})
	header := tcell.StyleDefault.Bold(true)
	//header = header.Bold(true)
	lineTemplate := fmt.Sprintf("%%-17.17s %%-8.8s %%-27s %%-%ds", width-(17+1+8+1+27))
	emitStr(s, x, y, header, fmt.Sprintf(lineTemplate, "HW Address", "Vendor", "IP Address", "Hostname"))

	odd := tcell.StyleDefault
	even := odd

	hosts := c.HostDatabase.Hosts()
	sort.Sort(SortableHosts(hosts))
	rowSelected := MaxInt(0, MinInt(len(hosts)-1, c.rowSelected))
	rowOffset := MaxInt(0, MinInt(len(hosts)-1, c.rowOffset))

	for hostNum, host := range hosts[rowOffset:] {
		realHostNum := hostNum + rowOffset
		var style tcell.Style
		if (realHostNum)%2 == 1 {
			style = odd
		} else {
			style = even
		}
		if realHostNum == rowSelected {
			style = style.Background(tcell.ColorLightGreen)
		}
		rows := MaxInt(len(host.HardwareAddresses), len(host.IPAddresses), len(host.Hostnames))
		for row := 0; row < rows; row++ {
			var hwAddress net.HardwareAddr
			ipAddress := ""
			hostname := ""
			if row < len(host.HardwareAddresses) {
				hwAddress = host.HardwareAddresses[row]
			}
			if row < len(host.IPAddresses) {
				ipAddress = host.IPAddresses[row].String()
			}
			if row < len(host.Hostnames) {
				hostname = host.Hostnames[row]
			}
			mac := ""
			org := ""
			if hwAddress != nil {
				vendor := c.MacVendorDatabase.Lookup(hwAddress)
				mac = hwAddress.String()
				if vendor != nil {
					org = vendor.ShortName
				}
			}
			emitStr(s, x, lines+y+1, style, fmt.Sprintf(lineTemplate, mac, org, ipAddress, hostname))
			lines++
			if lines+1 >= height {
				break
			}
		}
	}
	c.rowOffset = rowOffset
	c.rowSelected = rowSelected
	s.Show()
}

func (c *UIController) UiLoop() {
	tcell.SetEncodingFallback(tcell.EncodingFallbackFail)
	s, e := tcell.NewScreen()
	if e != nil {
		fmt.Fprintf(os.Stderr, "%v\n", e)
		os.Exit(1)
	}
	if e = s.Init(); e != nil {
		fmt.Fprintf(os.Stderr, "%v\n", e)
		os.Exit(1)
	}
	defer s.Fini()
	s.SetStyle(tcell.StyleDefault)

	s.Clear()

	quit := make(chan struct{})
	go func() {
		for {
			ev := s.PollEvent()
			switch ev := ev.(type) {
			case *tcell.EventKey:
				switch ev.Key() {
				case tcell.KeyEscape, tcell.KeyCtrlC:
					fmt.Println("quit")
					close(quit)
					return
				case tcell.KeyCtrlL:
					s.Sync()
				case tcell.KeyDown, tcell.KeyDownRight, tcell.KeyDownLeft:
					c.NextRow()
				case tcell.KeyUp, tcell.KeyUpRight, tcell.KeyUpLeft:
					c.PreviousRow()
				}
			case *tcell.EventResize:
				s.Sync()
			}
		}
	}()

	defer s.Fini()

	timer := time.NewTimer(1 * time.Second)
	for {
		select {
		case <-quit:
			fmt.Println("quit received")
			return
		case <-c.Updated:
			//println("controller updated")
			timer.Reset(1 * time.Millisecond)
		case <-timer.C:
			width, height := s.Size()
			s.Clear()
			c.ShowStats(s, 0, 0)
			c.ShowHosts(s, 0, 3, width, height-3)
			timer.Reset(1 * time.Second)
		}
	}
}

func (c *UIController) ShowStats(s tcell.Screen, x, y int) {
	stats := c.HostDatabase.Stat()
	const (
		hostsLabel    = "Hosts:    "
		packagesLabel = "Packages: "
		ethernetLabel = "Ethernet: "
	)
	labelStyle := tcell.StyleDefault
	counterStyle := tcell.StyleDefault.Bold(true)
	emitStr(s, x, y, labelStyle, hostsLabel)
	emitStr(s, x+len(hostsLabel), y, counterStyle, fmt.Sprintf("%6d", stats.HostsCount))

	y++
	currentX := x
	emitStr(s, currentX, y, labelStyle, packagesLabel)
	currentX += len(packagesLabel)
	emitStr(s, currentX, y, counterStyle, fmt.Sprintf("%6d", stats.PackageCount))
	currentX += 12
	emitStr(s, currentX, y, labelStyle, ethernetLabel)
	currentX += len(ethernetLabel)
	emitStr(s, currentX, y, counterStyle, fmt.Sprintf("%6d", stats.EthernetPackageCount))

}
