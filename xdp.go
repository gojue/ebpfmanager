package manager

import (
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// XdpAttachMode selects a way how XDP program will be attached to interface
type XdpAttachMode int

const (
	// XdpAttachModeNone stands for "best effort" - the kernel automatically
	// selects the best mode (would try Drv first, then fallback to Generic).
	// NOTE: Kernel will not fall back to Generic XDP if NIC driver failed
	//       to install XDP program.
	XdpAttachModeNone XdpAttachMode = 0
	// XdpAttachModeSkb is "generic", kernel mode, less performant comparing to native,
	// but does not requires driver support.
	XdpAttachModeSkb XdpAttachMode = 1 << 1
	// XdpAttachModeDrv is native, driver mode (support from driver side required)
	XdpAttachModeDrv XdpAttachMode = 1 << 2
	// XdpAttachModeHw suitable for NICs with hardware XDP support
	XdpAttachModeHw XdpAttachMode = 1 << 3
)

var _ io.Closer = (*netlinkXDPLink)(nil)

type netlinkXDPLink struct {
	link    netlink.Link
	ifIndex int
	mode    int
}

func (l *netlinkXDPLink) Close() error {
	err := netlink.LinkSetXdpFdWithFlags(l.link, -1, l.mode)
	if err != nil {
		return fmt.Errorf("detach XDP program from interface %d: %w", l.ifIndex, err)
	}
	return nil
}

// attachXDP - Attaches the probe to an interface with an XDP hook point
func (p *Probe) attachXDP() error {
	var err error
	if _, err = p.resolveLink(); err != nil {
		return err
	}

	p.progLink, err = link.AttachXDP(link.XDPOptions{
		Program:   p.program,
		Interface: p.IfIndex,
		Flags:     link.XDPAttachFlags(p.XDPAttachMode),
	})
	if err != nil {
		if !errors.Is(err, link.ErrNotSupported) {
			return fmt.Errorf("link xdp to interface %v: %w", p.IfIndex, err)
		}

		err = netlink.LinkSetXdpFdWithFlags(p.link, p.program.FD(), int(p.XDPAttachMode))
		if err != nil {
			return fmt.Errorf("attach XDP program %v to interface %v: %w", p.GetIdentificationPair(), p.IfIndex, err)
		}
		p.progLink = &netlinkXDPLink{
			link:    p.link,
			ifIndex: p.IfIndex,
			mode:    int(p.XDPAttachMode),
		}
	}
	return nil
}
