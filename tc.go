package manager

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"github.com/gojue/ebpfmanager/internal"
)

type TrafficType uint16

func (tt TrafficType) String() string {
	switch tt {
	case Ingress:
		return "ingress"
	case Egress:
		return "egress"
	default:
		return fmt.Sprintf("TrafficType(%d)", tt)
	}
}

const (
	// DefaultTCFilterPriority is the default TC filter priority if none were given
	DefaultTCFilterPriority = 50

	Ingress     = TrafficType(uint16(netlink.HANDLE_MIN_INGRESS & 0x0000FFFF))
	Egress      = TrafficType(uint16(netlink.HANDLE_MIN_EGRESS & 0x0000FFFF))
	clsactQdisc = uint16(netlink.HANDLE_INGRESS >> 16)

	// maxBPFClassifierNameLen - maximum length for a TC
	// CLS_BPF_NAME_LEN (linux/net/sched/cls_bpf.c)
	maxBPFClassifierNameLen = 256
)

func generateTCFilterName(UID, sectionName string, attachPID int) (string, error) {
	attachPIDstr := strconv.Itoa(attachPID)
	maxSectionNameLen := maxBPFClassifierNameLen - 3 /* _ */ - len(UID) - len(attachPIDstr)
	if maxSectionNameLen < 0 {
		dbgFullFilterString := safeEventRegexp.ReplaceAllString(fmt.Sprintf("%s_%s_%s", sectionName, UID, attachPIDstr), "_")
		return "", fmt.Errorf("filter name is too long (kernel limit is %d (CLS_BPF_NAME_LEN)): sectionName %d, UID %d, attachPIDstr %d ; full event string : '%s'", maxEventNameLen, len(sectionName), len(UID), len(attachPIDstr), dbgFullFilterString)
	}
	filterName := safeEventRegexp.ReplaceAllString(fmt.Sprintf("%.*s_%s_%s", maxSectionNameLen, sectionName, UID, attachPIDstr), "_")

	if len(filterName) > maxBPFClassifierNameLen {
		return "", fmt.Errorf("filter name too long (kernel limit CLS_BPF_NAME_LEN is %d): '%s'", maxBPFClassifierNameLen, filterName)
	}
	return filterName, nil
}

// getNetlinkSocket returns a netlink socket in the probe network namespace
func (p *Probe) getNetlinkSocket() (*NetlinkSocket, error) {
	return p.netlinkSocketCache.getNetlinkSocket(p.IfIndexNetns, p.IfIndexNetnsID)
}

func (p *Probe) buildTCClsActQdisc() netlink.Qdisc {
	if p.tcClsActQdisc == nil {
		p.tcClsActQdisc = &netlink.GenericQdisc{
			QdiscType: "clsact",
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: p.IfIndex,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_INGRESS,
			},
		}
	}
	return p.tcClsActQdisc
}

func (p *Probe) getTCFilterParentHandle() uint32 {
	return netlink.MakeHandle(clsactQdisc, uint16(p.NetworkDirection))
}

func (p *Probe) buildTCFilter() (netlink.BpfFilter, error) {
	if p.tcFilter.LinkIndex == 0 {
		var filterName string
		filterName, err := generateTCFilterName(p.UID, p.programSpec.SectionName, p.attachPID)
		if err != nil {
			return p.tcFilter, fmt.Errorf("couldn't create TC filter for %v: %w", p.GetIdentificationPair(), err)
		}

		p.tcFilter = netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: p.IfIndex,
				Parent:    p.getTCFilterParentHandle(),
				Handle:    p.TCFilterHandle,
				Priority:  p.TCFilterPrio,
				Protocol:  p.TCFilterProtocol,
			},
			Fd:           p.program.FD(),
			Name:         filterName,
			DirectAction: true,
		}
	}
	return p.tcFilter, nil
}

// attachTCCLS - Attaches the probe to its TC classifier hook point
func (p *Probe) attachTCCLS() error {
	var err error
	// Resolve Probe's interface
	if _, err = p.resolveLink(); err != nil {
		return err
	}

	// Recover the netlink socket of the interface from the manager
	ntl, err := p.getNetlinkSocket()
	if err != nil {
		return err
	}

	// Create a Qdisc for the provided interface
	err = ntl.Sock.QdiscAdd(p.buildTCClsActQdisc())
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			// cleanup previous TC filters if necessary
			if err = p.cleanupTCFilters(ntl); err != nil {
				return fmt.Errorf("couldn't clean up existing \"clsact\" qdisc filters for %s[%d]: %w", p.IfName, p.IfIndex, err)
			}
		} else {
			return fmt.Errorf("couldn't add a \"clsact\" qdisc to interface %s[%d]: %w", p.IfName, p.IfIndex, err)
		}
	}

	// Create qdisc filter
	_, err = p.buildTCFilter()
	if err != nil {
		return err
	}
	if err = ntl.Sock.FilterAdd(&p.tcFilter); err != nil {
		return fmt.Errorf("couldn't add a %v filter to interface %s[%d]: %w", p.NetworkDirection, p.IfName, p.IfIndex, err)
	}

	// retrieve filter handle
	resp, err := ntl.Sock.FilterList(p.link, p.tcFilter.Parent)
	if err != nil {
		return fmt.Errorf("couldn't list filters of interface %s[%d]: %w", p.IfName, p.IfIndex, err)
	}

	var found bool
	bpfType := (&netlink.BpfFilter{}).Type()
	for _, elem := range resp {
		if elem.Type() != bpfType {
			continue
		}

		bpfFilter, ok := elem.(*netlink.BpfFilter)
		if !ok {
			continue
		}

		// we can't test the equality of the program tag, there is a bug in the netlink library.
		// See https://github.com/vishvananda/netlink/issues/722
		if bpfFilter.Id == p.systemWideID && strings.Contains(p.programTag, bpfFilter.Tag) { //
			found = true
			p.tcFilter.Handle = bpfFilter.Handle
		}
	}
	if !found {
		return fmt.Errorf("couldn't create TC filter for %v: filter not found", p.GetIdentificationPair())
	}

	ntl.IncreaseFilterCount(p.IfIndex)

	return nil
}

func (p *Probe) IsTCFilterActive() bool {
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	if p.state < paused || !p.Enabled {
		return false
	}
	if p.programSpec.Type != ebpf.SchedCLS {
		return false
	}

	// Recover the netlink socket of the interface from the manager
	ntl, err := p.getNetlinkSocket()
	if err != nil {
		return false
	}

	resp, err := ntl.Sock.FilterList(p.link, p.tcFilter.Parent)
	if err != nil {
		return false
	}

	bpfType := (&netlink.BpfFilter{}).Type()
	for _, elem := range resp {
		if elem.Type() != bpfType {
			continue
		}

		bpfFilter, ok := elem.(*netlink.BpfFilter)
		if !ok {
			continue
		}

		// we can't test the equality of the program tag, there is a bug in the netlink library.
		// See https://github.com/vishvananda/netlink/issues/722
		if bpfFilter.Id == p.systemWideID && strings.Contains(p.programTag, bpfFilter.Tag) {
			return true
		}
	}

	// This TC filter is no longer active, the interface has been deleted or the filter was replaced by a third party.
	// Regardless of the reason, we do not hold the current Handle on this filter, remove it, so we make sure we won't
	// delete something that we do not own.
	p.tcFilter.Handle = 0
	return false
}

// detachTCCLS - Detaches the probe from its TC classifier hook point
func (p *Probe) detachTCCLS() error {
	// Recover the netlink socket of the interface from the manager
	ntl, err := p.getNetlinkSocket()
	if err != nil {
		return err
	}

	if p.tcFilter.Handle > 0 {
		// delete the current filter
		if err = ntl.Sock.FilterDel(&p.tcFilter); err != nil {
			// the device or the filter might already be gone, ignore the error if that's the case
			if !errors.Is(err, syscall.ENODEV) && !errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("couldn't remove TC classifier %v: %w", p.GetIdentificationPair(), err)
			}
		}
	}

	remainingFilterUsers := ntl.DecreaseFilterCount(p.IfIndex)
	if remainingFilterUsers >= 1 {
		// at list one of our classifiers is still using it
		return nil
	}

	if p.TCCleanupQDisc {
		// check if someone else is using the clsact qdisc on ingress
		resp, err := ntl.Sock.FilterList(p.link, netlink.HANDLE_MIN_INGRESS)
		if err != nil || err == nil && len(resp) > 0 {
			// someone is still using it
			return nil
		}

		// check on egress
		resp, err = ntl.Sock.FilterList(p.link, netlink.HANDLE_MIN_EGRESS)
		if err != nil || err == nil && len(resp) > 0 {
			// someone is still using it
			return nil
		}

		// delete qdisc
		if err = ntl.Sock.QdiscDel(p.buildTCClsActQdisc()); err != nil {
			// the device might already be gone, ignore the error if that's the case
			if !errors.Is(err, syscall.ENODEV) {
				return fmt.Errorf("couldn't remove clsact qdisc: %w", err)
			}
		}
	}
	return nil
}

// cleanupTCFilters - Cleans up existing TC Filters by removing entries of known UIDs, that they're not used anymore.
//
// Previous instances of this manager might have been killed unexpectedly. When this happens, TC filters are not cleaned
// up properly and can grow indefinitely. To prevent this, start by cleaning up the TC filters of previous managers that
// are not running anymore.
func (p *Probe) cleanupTCFilters(ntl *NetlinkSocket) error {
	// build the pattern to look for in the TC filters name
	pattern, err := regexp.Compile(fmt.Sprintf(`.*(%s)_([0-9]*)`, p.UID))
	if err != nil {
		return fmt.Errorf("filter name pattern generation failed: %w", err)
	}

	resp, err := ntl.Sock.FilterList(p.link, p.getTCFilterParentHandle())
	if err != nil {
		return err
	}

	var errs []error
	bpfType := (&netlink.BpfFilter{}).Type()
	for _, elem := range resp {
		if elem.Type() != bpfType {
			continue
		}

		bpfFilter, ok := elem.(*netlink.BpfFilter)
		if !ok {
			continue
		}

		match := pattern.FindStringSubmatch(bpfFilter.Name)
		if len(match) < 3 {
			continue
		}

		// check if the manager that loaded this TC filter is still up
		var pid int
		pid, err = strconv.Atoi(match[2])
		if err != nil {
			continue
		}

		// this short sleep is used to avoid a CPU spike (5s ~ 60k * 80 microseconds)
		time.Sleep(80 * time.Microsecond)

		if internal.ProcessExists(pid) {
			continue
		}

		// remove this filter
		errs = append(errs, ntl.Sock.FilterDel(elem))
	}
	return errors.Join(errs...)
}
