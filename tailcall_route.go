package manager

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// TailCallRoute - A tail call route defines how tail calls should be routed between eBPF programs.
//
// The provided eBPF program will be inserted in the provided eBPF program array, at the provided key. The eBPF program
// can be provided by its function name or by its *ebpf.Program representation.
type TailCallRoute struct {
	// ProgArrayName - Name of the BPF_MAP_TYPE_PROG_ARRAY map as defined in its section SEC("maps/[ProgArray]")
	ProgArrayName string

	// Key - Key at which the program will be inserted in the ProgArray map
	Key uint32

	// ProbeIdentificationPair - Selector of the program to insert in the ProgArray map
	ProbeIdentificationPair ProbeIdentificationPair

	// Program - Program to insert in the ProgArray map
	Program *ebpf.Program
}

// UpdateTailCallRoutes - Update one or multiple program arrays so that the provided keys point to the provided programs.
func (m *Manager) UpdateTailCallRoutes(router ...TailCallRoute) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	switch m.state {
	case reset, elfLoaded:
		return ErrManagerNotInitialized
	case initialized, stopping, paused, running:
	}
	if m.collection == nil {
		return ErrManagerNotInitialized
	}

	for _, route := range router {
		if err := m.updateTailCallRoute(route); err != nil {
			return err
		}
	}
	return nil
}

// updateTailCallRoute - Update a program array so that the provided key point to the provided program.
func (m *Manager) updateTailCallRoute(route TailCallRoute) error {
	// Select the routing map
	routingMap, found, err := m.getMap(route.ProgArrayName)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("couldn't find routing map %s: %w", route.ProgArrayName, ErrUnknownSection)
	}

	// Get file descriptor of the routed program
	var fd uint32
	if route.Program != nil {
		fd = uint32(route.Program.FD())
	} else {
		progs, found, err := m.getProgram(route.ProbeIdentificationPair)
		if err != nil {
			return err
		}
		if !found || len(progs) == 0 {
			return fmt.Errorf("couldn't find program %v: %w", route.ProbeIdentificationPair, ErrUnknownSectionOrFuncName)
		}
		if progs[0] == nil {
			return fmt.Errorf("the program that you are trying to route to is empty")
		}
		fd = uint32(progs[0].FD())
	}

	// Insert tail call
	if err = routingMap.Put(route.Key, fd); err != nil {
		return fmt.Errorf("couldn't update routing map %s: %w", route.ProgArrayName, err)
	}
	return nil
}
