package manager

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// MapRoute - A map route defines how multiple maps should be routed between eBPF programs.
//
// The provided eBPF map will be inserted in the provided eBPF array of maps (or hash of maps), at the provided key. The
// inserted eBPF map can be provided by its section or by its *ebpf.Map representation.
type MapRoute struct {
	// RoutingMapName - Name of the BPF_MAP_TYPE_ARRAY_OF_MAPS or BPF_MAP_TYPE_HASH_OF_MAPS map, as defined in its
	// section SEC("maps/[RoutingMapName]")
	RoutingMapName string

	// Key - Key at which the program will be inserted in the routing map
	Key interface{}

	// RoutedName - Section of the map that will be inserted
	RoutedName string

	// Map - Map to insert in the routing map
	Map *ebpf.Map
}

// UpdateMapRoutes - Update one or multiple map of maps structures so that the provided keys point to the provided maps.
func (m *Manager) UpdateMapRoutes(router ...MapRoute) error {
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
		if err := m.updateMapRoute(route); err != nil {
			return err
		}
	}
	return nil
}

// updateMapRoute - Update a map of maps structure so that the provided key points to the provided map
func (m *Manager) updateMapRoute(route MapRoute) error {
	// Select the routing map
	routingMap, found, err := m.getMap(route.RoutingMapName)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("couldn't find routing map %s: %w", route.RoutingMapName, ErrUnknownSection)
	}

	// Get file descriptor of the routed map
	var fd uint32
	if route.Map != nil {
		fd = uint32(route.Map.FD())
	} else {
		var routedMap *ebpf.Map
		routedMap, found, err = m.getMap(route.RoutedName)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("couldn't find routed map %s: %w", route.RoutedName, ErrUnknownSection)
		}
		fd = uint32(routedMap.FD())
	}

	// Insert map
	if err = routingMap.Put(route.Key, fd); err != nil {
		return fmt.Errorf("couldn't update routing map %s: %w", route.RoutingMapName, err)
	}
	return nil
}
