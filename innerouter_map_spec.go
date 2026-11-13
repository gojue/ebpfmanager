package manager

import "fmt"

// InnerOuterMapSpec - An InnerOuterMapSpec defines the map that should be used as the inner map of the provided outer map.
type InnerOuterMapSpec struct {
	// OuterMapName - Name of the BPF_MAP_TYPE_ARRAY_OF_MAPS or BPF_MAP_TYPE_HASH_OF_MAPS map, as defined in its
	// section SEC("maps/[OuterMapName]")
	OuterMapName string

	// InnerMapName - Name of the inner map of the provided outer map, as defined in its section SEC("maps/[InnerMapName]")
	InnerMapName string
}

// editInnerOuterMapSpecs - Update the inner maps of the maps of maps in the collection spec
func (m *Manager) editInnerOuterMapSpec(spec InnerOuterMapSpec) error {
	// find the outer map
	outerSpec, exists, err := m.GetMapSpec(spec.OuterMapName)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("failed to set inner map for maps/%s: couldn't find outer map: %w", spec.OuterMapName, ErrUnknownSection)
	}
	// find the inner map
	innerMap, exists, err := m.GetMapSpec(spec.InnerMapName)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("failed to set inner map for maps/%s: couldn't find inner map %s: %w", spec.OuterMapName, spec.InnerMapName, ErrUnknownSection)
	}

	// set inner map
	outerSpec.InnerMap = innerMap
	return nil
}
