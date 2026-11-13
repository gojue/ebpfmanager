package manager

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// MapSpecEditorFlag - Flag used to specify what a MapSpecEditor should edit.
type MapSpecEditorFlag uint

const (
	EditType       MapSpecEditorFlag = 1 << 1
	EditMaxEntries MapSpecEditorFlag = 1 << 2
	EditFlags      MapSpecEditorFlag = 1 << 3
	EditInnerMap   MapSpecEditorFlag = 1 << 4
	EditKey        MapSpecEditorFlag = 1 << 5
	EditValue      MapSpecEditorFlag = 1 << 6
	EditKeyValue   MapSpecEditorFlag = EditKey | EditValue
)

// MapSpecEditor - A MapSpec editor defines how specific parameters of specific maps should be updated at runtime
//
// For example, this can be used if you need to change the max_entries of a map before it is loaded in the kernel, but
// you don't know what this value should be initially.
type MapSpecEditor struct {
	// Type - Type of the map.
	Type ebpf.MapType
	// MaxEntries - Max Entries of the map.
	MaxEntries uint32
	// Flags - Flags provided to the kernel during the loading process.
	Flags uint32
	// KeySize - Defines the key size of the map
	KeySize uint32
	// Key - Defines the BTF type of the keys of the map
	Key btf.Type
	// ValueSize - Defines the value size of the map
	ValueSize uint32
	// Value - Defines the BTF type of the values of the map
	Value btf.Type
	// EditorFlag - Use this flag to specify what fields should be updated. See MapSpecEditorFlag.
	EditorFlag MapSpecEditorFlag
	InnerMap   *ebpf.MapSpec
}

// editMapSpecs - Update the MapSpec with the provided MapSpec editors.
func (m *Manager) editMapSpecs() error {
	for name, mapEditor := range m.options.MapSpecEditors {
		// select the map spec
		spec, exists, err := m.GetMapSpec(name)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("failed to edit maps/%s: couldn't find map: %w", name, ErrUnknownSection)
		}
		if mapEditor.EditorFlag == 0 {
			return fmt.Errorf("failed to edit maps/%s: %w", name, ErrMissingEditorFlags)
		}
		if EditType&mapEditor.EditorFlag == EditType {
			spec.Type = mapEditor.Type
		}
		if EditMaxEntries&mapEditor.EditorFlag == EditMaxEntries {
			spec.MaxEntries = mapEditor.MaxEntries
		}
		if EditFlags&mapEditor.EditorFlag == EditFlags {
			spec.Flags = mapEditor.Flags
		}
		if EditInnerMap&mapEditor.EditorFlag == EditInnerMap {
			spec.InnerMap = mapEditor.InnerMap
		}
		if EditKey&mapEditor.EditorFlag == EditKey {
			spec.Key = mapEditor.Key
			spec.KeySize = mapEditor.KeySize
		}
		if EditValue&mapEditor.EditorFlag == EditValue {
			spec.Value = mapEditor.Value
			spec.ValueSize = mapEditor.ValueSize
		}
	}
	return nil
}
