package manager

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// ConstantEditor - A constant editor tries to rewrite the value of a constant in a compiled eBPF program.
//
// Constant edition only works before the eBPF programs are loaded in the kernel, and therefore before the
// Manager is started. If no program sections are provided, the manager will try to edit the constant in all eBPF programs.
type ConstantEditor struct {
	// Name - Name of the constant to rewrite
	Name string

	// Value - Value to write in the eBPF bytecode. When using the asm load method, the Value has to be a `uint64`.
	Value interface{}

	// ValueCallback - Called to get the value to write in the eBPF bytecode
	ValueCallback func(prog *ebpf.ProgramSpec) interface{}

	// FailOnMissing - If FailOMissing is set to true, the constant edition process will return an error if the constant
	// was missing in at least one program
	FailOnMissing bool

	// BTFGlobalConstant - Indicates if the constant is a BTF global constant.
	BTFGlobalConstant bool

	// ProbeIdentificationPairs - Identifies the list of programs to edit. If empty, it will apply to all the programs
	// of the manager. Will return an error if at least one edition failed.
	ProbeIdentificationPairs []ProbeIdentificationPair
}

func (ce *ConstantEditor) GetValue(prog *ebpf.ProgramSpec) interface{} {
	if ce.ValueCallback != nil {
		return ce.ValueCallback(prog)
	}
	return ce.Value
}

// isGlobalConstant preserves automatic BTF constant editing for fork callers.
// Explicit BTFGlobalConstant also reports a missing global when requested.
func (m *Manager) isGlobalConstant(editor ConstantEditor) bool {
	if editor.BTFGlobalConstant {
		return true
	}
	variable := m.collectionSpec.Variables[editor.Name]
	return variable != nil && variable.Constant() && len(editor.ProbeIdentificationPairs) == 0 && editor.ValueCallback == nil
}

// editConstants edits the programs in the CollectionSpec with the provided constant editors. Tries with the BTF global
// variable first, and fall back to the asm method if BTF is not available.
func (m *Manager) editConstants() error {
	// Start with the BTF based solution
	for _, editor := range m.options.ConstantEditors {
		if !m.isGlobalConstant(editor) {
			continue
		}
		vs, ok := m.collectionSpec.Variables[editor.Name]
		if !ok {
			if editor.FailOnMissing {
				return fmt.Errorf("variable %s not found", editor.Name)
			}
			continue
		}
		if !vs.Constant() {
			return fmt.Errorf("variable %s is not a constant", editor.Name)
		}

		if err := vs.Set(editor.GetValue(nil)); err != nil {
			return fmt.Errorf("edit constant %s: %s", editor.Name, err)
		}
	}

	// Fall back to the old school constant edition
	for _, constantEditor := range m.options.ConstantEditors {
		if m.isGlobalConstant(constantEditor) {
			continue
		}

		// Edit the constant of the provided programs
		for _, id := range constantEditor.ProbeIdentificationPairs {
			programs, found, err := m.GetProgramSpec(id)
			if err != nil {
				return err
			}
			if !found || len(programs) == 0 {
				return fmt.Errorf("couldn't find programSpec %v: %w", id, ErrUnknownSectionOrFuncName)
			}
			prog := programs[0]

			// Edit program
			if err := m.editConstant(prog, constantEditor); err != nil {
				return fmt.Errorf("couldn't edit %s in %v: %w", constantEditor.Name, id, err)
			}
		}
	}

	// Apply to all programs if no section was provided
	for section, prog := range m.collectionSpec.Programs {
		var edit *editor
		for _, constantEditor := range m.options.ConstantEditors {
			if m.isGlobalConstant(constantEditor) {
				continue
			}

			if len(constantEditor.ProbeIdentificationPairs) != 0 {
				continue
			}

			if edit == nil {
				edit = newEditor(&prog.Instructions)
			}

			if err := m.editConstantWithEditor(prog, edit, constantEditor); err != nil {
				return fmt.Errorf("couldn't edit %s in %s: %w", constantEditor.Name, section, err)
			}
		}
	}

	return nil
}

// editConstant edits the provided program with the provided constant using the asm method.
func (m *Manager) editConstant(prog *ebpf.ProgramSpec, editor ConstantEditor) error {
	edit := newEditor(&prog.Instructions)
	return m.editConstantWithEditor(prog, edit, editor)
}

func (m *Manager) editConstantWithEditor(prog *ebpf.ProgramSpec, edit *editor, editor ConstantEditor) error {
	data, ok := (editor.GetValue(prog)).(uint64)
	if !ok {
		return fmt.Errorf("with the asm method, the constant value has to be of type uint64")
	}
	if err := edit.RewriteConstant(editor.Name, data); err != nil {
		if editor.FailOnMissing || !isUnreferencedSymbol(err) {
			return err
		}
	}
	return nil
}
