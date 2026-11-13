package manager

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/asm"
)

// editor modifies eBPF instructions.
type editor struct {
	instructions     *asm.Instructions
	ReferenceOffsets map[string][]int
}

// newEditor creates a new editor.
//
// The editor retains a reference to insns and modifies its
// contents.
func newEditor(insns *asm.Instructions) *editor {
	refs := insns.ReferenceOffsets()
	return &editor{insns, refs}
}

// RewriteConstant rewrites all loads of a symbol to a constant value.
//
// This is a way to parameterize clang-compiled eBPF byte code at load
// time.
//
// The following macro should be used to access the constant:
//
//	#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))
//
//	int xdp() {
//	    bool my_constant;
//	    LOAD_CONSTANT("SYMBOL_NAME", my_constant);
//
//	    if (my_constant) ...
//
// Caveats:
//
//   - The symbol name you pick must be unique
//
//   - Failing to rewrite a symbol will not result in an error,
//     0 will be loaded instead (subject to change)
//
// Use isUnreferencedSymbol if you want to rewrite potentially
// unused symbols.
func (ed *editor) RewriteConstant(symbol string, value uint64) error {
	indices := ed.ReferenceOffsets[symbol]
	if len(indices) == 0 {
		return &unreferencedSymbolError{symbol}
	}

	ldDWImm := asm.LoadImmOp(asm.DWord)
	for _, index := range indices {
		load := &(*ed.instructions)[index]
		if load.OpCode != ldDWImm {
			return fmt.Errorf("symbol %v: load: found %v instead of %v", symbol, load.OpCode, ldDWImm)
		}

		load.Constant = int64(value)
	}
	return nil
}

type unreferencedSymbolError struct {
	symbol string
}

func (use *unreferencedSymbolError) Error() string {
	return fmt.Sprintf("unreferenced symbol %s", use.symbol)
}

// isUnreferencedSymbol returns true if err was caused by
// an unreferenced symbol.
func isUnreferencedSymbol(err error) bool {
	var ue *unreferencedSymbolError
	return errors.As(err, &ue)
}
