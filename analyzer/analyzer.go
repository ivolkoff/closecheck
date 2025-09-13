package analyzer

import (
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

var (
	// Analyzer defines the analyzer for closecheck
	Analyzer = &analysis.Analyzer{
		Name:      "closecheck",
		Doc:       "check that any io.Closer in return a value is closed",
		Run:       run,
		Requires:  []*analysis.Analyzer{inspect.Analyzer},
		FactTypes: []analysis.Fact{new(ioCloserFunc), new(containerMethodFact)},
	}

	closerType          *types.Interface
	printStatementsMode bool
)

func run(pass *analysis.Pass) (interface{}, error) {
	fVisitor := &FunctionVisitor{pass: pass}
	funcs := fVisitor.findFunctionsThatReceiveAnIOCloser()

	aVisitor := &AssignVisitor{pass: pass, closerFuncs: funcs, localGlobalVars: fVisitor.localGlobalVars}
	aVisitor.checkFunctionsThatAssignCloser()

	return nil, nil
}

func init() {
	Analyzer.Flags.BoolVar(&printStatementsMode, "print-statements", false, "print program trace")
	Analyzer.Flags.BoolVar(&enableFunctionDebugger, "enable-function-debugger", false, "enable function debugger")
	Analyzer.Flags.BoolVar(&showCloserFunctionsFound, "show-closer-functions-found", false, "show closer functions found")
}

// init constructs the io.Closer interface type programmatically to avoid loading stdlib packages
func init() {
	// error type from universe
	errT := types.Universe.Lookup("error").Type()
	// func() error
	params := types.NewTuple()
	results := types.NewTuple(types.NewVar(token.NoPos, nil, "", errT))
	sig := types.NewSignatureType(nil, nil, nil, params, results, false)
	// method Close
	closeFn := types.NewFunc(token.NoPos, nil, "Close", sig)
	// interface { Close() error }
	closerType = types.NewInterfaceType([]*types.Func{closeFn}, nil)
	closerType.Complete()
}

// isCloserType checks if a type implements io.Closer
func isCloserType(t types.Type) bool {
	return types.Implements(t, closerType)
}
