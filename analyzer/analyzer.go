package analyzer

import (
    "go/types"

    "golang.org/x/tools/go/analysis"
    "golang.org/x/tools/go/analysis/passes/inspect"
    "golang.org/x/tools/go/packages"
)

var (
	// Analyzer defines the analyzer for closecheck
	Analyzer = &analysis.Analyzer{
		Name:      "closecheck",
		Doc:       "check that any io.Closer in return a value is closed",
		Run:       run,
		Requires:  []*analysis.Analyzer{inspect.Analyzer},
		FactTypes: []analysis.Fact{new(ioCloserFunc)},
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

// init finds the io.Closer interface
func init() {
	cfg := &packages.Config{
		Mode:  packages.NeedDeps | packages.NeedTypes,
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, "io")
	if err != nil {
		panic(err)
	}

	if len(pkgs) != 1 {
		panic("couldn't load io package")
	}

	closerType = pkgs[0].Types.Scope().Lookup("Closer").Type().Underlying().(*types.Interface)
	if closerType == nil {
		panic("io.Closer not found")
	}
}

// isCloserType checks if a type implements io.Closer
func isCloserType(t types.Type) bool {
    return types.Implements(t, closerType)
}
