package analyzer

import (
    "go/types"
    "sync"

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
		FactTypes: []analysis.Fact{new(ioCloserFunc), new(containerMethodFact)},
	}

	closerType          *types.Interface
	printStatementsMode bool
    // performance/behavior controls
    enableCrossPkgScan       bool // heavy project-wide scanning for shutdown calls
    enablePerMethodPkgLoad   bool // per-method package load to inspect bodies
    maxFixedPointPasses      int  // limit function closer fixed-point passes (default: 5)
    parallelWorkers          int  // goroutines for intra-package analysis (0=auto)
    closerCache              sync.Map // types.Type (stripped) -> bool
    trustVendor              bool // treat vendor as trusted (skip deep scans)
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
    // performance/behavior flags (defaults kept conservative for speed)
    // Deep checks default ON for project code (vendor is skipped). Disable via '=false'.
    Analyzer.Flags.BoolVar(&enableCrossPkgScan, "enable-cross-package-scan", true, "enable cross-package scan for project code; set to '=false' to disable")
    Analyzer.Flags.BoolVar(&enablePerMethodPkgLoad, "enable-per-method-pkg-load", true, "enable per-method package load for project code; set to '=false' to disable")
    Analyzer.Flags.BoolVar(&trustVendor, "trust-vendor", true, "trust vendor packages: skip deep scans under vendor; set to '=false' to include vendor in deep scans")
    Analyzer.Flags.IntVar(&maxFixedPointPasses, "max-passes", 5, "max fixed-point passes when discovering closer functions per package")
    Analyzer.Flags.IntVar(&parallelWorkers, "parallel", 0, "worker goroutines for intra-package analysis (0=auto)")
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
    if t == nil {
        return false
    }
    // Fast-path and cache: implementations are stable within a run
    if v, ok := closerCache.Load(t); ok {
        return v.(bool)
    }
    res := types.Implements(t, closerType)
    closerCache.Store(t, res)
    return res
}
