package analyzer

import (
	"go/types"
	"regexp"
	"strings"
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

	// closerType holds the io.Closer interface type loaded during init
	closerType *types.Interface

	// Performance and behavior controls
	enableCrossPkgScan     bool     // Enable heavy project-wide scanning for shutdown calls (default: true)
	enablePerMethodPkgLoad bool     // Enable per-method package loading to inspect function bodies (default: true)
	maxFixedPointPasses    int      // Maximum passes when discovering closer functions per package (default: 5)
	parallelWorkers        int      // Number of worker goroutines for intra-package analysis (0=auto)
	closerCache            sync.Map // Cache for type implements io.Closer checks: types.Type -> bool

	// Security and filtering controls
	trustVendor bool // Treat vendor packages as trusted, skip deep scans (default: true)

	// Debug and development flags
	debugModuleCache bool // Log module cache timing information (default: false)

	// Analysis scope controls
	excludeGenerated bool // Skip files marked with '// Code generated' comments (default: true)
	includeTests     bool // Analyze _test.go files and test-only packages (default: false)
	skipStdlib       bool // Skip analysis for standard library packages (default: true)

	// Pattern-based filtering
	excludePkgPatterns  regexList // Regex patterns for package import paths to skip
	excludePathPatterns regexList // Regex patterns for file paths to skip
)

type regexList struct {
	patterns []string
	regexes  []*regexp.Regexp
}

func (r *regexList) String() string {
	return strings.Join(r.patterns, ",")
}

func (r *regexList) Set(value string) error {
	if value == "" {
		return nil
	}
	re, err := regexp.Compile(value)
	if err != nil {
		return err
	}
	r.patterns = append(r.patterns, value)
	r.regexes = append(r.regexes, re)
	return nil
}

func (r *regexList) matches(s string) bool {
	if len(r.regexes) == 0 {
		return false
	}
	for _, re := range r.regexes {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func run(pass *analysis.Pass) (interface{}, error) {
	if shouldSkipPackage(pass) {
		return nil, nil
	}

	skipFiles, hasAny := determineFileFilters(pass)
	if !hasAny {
		return nil, nil
	}
	skipPosFn := makeSkipPosFunc(pass.Fset, skipFiles)

	fVisitor := &FunctionVisitor{pass: pass, skipPos: skipPosFn}
	funcs := fVisitor.findFunctionsThatReceiveAnIOCloser()

	aVisitor := &AssignVisitor{pass: pass, skipPos: skipPosFn, closerFuncs: funcs, localGlobalVars: fVisitor.localGlobalVars}
	aVisitor.moduleRoot = aVisitor.findModuleRoot()
	aVisitor.checkFunctionsThatAssignCloser()

	return nil, nil
}

func init() {
	Analyzer.Flags.BoolVar(&enableFunctionDebugger, "enable-function-debugger", false, "enable function debugger")
	Analyzer.Flags.BoolVar(&showCloserFunctionsFound, "show-closer-functions-found", false, "show closer functions found")
	// performance/behavior flags (defaults kept conservative for speed)
	// Deep checks default ON for project code (vendor is skipped). Disable via '=false'.
	Analyzer.Flags.BoolVar(&enableCrossPkgScan, "enable-cross-package-scan", true, "enable cross-package scan for project code; set to '=false' to disable")
	Analyzer.Flags.BoolVar(&enablePerMethodPkgLoad, "enable-per-method-pkg-load", true, "enable per-method package load for project code; set to '=false' to disable")
	Analyzer.Flags.BoolVar(&trustVendor, "trust-vendor", true, "trust vendor packages: skip deep scans under vendor; set to '=false' to include vendor in deep scans")
	Analyzer.Flags.IntVar(&maxFixedPointPasses, "max-passes", 5, "max fixed-point passes when discovering closer functions per package")
	Analyzer.Flags.IntVar(&parallelWorkers, "parallel", 0, "worker goroutines for intra-package analysis (0=auto)")
	Analyzer.Flags.BoolVar(&debugModuleCache, "debug-module-cache", false, "log module cache timing information")
	Analyzer.Flags.BoolVar(&excludeGenerated, "exclude-generated", true, "skip files marked with '// Code generated' comments")
	Analyzer.Flags.BoolVar(&includeTests, "include-tests", false, "analyze _test.go files and test-only packages")
	Analyzer.Flags.BoolVar(&skipStdlib, "skip-stdlib", true, "skip analysis for standard library packages")
	Analyzer.Flags.Var(&excludePkgPatterns, "exclude-pkg", "regexp of package import paths to skip; repeatable")
	Analyzer.Flags.Var(&excludePathPatterns, "exclude-path", "regexp of file paths to skip; repeatable")
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
