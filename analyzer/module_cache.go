package analyzer

import (
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"runtime"
	"sync"
	"time"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/types/typeutil"
)

type moduleScanKey struct {
	root        string
	trustVendor bool
}

type moduleShutdownIndex struct {
	once             sync.Once
	buildErr         error
	typeHasShutdown  map[string]bool
	methodIsShutdown map[string]bool
}

var (
	moduleShutdownCache   sync.Map // moduleScanKey -> *moduleShutdownIndex
	errPackagesWithErrors = errors.New("packages contain errors")
)

func getModuleShutdownIndex(root string, trustVendor bool) *moduleShutdownIndex {
	key := moduleScanKey{root: root, trustVendor: trustVendor}
	if idx, ok := moduleShutdownCache.Load(key); ok {
		return idx.(*moduleShutdownIndex)
	}
	idx := &moduleShutdownIndex{}
	actual, _ := moduleShutdownCache.LoadOrStore(key, idx)
	return actual.(*moduleShutdownIndex)
}

func (idx *moduleShutdownIndex) ensureBuilt(root string, trustVendor bool) {
	idx.once.Do(func() {
		start := time.Now()
		if debugModuleCache {
			fmt.Printf("[closecheck][module-cache] build start root=%q trustVendor=%t\n", root, trustVendor)
		}
		idx.typeHasShutdown = make(map[string]bool)
		idx.methodIsShutdown = make(map[string]bool)

		loadStart := time.Now()
		cfg := &packages.Config{Mode: packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps}
		if root != "" {
			cfg.Dir = root
		}
		pkgs, err := packages.Load(cfg, "./...")
		if debugModuleCache {
			errStr := "<nil>"
			if err != nil {
				errStr = err.Error()
			}
			fmt.Printf("[closecheck][module-cache] packages.Load duration=%s err=%s count=%d\n", time.Since(loadStart), errStr, len(pkgs))
		}
		if err != nil {
			idx.buildErr = err
			return
		}
		if packages.PrintErrors(pkgs) > 0 {
			idx.buildErr = errPackagesWithErrors
			return
		}

		filtered := make([]*packages.Package, 0, len(pkgs))
		for _, pkg := range pkgs {
			if pkg == nil || pkg.TypesInfo == nil {
				continue
			}
			filtered = append(filtered, pkg)
		}
		if len(filtered) == 0 {
			if debugModuleCache {
				fmt.Printf("[closecheck][module-cache] no packages with type info; total=%s\n", time.Since(start))
			}
			return
		}

		workerCount := runtime.GOMAXPROCS(0)
		if workerCount <= 0 {
			workerCount = 1
		}
		if workerCount > len(filtered) {
			workerCount = len(filtered)
		}

		methodsStart := time.Now()
		methodResults := make(chan map[string]bool, len(filtered))
		runWorkers(workerCount, filtered, func(pkg *packages.Package) {
			methods := collectShutdownMethods(pkg, trustVendor)
			if len(methods) > 0 {
				methodResults <- methods
			}
		})
		close(methodResults)
		for res := range methodResults {
			for key := range res {
				idx.methodIsShutdown[key] = true
			}
		}
		if debugModuleCache {
			fmt.Printf("[closecheck][module-cache] method scan duration=%s methods=%d\n", time.Since(methodsStart), len(idx.methodIsShutdown))
		}

		callsStart := time.Now()
		typeResults := make(chan map[string]bool, len(filtered))
		runWorkers(workerCount, filtered, func(pkg *packages.Package) {
			found := collectShutdownCalls(pkg, trustVendor, idx.methodIsShutdown)
			if len(found) > 0 {
				typeResults <- found
			}
		})
		close(typeResults)
		for res := range typeResults {
			for key := range res {
				idx.typeHasShutdown[key] = true
			}
		}
		if debugModuleCache {
			fmt.Printf("[closecheck][module-cache] call scan duration=%s types=%d\n", time.Since(callsStart), len(idx.typeHasShutdown))
			fmt.Printf("[closecheck][module-cache] build done total=%s err=%v\n", time.Since(start), idx.buildErr)
		}
	})
}

func runWorkers(workerCount int, pkgs []*packages.Package, fn func(*packages.Package)) {
	jobs := make(chan *packages.Package, len(pkgs))
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pkg := range jobs {
				fn(pkg)
			}
		}()
	}
	for _, pkg := range pkgs {
		jobs <- pkg
	}
	close(jobs)
	wg.Wait()
}

func collectShutdownMethods(pkg *packages.Package, trustVendor bool) map[string]bool {
	methods := make(map[string]bool)
	for _, file := range pkg.Syntax {
		filename := pkg.Fset.Position(file.Pos()).Filename
		if trustVendor && isVendorFilename(filename) {
			continue
		}
		if shouldSkipFilename(filename) {
			continue
		}
		if excludeGenerated && isGeneratedFile(file) {
			continue
		}
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil {
				continue
			}
			if !methodDeclLooksLikeShutdown(fd) {
				continue
			}
			if fn, ok := pkg.TypesInfo.Defs[fd.Name].(*types.Func); ok && fn != nil {
				if key := methodKey(fn); key != "" {
					methods[key] = true
				}
			}
		}
	}
	return methods
}

func collectShutdownCalls(pkg *packages.Package, trustVendor bool, shutdownMethods map[string]bool) map[string]bool {
	found := make(map[string]bool)
	for _, file := range pkg.Syntax {
		filename := pkg.Fset.Position(file.Pos()).Filename
		if trustVendor && isVendorFilename(filename) {
			continue
		}
		if shouldSkipFilename(filename) {
			continue
		}
		if excludeGenerated && isGeneratedFile(file) {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fn, _ := typeutil.Callee(pkg.TypesInfo, call).(*types.Func)
			if fn == nil {
				return true
			}
			sig, ok := fn.Type().(*types.Signature)
			if !ok || sig.Recv() == nil {
				return true
			}
			recvKey := normalizeTypeKey(sig.Recv().Type())
			if recvKey == "" {
				return true
			}
			if fn.Name() == "Close" && looksLikeCloserClose(sig) {
				found[recvKey] = true
				return true
			}
			if shutdownMethods[methodKey(fn)] {
				found[recvKey] = true
			}
			return true
		})
	}
	return found
}

func (idx *moduleShutdownIndex) hasShutdownCall(typeKey string) bool {
	return idx.typeHasShutdown[typeKey]
}

func (idx *moduleShutdownIndex) isShutdownMethod(methodKey string) bool {
	return idx.methodIsShutdown[methodKey]
}
