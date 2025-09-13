package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"runtime"
	"sync"
	"unicode"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/types/typeutil"
)

var (
	enableFunctionDebugger   = false
	showCloserFunctionsFound = false
)

// FunctionVisitor is in charge of preprocessing packages to find functions that close io.Closers
type FunctionVisitor struct {
	pass            *analysis.Pass
	skipPos         func(token.Pos) bool
	receivers       map[*types.Func]*ioCloserFunc
	localGlobalVars map[token.Pos]bool
}

type ioCloserFunc struct {
	obj                *types.Func
	fdecl              *ast.FuncDecl
	argsThatAreClosers []bool
	argNames           []*ast.Ident
	isCloser           bool
}

// containerMethodFact records inter-procedural container lifecycle behavior for methods
// - registersShutdown: method registers shutdown handlers that eventually call Close()
// - isShutdown: method executes registered handlers (container cleanup)
type containerMethodFact struct {
	registersShutdown bool
	isShutdown        bool
}

func (c *containerMethodFact) AFact() {}

func (c *containerMethodFact) String() string {
	return fmt.Sprintf("registersShutdown=%t,isShutdown=%t", c.registersShutdown, c.isShutdown)
}

func (c *ioCloserFunc) AFact() {}

// String is the string representation of the fact
func (c *ioCloserFunc) String() string {
	if c.isCloser {
		return "is closer"
	}

	return "is not closer"
}

func (pp *FunctionVisitor) debug(n ast.Node, template string, args ...interface{}) {
	if !enableFunctionDebugger {
		return
	}

	fmt.Printf(template+"\n", args...)

	_ = ast.Print(pp.pass.Fset, n)
}

func (pp *FunctionVisitor) shouldSkipNode(n ast.Node) bool {
	if pp == nil || pp.skipPos == nil || n == nil {
		return false
	}
	return pp.skipPos(n.Pos())
}

// this function finds functions that receive and closes an io.Closer
func (pp *FunctionVisitor) findFunctionsThatReceiveAnIOCloser() map[*types.Func]*ioCloserFunc {
	pp.receivers = map[*types.Func]*ioCloserFunc{}
	pp.localGlobalVars = map[token.Pos]bool{}

	ins := pp.pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	// Collect package-level variables that are (or contain) closers
	ins.WithStack([]ast.Node{(*ast.ValueSpec)(nil)}, func(n ast.Node, push bool, stack []ast.Node) bool {
		if !push {
			return true
		}
		if pp.shouldSkipNode(n) {
			return true
		}
		vs := n.(*ast.ValueSpec)
		// Identify top-level (package) var: parent is GenDecl under File, not under DeclStmt
		var gen *ast.GenDecl
		for i := len(stack) - 2; i >= 0; i-- { // skip current ValueSpec at end
			switch p := stack[i].(type) {
			case *ast.DeclStmt:
				return true // local var inside function — skip
			case *ast.GenDecl:
				gen = p
				// continue to see if there is a DeclStmt above (which would make it local)
			}
		}
		if gen == nil || gen.Tok != token.VAR {
			return true
		}
		for _, name := range vs.Names {
			obj := pp.pass.TypesInfo.ObjectOf(name)
			if obj == nil {
				continue
			}
			if isCloserReceiver(obj.Type().Underlying()) {
				pp.localGlobalVars[name.NamePos] = true
			}
		}
		return true
	})

	// Process function declarations
	ins.Preorder([]ast.Node{(*ast.FuncDecl)(nil)}, func(n ast.Node) {
		cDecl := n.(*ast.FuncDecl)
		if pp.shouldSkipNode(cDecl) {
			return
		}
		if cDecl.Body == nil {
			return
		}

		fn, ok := pp.pass.TypesInfo.Defs[cDecl.Name].(*types.Func)
		if !ok {
			return
		}

		// Skip constructor-like functions that store closers rather than close them
		if pp.isConstructorFunction(cDecl, fn) {
			return
		}

		sig := fn.Type().(*types.Signature)
		params := sig.Params()

		receivesCloser := false
		argsThatAreClosers := make([]bool, params.Len())
		argNames := []*ast.Ident{}

		// collect only names of parameters that are closers
		paramIdx := 0
		if cDecl.Type.Params != nil {
			for _, plist := range cDecl.Type.Params.List {
				count := len(plist.Names)
				// match names to signature positions
				for i := 0; i < count; i++ {
					// placeholder; actual closer marking is done using types from signature below
					argNames = append(argNames, plist.Names[i])
					paramIdx++
				}
			}
		}

		for i := 0; i < params.Len(); i++ {
			param := params.At(i)
			if isCloserReceiver(param.Type()) {
				receivesCloser = true
				argsThatAreClosers[i] = true
			}
		}

		if receivesCloser {
			// filter argNames to only those positions that are closers
			filteredNames := make([]*ast.Ident, 0, len(argNames))
			namePos := 0
			if cDecl.Type.Params != nil {
				for _, plist := range cDecl.Type.Params.List {
					for range plist.Names {
						if namePos < len(argsThatAreClosers) && argsThatAreClosers[namePos] {
							filteredNames = append(filteredNames, argNames[namePos])
						}
						namePos++
					}
				}
			}
			pp.receivers[fn] = &ioCloserFunc{
				obj:                fn,
				fdecl:              cDecl,
				argsThatAreClosers: argsThatAreClosers,
				argNames:           filteredNames,
			}
		}

		// Independently of receiving closers, record container lifecycle facts for methods with receiver
		if cDecl.Recv != nil {
			reg := pp.methodRegistersShutdownHandlers(cDecl)
			shut := pp.methodIsShutdownMethod(cDecl)
			if reg || shut {
				if showCloserFunctionsFound {
					fmt.Println("found container method:", fn.FullName(), "registers:", reg, "shutdown:", shut)
				}
				pp.pass.ExportObjectFact(fn, &containerMethodFact{registersShutdown: reg, isShutdown: shut})
				if shut {
					// Register globally for cross-package detection
					if recv := fn.Type().(*types.Signature).Recv(); recv != nil {
						if key := pp.typeKey(recv.Type()); key != "" {
							registerShutdownMethod(key, cDecl.Name.Name)
						}
					}
				}
			}
		}
	})

	// Run multiple passes to handle transitive closure relationships
	passes := maxFixedPointPasses
	if passes <= 0 {
		passes = 5
	}
	// Prepare a stable slice of receivers to iterate (for deterministic order)
	rcvList := make([]*ioCloserFunc, 0, len(pp.receivers))
	for _, r := range pp.receivers {
		rcvList = append(rcvList, r)
	}

	for passN := 0; passN < passes; passN++ {
		changesMade := false

		// Determine worker count
		workers := parallelWorkers
		if workers <= 0 {
			workers = runtime.GOMAXPROCS(0)
			if workers <= 0 {
				workers = 1
			}
		}
		if workers > len(rcvList) {
			workers = len(rcvList)
		}

		type job struct{ idx int }
		type res struct {
			idx      int
			isCloser bool
		}
		jobs := make(chan job, len(rcvList))
		results := make(chan res, len(rcvList))

		var wg sync.WaitGroup
		workerFn := func() {
			defer wg.Done()
			for j := range jobs {
				rcv := rcvList[j.idx]
				if rcv.isCloser {
					// already known, skip expensive traverse
					results <- res{idx: j.idx, isCloser: true}
					continue
				}
				found := false
				for _, id := range rcv.argNames {
					if pp.traverse(id, rcv.fdecl.Body.List) {
						found = true
						break
					}
				}
				results <- res{idx: j.idx, isCloser: found}
			}
		}

		if workers <= 1 {
			// Run serially
			for i := range rcvList {
				j := job{idx: i}
				rcv := rcvList[j.idx]
				if rcv.isCloser {
					continue
				}
				found := false
				for _, id := range rcv.argNames {
					if pp.traverse(id, rcv.fdecl.Body.List) {
						found = true
						break
					}
				}
				if found {
					rcv.isCloser = true
					changesMade = true
				}
			}
		} else {
			// Run in parallel
			wg.Add(workers)
			for i := 0; i < workers; i++ {
				go workerFn()
			}
			for i := range rcvList {
				if !rcvList[i].isCloser {
					jobs <- job{idx: i}
				}
			}
			close(jobs)
			wg.Wait()
			close(results)
			for r := range results {
				if r.isCloser && !rcvList[r.idx].isCloser {
					rcvList[r.idx].isCloser = true
					changesMade = true
				}
			}
		}

		if !changesMade {
			break // No more changes, we're done
		}
	}

	for _, rcv := range pp.receivers {
		if showCloserFunctionsFound {
			fmt.Println("found closer function:", rcv.obj.FullName(), "closer:", rcv.isCloser, "pos:", rcv.obj.Pos())
		}

		// Debug Redis function detection
		// if strings.Contains(rcv.obj.FullName(), "Get") {
		//	fmt.Printf("DEBUG: Redis function %s isCloser=%t\n", rcv.obj.FullName(), rcv.isCloser)
		// }

		pp.pass.ExportObjectFact(rcv.obj, rcv)
	}

	return pp.receivers
}

// typeKey normalizes a receiver type to pkgpath.TypeName (ignoring pointers and type params)
func (pp *FunctionVisitor) typeKey(t types.Type) string {
	return normalizeTypeKey(t)
}

// looksLikeCloserClose verifies that a method signature EXACTLY matches io.Closer.Close(): func() error
func looksLikeCloserClose(sig *types.Signature) bool {
	// Must have no parameters
	if sig.Params().Len() != 0 {
		return false
	}

	// Must return exactly one result
	results := sig.Results()
	if results.Len() != 1 {
		return false
	}

	// The result must be exactly "error"
	resultType := results.At(0).Type()
	if resultType.String() == "error" {
		return true
	}
	return false
}

func isCloserReceiver(t types.Type) bool {
	// Debug Context detection
	// if strings.Contains(t.String(), "Context") {
	//	fmt.Printf("DEBUG: Analyzing type %s\n", t.String())
	// }

	if isCloserType(t) {
		// if strings.Contains(t.String(), "Context") {
		//	fmt.Printf("DEBUG: Type %s detected as isCloserType\n", t.String())
		// }
		return true
	}

	// Do not use name/signature heuristics; only io.Closer interface or structs with io.Closer fields

	// Check for named types (which could be generic)
	if named, ok := t.(*types.Named); ok {
		result := isCloserReceiverStruct(named.Underlying())
		// if result && strings.Contains(t.String(), "Context") {
		//	fmt.Printf("DEBUG: Type %s detected as closerReceiverStruct via named\n", t.String())
		// }
		return result
	}

	// special case: a struct containing a io.Closer fields that implements io.Closer, like http.Response.Body
	result := isCloserReceiverStruct(t)
	// if result && strings.Contains(t.String(), "Context") {
	//	fmt.Printf("DEBUG: Type %s detected as closerReceiverStruct direct\n", t.String())
	// }
	return result
}

func isCloserReceiverStruct(t types.Type) bool {
	// Ignore net/http.Request: its Body is managed by transport; passing *http.Request
	// should not mark the function as a closer receiver.
	if isHTTPRequestType(t) {
		return false
	}
	ptr, ok := t.(*types.Pointer)
	if !ok {
		// Also check non-pointer structs
		if str, ok := t.(*types.Struct); ok {
			return hasCloserFields(str)
		}
		return false
	}

	str, ok := ptr.Elem().Underlying().(*types.Struct)
	if !ok {
		return false
	}

	return hasCloserFields(str)
}

func hasCloserFields(str *types.Struct) bool {
	for i := 0; i < str.NumFields(); i++ {
		v := str.Field(i)
		fieldName := v.Name()

		// Check exported fields
		if isCloserType(v.Type()) && unicode.IsUpper([]rune(fieldName)[0]) {
			return true
		}

		// Also check unexported fields - this is important for generic types like Asset[T]
		// where the closer might be stored in an unexported field
		if isCloserType(v.Type()) {
			return true
		}
	}
	return false
}

// isHTTPRequestType reports whether t is net/http.Request or *net/http.Request
func isHTTPRequestType(t types.Type) bool {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok {
		if obj := n.Obj(); obj != nil {
			if pkg := obj.Pkg(); pkg != nil && pkg.Path() == "net/http" && obj.Name() == "Request" {
				return true
			}
		}
	}
	return false
}

func (pp *FunctionVisitor) traverse(id *ast.Ident, stmts []ast.Stmt) bool {
	for _, stmt := range stmts {
		switch castedStmt := stmt.(type) {
		case *ast.IfStmt:
			pp.debug(castedStmt, "found if stmt")

			if castedStmt.Init != nil && pp.traverse(id, []ast.Stmt{castedStmt.Init}) {
				return true
			}

			if pp.traverse(id, castedStmt.Body.List) {
				return true
			}
		case *ast.ReturnStmt:
			pp.debug(castedStmt, "found return stmt")

			if pp.closesIdentOnAnyExpression(id, castedStmt.Results) {
				return true
			}

		case *ast.DeferStmt:
			pp.debug(castedStmt, "found defer stmt, checking id: %s", id.String())

			if pp.closesIdentOnExpression(id, castedStmt.Call) {
				return true
			}
		case *ast.ExprStmt:
			pp.debug(castedStmt, "found expr stmt")

			if pp.closesIdentOnExpression(id, castedStmt.X) {
				return true
			}

		case *ast.AssignStmt:
			pp.debug(castedStmt, "found assign stmt comparing against: %s", id.String())

			if pp.closesIdentOnAnyExpression(id, castedStmt.Rhs) {
				return true
			}

		case *ast.BlockStmt:
			pp.debug(castedStmt, "found block stmt")
		}
	}

	return false
}

func (pp *FunctionVisitor) findKnownReceiverFromCall(call *ast.CallExpr) *ioCloserFunc {
	fndecl, _ := typeutil.Callee(pp.pass.TypesInfo, call).(*types.Func)
	if fndecl == nil {
		return nil
	}

	fn := &ioCloserFunc{}
	if !pp.pass.ImportObjectFact(fndecl, fn) {
		return nil
	}

	return fn
}

func (pp *FunctionVisitor) getKnownCloser(call *ast.CallExpr) *ioCloserFunc {
	if fn := pp.findKnownReceiverFromCall(call); fn != nil {
		return fn
	}

	switch castedFun := call.Fun.(type) {
	case *ast.Ident:
		return pp.getKnownCloserFromIdent(castedFun)
	case *ast.SelectorExpr:
		return pp.getKnownCloserFromSelector(castedFun)
	}

	return nil
}

func (pp *FunctionVisitor) getKnownCloserFromIdent(id *ast.Ident) *ioCloserFunc {
	fndecl, ok := pp.pass.TypesInfo.ObjectOf(id).(*types.Func)
	if !ok {
		return nil
	}

	fn, ok := pp.receivers[fndecl]
	if !ok {
		return nil
	}

	return fn
}

// isConstructorFunction determines if a function is a constructor that stores closers
// rather than closes them. Constructors typically:
// 1. Return a struct/pointer to struct (not primitive/interface)
// 2. Store parameters in the returned struct fields
// 3. Don't call Close() on their parameters
func (pp *FunctionVisitor) isConstructorFunction(fdecl *ast.FuncDecl, fn *types.Func) bool {
	sig := fn.Type().(*types.Signature)
	results := sig.Results()

	// Must return exactly one value
	if results.Len() != 1 {
		return false
	}

	returnType := results.At(0).Type()

	// Check if return type is a struct or pointer to struct
	if !pp.returnsStructType(returnType) {
		return false
	}

	// Check if function stores parameters in struct fields (constructor pattern)
	// and doesn't call Close() on parameters
	return pp.storesParametersInStruct(fdecl) && !pp.callsCloseOnParameters(fdecl)
}

// returnsStructType checks if the type is a struct or pointer to struct
func (pp *FunctionVisitor) returnsStructType(t types.Type) bool {
	switch underlying := t.Underlying().(type) {
	case *types.Struct:
		return true
	case *types.Pointer:
		_, isStruct := underlying.Elem().Underlying().(*types.Struct)
		return isStruct
	}
	return false
}

// storesParametersInStruct checks if function assigns parameters to struct fields
func (pp *FunctionVisitor) storesParametersInStruct(fdecl *ast.FuncDecl) bool {
	if fdecl.Body == nil {
		return false
	}

	// Look for patterns like: return &Struct{field: param}
	for _, stmt := range fdecl.Body.List {
		if retStmt, ok := stmt.(*ast.ReturnStmt); ok {
			for _, result := range retStmt.Results {
				if pp.isStructLiteralWithFieldAssignment(result) {
					return true
				}
			}
		}
	}
	return false
}

// isStructLiteralWithFieldAssignment checks for &Struct{field: value} or Struct{field: value}
func (pp *FunctionVisitor) isStructLiteralWithFieldAssignment(expr ast.Expr) bool {
	// Handle &Struct{...}
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		expr = unary.X
	}

	// Check for Struct{field: value}
	if compLit, ok := expr.(*ast.CompositeLit); ok {
		// Must have field assignments (not just positional)
		for _, elt := range compLit.Elts {
			if _, ok := elt.(*ast.KeyValueExpr); ok {
				return true
			}
		}
	}
	return false
}

// callsCloseOnParameters checks if function calls Close() on any of its parameters
func (pp *FunctionVisitor) callsCloseOnParameters(fdecl *ast.FuncDecl) bool {
	if fdecl.Body == nil {
		return false
	}

	// Get parameter names
	paramNames := make(map[string]bool)
	if fdecl.Type.Params != nil {
		for _, field := range fdecl.Type.Params.List {
			for _, name := range field.Names {
				paramNames[name.Name] = true
			}
		}
	}

	// Check if any statement calls Close() on parameters
	return pp.hasCloseCallOnParams(fdecl.Body.List, paramNames)
}

// hasCloseCallOnParams recursively checks for Close() calls on parameters
func (pp *FunctionVisitor) hasCloseCallOnParams(stmts []ast.Stmt, paramNames map[string]bool) bool {
	for _, stmt := range stmts {
		switch s := stmt.(type) {
		case *ast.ExprStmt:
			if pp.isCloseCallOnParam(s.X, paramNames) {
				return true
			}
		case *ast.DeferStmt:
			if pp.isCloseCallOnParam(s.Call, paramNames) {
				return true
			}
		case *ast.IfStmt:
			if pp.hasCloseCallOnParams(s.Body.List, paramNames) {
				return true
			}
		case *ast.BlockStmt:
			if pp.hasCloseCallOnParams(s.List, paramNames) {
				return true
			}
		}
	}
	return false
}

// isCloseCallOnParam checks if expression is a method call on a parameter that looks like cleanup
func (pp *FunctionVisitor) isCloseCallOnParam(expr ast.Expr, paramNames map[string]bool) bool {
	if call, ok := expr.(*ast.CallExpr); ok {
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok && paramNames[ident.Name] {
				// Check if this method call has a cleanup-like signature
				return pp.isMethodCallWithCleanupSignature(call)
			}
		}
	}
	return false
}

// isMethodCallWithCleanupSignature checks if call is EXACTLY io.Closer.Close() error
func (pp *FunctionVisitor) isMethodCallWithCleanupSignature(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return false
	}

	// Method MUST be named exactly "Close"
	if sel.Sel.Name != "Close" {
		return false
	}

	if fn, ok := typeutil.Callee(pp.pass.TypesInfo, call).(*types.Func); ok && fn != nil {
		if fn.Name() != "Close" {
			return false
		}
		if sig, ok := fn.Type().(*types.Signature); ok {
			// Receiver MUST be io.Closer or implement it exactly
			if recvInfo, ok := pp.pass.TypesInfo.Types[sel.X]; ok && (isCloserType(recvInfo.Type) || types.Identical(recvInfo.Type, closerType)) {
				// Signature MUST be exactly func() error
				return looksLikeCloserClose(sig)
			}
		}
	}
	return false
}

// methodRegistersShutdownHandlers detects patterns like:
//
//	f.shutdownHandlers = append(f.shutdownHandlers, func(){ _ = closer.Close() })
//
// where the receiver registers a handler that (provably) calls Close()
func (pp *FunctionVisitor) methodRegistersShutdownHandlers(fdecl *ast.FuncDecl) bool {
	if fdecl == nil || fdecl.Recv == nil || fdecl.Body == nil {
		return false
	}
	// receiver ident name (e.g., "f")
	var recvName string
	if len(fdecl.Recv.List) > 0 && len(fdecl.Recv.List[0].Names) > 0 {
		recvName = fdecl.Recv.List[0].Names[0].Name
	}
	if recvName == "" {
		return false
	}
	// scan statements for assignments: recv.field = append(recv.field, <arg...>)
	for _, stmt := range fdecl.Body.List {
		as, ok := stmt.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			continue
		}
		sel, ok := as.Lhs[0].(*ast.SelectorExpr)
		if !ok {
			continue
		}
		// base must be receiver ident
		if base, ok := sel.X.(*ast.Ident); !ok || base.Name != recvName {
			continue
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			continue
		}
		// append(recv.field, ...)
		if funIdent, ok := call.Fun.(*ast.Ident); !ok || funIdent.Name != "append" {
			continue
		}
		// first arg must be same selector as LHS
		if argSel, ok := call.Args[0].(*ast.SelectorExpr); !ok || !pp.sameSelector(argSel, sel) {
			continue
		}
		// any subsequent arg that is a function (literal or method value) qualifies as
		// "registering a shutdown handler". Whether it actually closes resources is proven later.
		for _, a := range call.Args[1:] {
			switch a.(type) {
			case *ast.FuncLit:
				return true
			case *ast.SelectorExpr, *ast.Ident:
				// method value or named func
				return true
			}
		}
	}
	return false
}

// methodIsShutdownMethod detects patterns like:
//
//	for _, h := range f.shutdownHandlers { h() }
func (pp *FunctionVisitor) methodIsShutdownMethod(fdecl *ast.FuncDecl) bool {
	if fdecl == nil || fdecl.Recv == nil || fdecl.Body == nil {
		return false
	}
	var recvName string
	if len(fdecl.Recv.List) > 0 && len(fdecl.Recv.List[0].Names) > 0 {
		recvName = fdecl.Recv.List[0].Names[0].Name
	}
	if recvName == "" {
		return false
	}
	for _, stmt := range fdecl.Body.List {
		rs, ok := stmt.(*ast.RangeStmt)
		if !ok {
			continue
		}
		// range over receiver field: range f.<field>
		if sel, ok := rs.X.(*ast.SelectorExpr); ok {
			if base, ok := sel.X.(*ast.Ident); ok && base.Name == recvName {
				// body should call the value variable ident with no args: h()
				if val, ok := rs.Value.(*ast.Ident); ok && val != nil {
					for _, bs := range rs.Body.List {
						if es, ok := bs.(*ast.ExprStmt); ok {
							if call, ok := es.X.(*ast.CallExpr); ok {
								if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == val.Name && len(call.Args) == 0 {
									return true
								}
							}
						}
					}
				}
			}
		}
	}
	return false
}

// funcLitCallsClose reports whether a function literal body contains a provable Close() call
func (pp *FunctionVisitor) funcLitCallsClose(fl *ast.FuncLit) bool {
	if fl == nil || fl.Body == nil {
		return false
	}
	// walk simple statements for Close() calls
	var scan func(stmts []ast.Stmt) bool
	scan = func(stmts []ast.Stmt) bool {
		for _, s := range stmts {
			switch n := s.(type) {
			case *ast.DeferStmt:
				if pp.isMethodCallWithCleanupSignature(n.Call) {
					return true
				}
			case *ast.ExprStmt:
				if c, ok := n.X.(*ast.CallExpr); ok {
					if pp.isMethodCallWithCleanupSignature(c) {
						return true
					}
				}
			case *ast.AssignStmt:
				for _, r := range n.Rhs {
					if c, ok := r.(*ast.CallExpr); ok && pp.isMethodCallWithCleanupSignature(c) {
						return true
					}
				}
			case *ast.BlockStmt:
				if scan(n.List) {
					return true
				}
			case *ast.IfStmt:
				if scan(n.Body.List) {
					return true
				}
				if n.Else != nil {
					if b, ok := n.Else.(*ast.BlockStmt); ok {
						if scan(b.List) {
							return true
						}
					}
				}
			}
		}
		return false
	}
	return scan(fl.Body.List)
}

// sameSelector checks structural equality of two selector expressions
func (pp *FunctionVisitor) sameSelector(a, b *ast.SelectorExpr) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Sel == nil || b.Sel == nil || a.Sel.Name != b.Sel.Name {
		return false
	}
	// Prefer object identity when available
	if ai, ok := a.X.(*ast.Ident); ok {
		if bi, ok2 := b.X.(*ast.Ident); ok2 {
			ao := pp.pass.TypesInfo.ObjectOf(ai)
			bo := pp.pass.TypesInfo.ObjectOf(bi)
			if ao != nil && bo != nil {
				return ao.Pos() == bo.Pos()
			}
			return ai.NamePos == bi.NamePos
		}
	}
	return false
}

func (pp *FunctionVisitor) getKnownCloserFromSelector(sel *ast.SelectorExpr) *ioCloserFunc {
	var knownCloser *ioCloserFunc

	pp.visitSelectors(sel, func(id *ast.Ident) bool {
		if fn := pp.getKnownCloserFromIdent(id); fn != nil {
			knownCloser = fn

			return false
		}

		return true
	})

	return knownCloser
}

func (pp *FunctionVisitor) closesIdentOnAnyExpression(id *ast.Ident, exprs []ast.Expr) bool {
	for _, expr := range exprs {
		if pp.closesIdentOnExpression(id, expr) {
			return true
		}
	}

	return false
}

func (pp *FunctionVisitor) closesIdentOnExpression(id *ast.Ident, expr ast.Expr) bool {
	switch castedExpr := expr.(type) { // TODO: funclit
	case *ast.CallExpr:
		// Check if this is a method call on our identifier (e.g., id.Method())
		if sel, ok := castedExpr.Fun.(*ast.SelectorExpr); ok {
			if pp.isPosInExpression(id.Pos(), sel.X) {
				// Only treat as cleanup if it's io.Closer.Close()
				return pp.isMethodCallWithCleanupSignature(castedExpr)
			}
		}

		if cl := pp.getKnownCloser(castedExpr); cl != nil && cl.isCloser {
			// Check if the identifier is passed as an argument that will be closed
			for i, arg := range castedExpr.Args {
				if pp.isPosInExpression(id.Pos(), arg) {
					// Check if this argument position corresponds to a closer parameter
					if i < len(cl.argsThatAreClosers) && cl.argsThatAreClosers[i] {
						return true
					}
				}
			}
		}

	case *ast.SelectorExpr:
		// This case handles when selector expression is passed recursively
		// but we want to check method calls, not just selectors
		return false
	}

	return false
}

func (pp *FunctionVisitor) isPosInExpression(pos token.Pos, expr ast.Expr) bool {
	switch castedExpr := expr.(type) {
	case *ast.Ident:
		return pp.isIdentInPos(castedExpr, pos)
	case *ast.SelectorExpr:
		wasFound := false

		pp.visitSelectors(castedExpr, func(id *ast.Ident) bool {
			if pp.isIdentInPos(id, pos) {
				wasFound = true
				return false
			}

			return true
		})

		return wasFound
	}

	return false
}

func (pp *FunctionVisitor) visitSelectors(sel *ast.SelectorExpr, cb func(id *ast.Ident) bool) {
	if !cb(sel.Sel) {
		return
	}

	if newSel, ok := sel.X.(*ast.SelectorExpr); ok {
		pp.visitSelectors(newSel, cb)
	}
}

func (pp *FunctionVisitor) isIdentInPos(id *ast.Ident, pos token.Pos) bool {
	if pos == id.Pos() {
		return true
	}

	decl := pp.pass.TypesInfo.ObjectOf(id)

	return decl.Pos() == pos
}

func (pp *FunctionVisitor) isExprEqualToIdent(id *ast.Ident, x ast.Expr) bool {
	xIdent, ok := x.(*ast.Ident)
	if !ok {
		return false
	}

	if id.NamePos == xIdent.NamePos {
		return true
	}

	if xIdent.Obj == nil || xIdent.Obj.Decl == nil {
		return false
	}

	vdecl, ok := xIdent.Obj.Decl.(*ast.Field)
	if !ok || len(vdecl.Names) != 1 {
		return false
	}

	return vdecl.Names[0].NamePos == id.NamePos
}
