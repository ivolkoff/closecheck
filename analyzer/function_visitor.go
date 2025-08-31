package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"unicode"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/typeutil"
)

var (
	enableFunctionDebugger   = false
	showCloserFunctionsFound = false
)

// FunctionVisitor is in charge of preprocessing packages to find functions that close io.Closers
type FunctionVisitor struct {
	pass            *analysis.Pass
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

// this function finds functions that receive and closes an io.Closer
func (pp *FunctionVisitor) findFunctionsThatReceiveAnIOCloser() map[*types.Func]*ioCloserFunc {
	pp.receivers = map[*types.Func]*ioCloserFunc{}
	pp.localGlobalVars = map[token.Pos]bool{}

	for _, file := range pp.pass.Files {
		for _, decl := range file.Decls {
			switch cDecl := decl.(type) {
			case *ast.GenDecl:
				if cDecl.Tok != token.VAR {
					continue
				}

				for _, spec := range cDecl.Specs {
					varSpec, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}

					for _, name := range varSpec.Names {
						obj := pp.pass.TypesInfo.ObjectOf(name)
						if obj == nil {
							continue
						}

						if isCloserReceiver(obj.Type().Underlying()) {
							pp.localGlobalVars[name.NamePos] = true
						}
					}
				}
			case *ast.FuncDecl:
				if cDecl.Body == nil {
					continue
				}

				fn, ok := pp.pass.TypesInfo.Defs[cDecl.Name].(*types.Func)
				if !ok {
					continue
				}

				// Skip constructor-like functions that store closers rather than close them
				// These typically create repositories/services and store dependencies
				if pp.isConstructorFunction(cDecl, fn) {
					continue
				}

				sig := fn.Type().(*types.Signature)
				params := sig.Params()

				receivesCloser := false
				argsThatAreClosers := make([]bool, params.Len())
				argNames := []*ast.Ident{}

				for _, params := range cDecl.Type.Params.List {
					argNames = append(argNames, params.Names...) // FIXME: should only contain io.Closers
				}

				for i := 0; i < params.Len(); i++ {
					param := params.At(i)

					if isCloserReceiver(param.Type()) {
						receivesCloser = true
						argsThatAreClosers[i] = true

						// Debug parameter type detection
						// if strings.Contains(fn.FullName(), "Get") {
						//	fmt.Printf("DEBUG: Function %s param %d type %s detected as closer\n", fn.FullName(), i, param.Type().String())
						// }
					}
				}

				if receivesCloser {
					pp.receivers[fn] = &ioCloserFunc{
						obj:                fn,
						fdecl:              cDecl,
						argsThatAreClosers: argsThatAreClosers,
						argNames:           argNames,
					}
				}
			}
		}
	}

	// Run multiple passes to handle transitive closure relationships
	maxPasses := 10 // Prevent infinite loops
	for pass := 0; pass < maxPasses; pass++ {
		changesMade := false

		for _, rcv := range pp.receivers {
			if rcv.isCloser {
				continue // Already determined to be a closer
			}

			for _, id := range rcv.argNames {
				if pp.traverse(id, rcv.fdecl.Body.List) {
					rcv.isCloser = true
					changesMade = true
					break
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
            // Receiver MUST implement io.Closer interface
            if recvInfo, ok := pp.pass.TypesInfo.Types[sel.X]; ok && isCloserType(recvInfo.Type) {
                // Signature MUST be exactly func() error
                return looksLikeCloserClose(sig)
            }
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
