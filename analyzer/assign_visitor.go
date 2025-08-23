package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
	"unicode"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/typeutil"
)

var (
	enableAssignDebugger = false
	printFunctionFailure = false
)

// AssignVisitor is in charge of preprocessing packages to find functions that close io.Closers
type AssignVisitor struct {
	pass            *analysis.Pass
	closerFuncs     map[*types.Func]*ioCloserFunc
	localGlobalVars map[token.Pos]bool
}

func (av *AssignVisitor) debug(n ast.Node, text string, args ...interface{}) {
	if !enableAssignDebugger {
		return
	}

	if n == nil {
		return
	}

	pos := av.pass.Fset.Position(
		n.Pos(),
	)

	if strings.Contains(pos.Filename, "/libexec/") || strings.Contains(pos.Filename, "/vendor/") {
		return
	}

	fmt.Printf(text+"\n", args...)

	_ = ast.Print(av.pass.Fset, n)
}

type posToClose struct {
	name                string
	typeName            string
	pos                 token.Pos
	parent              *ast.Ident
	wasClosedOrReturned bool
}

type field struct {
	name     string
	typeName string
	pos      token.Pos
}

type returnVar struct {
	needsClosing bool
	typeName     string
	fields       []field
}

func (av *AssignVisitor) newReturnVar(t types.Type) returnVar {
	if isCloserType(t) {
		return returnVar{
			needsClosing: true,
			typeName:     t.String(),
			fields:       []field{},
		}
	}

	// special case: a struct containing a io.Closer fields that implements io.Closer, like http.Response.Body
	ptr, ok := t.Underlying().(*types.Pointer)
	if !ok {
		return returnVar{
			needsClosing: false,
			fields:       []field{},
		}
	}

	str, ok := ptr.Elem().Underlying().(*types.Struct)
	if !ok {
		return returnVar{
			needsClosing: false,
			fields:       []field{},
		}
	}

	fields := []field{}

	for i := 0; i < str.NumFields(); i++ {
		v := str.Field(i)
		fieldName := v.Name()

		// TODO: don't ignore unexported fields if the struct is in the current package
		if isCloserType(v.Type()) && unicode.IsUpper([]rune(fieldName)[0]) {
			fields = append(fields, field{
				name:     fieldName,
				typeName: v.Type().String(),
				pos:      v.Pos(),
			})
		}
	}

	return returnVar{
		needsClosing: len(fields) > 0,
		typeName:     t.String(),
		fields:       fields,
	}
}

// this function checks functions that assign a closer
func (av *AssignVisitor) checkFunctionsThatAssignCloser() {
	for _, file := range av.pass.Files {
		for _, decl := range file.Decls {
			fdecl, ok := decl.(*ast.FuncDecl)
			if !ok || fdecl.Body == nil {
				continue
			}

			
			if !av.traverse(fdecl.Body.List) && printFunctionFailure {
				fmt.Println("Printing function that failed")

				_ = ast.Print(av.pass.Fset, fdecl)
			}
		}
	}
}

func (av *AssignVisitor) traverse(stmts []ast.Stmt) bool {
	posListToClose := []*posToClose{}

	// First pass: collect all closers from assignments and check for unassigned calls
	for _, stmt := range stmts {
		switch castedStmt := stmt.(type) {
		case *ast.ExprStmt:
			call, ok := castedStmt.X.(*ast.CallExpr)
			if ok && av.callReturnsCloser(call) {
				av.pass.Reportf(call.Pos(), "return value won't be closed because it wasn't assigned") // FIXME: improve message
			}
		case *ast.DeferStmt:
			if av.callReturnsCloser(castedStmt.Call) {
				av.pass.Reportf(castedStmt.Call.Pos(), "return value won't be closed because it's on defer statement") // FIXME: improve message
				return false
			}
		case *ast.GoStmt:
			if av.callReturnsCloser(castedStmt.Call) {
				av.pass.Reportf(castedStmt.Call.Pos(), "return value won't be closed because it's on go statement") // FIXME: improve message
				return false
			}
		case *ast.AssignStmt:
			if av.hasGlobalCloserInAssignment(castedStmt.Lhs) {
				continue
			}

			if len(castedStmt.Rhs) == 1 {
				posListToClose = append(posListToClose, av.handleAssignment(castedStmt.Lhs, castedStmt.Rhs[0])...)
			} else {
				posListToClose = append(posListToClose, av.handleMultiAssignment(castedStmt.Lhs, castedStmt.Rhs)...)
			}
		}
	}

	// Second pass: check all statements to see if they close any of the collected closers
	for _, stmt := range stmts {
		for _, idToClose := range posListToClose {
			if av.returnsOrClosesID(*idToClose, stmt) {
				idToClose.wasClosedOrReturned = true
			}
		}
	}

	hasErrors := false
	for _, idToClose := range posListToClose {
		if !idToClose.wasClosedOrReturned {
			// Simplify the type name for display (remove vendor paths)
			typeName := idToClose.typeName
			if strings.Contains(typeName, "/vendor/") && strings.Contains(typeName, "/redis.") {
				// Extract the package and type from vendor path like "redigo/vendor/github.com/gomodule/redigo/redis.Conn" -> "redis.Conn"
				if idx := strings.LastIndex(typeName, "/redis."); idx != -1 {
					typeName = "redis" + typeName[idx+6:] // Take everything after "/redis"
				}
			}
			av.pass.Reportf(idToClose.parent.Pos(), "%s (%s) was not closed", idToClose.name, typeName)
			hasErrors = true
		}
	}

	if hasErrors {
		return false
	}

	return true
}

func (av *AssignVisitor) hasGlobalCloserInAssignment(lhs []ast.Expr) bool {
	for i := 0; i < len(lhs); i++ {
		assignedID, ok := lhs[i].(*ast.Ident)
		if !ok {
			continue
		}

		if av.shouldIgnoreGlobalVariable(assignedID) {
			return true
		}
	}

	return false
}

func (av *AssignVisitor) returnsOrClosesIDOnExpression(idToClose posToClose, expr ast.Expr) bool {
	// First check if the expression contains the identifier we're tracking
	if !av.isPosInExpression(idToClose.pos, expr) {
		return false
	}

	// If it contains the identifier, check if it's being properly handled
	switch cExpr := expr.(type) {
	case *ast.Ident:
		return av.getKnownCloserFromIdent(cExpr) != nil
	case *ast.FuncLit:
		return av.traverse(cExpr.Body.List)
	case *ast.CallExpr:
		// Check if this is a direct Close() call on our identifier
		if sel, ok := cExpr.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Close" {
			if av.isPosInExpression(idToClose.pos, sel.X) {
				return true
			}
		}

		return av.callsToKnownCloser(idToClose.pos, cExpr)
	case *ast.SelectorExpr:
		// This case handles expressions like res7.Body (not function calls)
		// A selector expression alone doesn't close anything
		return av.getKnownCloserFromSelector(cExpr) != nil
	}

	return false
}

func (av *AssignVisitor) returnsOrClosesID(idToClose posToClose, stmt ast.Stmt) bool {
	if stmt == nil {
		return false
	}
	
	switch castedStmt := stmt.(type) {
	case *ast.ReturnStmt:
		for _, res := range castedStmt.Results {
			// Check if closer is being transferred to a io.Closer struct in return
			if av.isCloserTransferredToCloserStruct(idToClose, res) {
				return true
			}
			
			// For redis connections, only consider direct identifier returns to avoid 
			// false positives where conn.Do(...) is used in return expressions
			if strings.Contains(idToClose.typeName, "redis.Conn") {
				if ident, ok := res.(*ast.Ident); ok {
					if av.isIdentInPos(ident, idToClose.pos) {
						return true
					}
					if idToClose.pos != idToClose.parent.Pos() && av.isIdentInPos(ident, idToClose.parent.Pos()) {
						return true
					}
				}
			} else {
				// For other closers, use broader logic to handle HTTP responses
				if av.isPosInExpression(idToClose.pos, res) {
					return true
				}
				if idToClose.pos != idToClose.parent.Pos() && av.isPosInExpression(idToClose.parent.Pos(), res) {
					return true  
				}
			}
		}

	case *ast.DeferStmt:
		if av.callsToKnownCloser(idToClose.pos, castedStmt.Call) {
			return true
		}
	case *ast.GoStmt:
		if av.callsToKnownCloser(idToClose.pos, castedStmt.Call) {
			return true
		}
	case *ast.ExprStmt:
		call, ok := castedStmt.X.(*ast.CallExpr)
		if !ok {
			return false
		}

		// Check if any of the arguments are direct Close() calls on our identifier
		for _, arg := range call.Args {
			if av.isDirectCloseCall(idToClose.pos, arg) {
				return true
			}
		}

		if av.callsToKnownCloser(idToClose.pos, call) {
			return true
		}

	case *ast.AssignStmt:
		for _, exp := range castedStmt.Rhs {
			if call, ok := exp.(*ast.CallExpr); ok {
				if av.callsToKnownCloser(idToClose.pos, call) {
					return true
				}
			}
		}

	case *ast.IfStmt:
		if castedStmt.Init != nil && av.returnsOrClosesID(idToClose, castedStmt.Init) {
			return true
		}

		for _, stmt := range castedStmt.Body.List {
			if av.returnsOrClosesID(idToClose, stmt) {
				return true
			}
		}
	}
	
	return false
}

func (av *AssignVisitor) isDirectCloseCall(pos token.Pos, expr ast.Expr) bool {
	if callExpr, ok := expr.(*ast.CallExpr); ok {
		if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok && selExpr.Sel.Name == "Close" {
			if av.isPosInExpression(pos, selExpr.X) {
				return true
			}
		}
	}
	return false
}

// isCloserTransferredToCloserStruct checks if a closer is being transferred to a struct that implements io.Closer
func (av *AssignVisitor) isCloserTransferredToCloserStruct(idToClose posToClose, expr ast.Expr) bool {
	var compLit *ast.CompositeLit
	var structType types.Type
	
	// Handle &StructType{...} case
	if unaryExpr, ok := expr.(*ast.UnaryExpr); ok && unaryExpr.Op == token.AND {
		if innerCompLit, ok := unaryExpr.X.(*ast.CompositeLit); ok {
			compLit = innerCompLit
			// Get type information from the unary expression (which gives us the pointer type)
			if typeInfo, exists := av.pass.TypesInfo.Types[expr]; exists {
				structType = typeInfo.Type
			}
		}
	} else if cl, ok := expr.(*ast.CompositeLit); ok {
		// Direct StructType{...} case
		compLit = cl
		if typeInfo, exists := av.pass.TypesInfo.Types[expr]; exists {
			structType = typeInfo.Type
		}
	}
	
	if compLit == nil || structType == nil {
		return false
	}

	// Check if the struct type (or what it points to) implements io.Closer
	if !isCloserType(structType) {
		return false
	}

	// Check if our closer or its parent is used in this composite literal
	// For struct fields like resp.Body, we need to check if the parent (resp) is used
	containsPos := av.isPosInExpression(idToClose.pos, compLit)
	containsParentPos := av.isPosInExpression(idToClose.parent.Pos(), compLit)
	
	return containsPos || containsParentPos
}

func (av *AssignVisitor) handleMultiAssignment(lhs []ast.Expr, rhs []ast.Expr) []*posToClose {
	posListToClose := make([]*posToClose, 0)

	for i := 0; i < len(rhs); i++ {
		id, ok := lhs[i].(*ast.Ident)
		if !ok {
			continue
		}

		call, ok := rhs[i].(*ast.CallExpr)
		if !ok {
			continue
		}

		returnVars := av.returnsThatAreClosers(call)

		if !returnVars[0].needsClosing {
			continue
		}

		if len(returnVars[0].fields) == 0 {
			posListToClose = append(posListToClose, &posToClose{
				parent:   id,
				name:     id.Name,
				typeName: returnVars[0].typeName,
				pos:      id.Pos(),
			})
		}

		for _, field := range returnVars[0].fields {
			posListToClose = append(posListToClose, &posToClose{
				parent:   id,
				name:     id.Name + "." + field.name,
				typeName: field.typeName,
				pos:      id.Pos(), // Use parent variable position instead of field position
			})
		}
	}

	return posListToClose
}

func (av *AssignVisitor) handleAssignment(lhs []ast.Expr, rhs ast.Expr) []*posToClose {
	call, ok := rhs.(*ast.CallExpr)
	if !ok {
		return []*posToClose{}
	}

	returnVars := av.returnsThatAreClosers(call)
	posListToClose := make([]*posToClose, 0, len(returnVars))

	for i := 0; i < len(lhs); i++ {
		id, ok := lhs[i].(*ast.Ident)
		if !ok {
			continue
		}

		if i >= len(returnVars) || !returnVars[i].needsClosing {
			continue
		}

		if len(returnVars[i].fields) == 0 {
			posListToClose = append(posListToClose, &posToClose{
				parent:   id,
				name:     id.Name,
				typeName: returnVars[i].typeName,
				pos:      id.Pos(),
			})
		}

		for _, field := range returnVars[i].fields {
			posListToClose = append(posListToClose, &posToClose{
				parent:   id,
				name:     id.Name + "." + field.name,
				typeName: field.typeName,
				pos:      id.Pos(), // Use parent variable position instead of field position
			})
		}
	}

	// TODO: check that Rhs is not a call to a known av.closerFuncs

	return posListToClose
}

func (av *AssignVisitor) callReturnsCloser(call *ast.CallExpr) bool {
	returnVars := av.returnsThatAreClosers(call)
	av.debug(call, "callReturnsCloser: checking %d return vars", len(returnVars))
	for i, returnVar := range returnVars {
		av.debug(call, "Return var %d: needsClosing=%t, typeName=%s, fields=%d",
			i, returnVar.needsClosing, returnVar.typeName, len(returnVar.fields))
		if returnVar.needsClosing {
			return true
		}
	}

	return false
}

func (av *AssignVisitor) returnsThatAreClosers(call *ast.CallExpr) []returnVar {
	if fn, ok := call.Fun.(*ast.SelectorExpr); ok && fn.Sel.Name == "NopCloser" {
		o, ok := fn.X.(*ast.Ident)
		if ok && (o.Name == "ioutil" || o.Name == "io") {
			return []returnVar{{}}
		}
	}

	switch t := av.pass.TypesInfo.Types[call].Type.(type) {
	case *types.Named:
		return []returnVar{av.newReturnVar(t)}
	case *types.Pointer:
		return []returnVar{av.newReturnVar(t)}
	case *types.Tuple:
		s := make([]returnVar, t.Len())

		for i := 0; i < t.Len(); i++ {
			switch et := t.At(i).Type().(type) {
			case *types.Named:
				s[i] = av.newReturnVar(et)
			case *types.Pointer:
				s[i] = av.newReturnVar(et)
			}
		}

		return s
	}

	return []returnVar{{}}
}

func (av *AssignVisitor) getKnownCloserFromIdent(id *ast.Ident) *ioCloserFunc {
	fndecl, ok := av.pass.TypesInfo.ObjectOf(id).(*types.Func)
	if !ok {
		return nil
	}

	fn, ok := av.closerFuncs[fndecl]
	if !ok {
		return nil
	}

	if av.pass.ImportObjectFact(fndecl, fn) && fn.isCloser {
		return fn
	}

	return fn
}

func (av *AssignVisitor) getKnownCloserFromSelector(sel *ast.SelectorExpr) *ioCloserFunc {
	var knownCloser *ioCloserFunc

	av.visitSelectors(sel, func(id *ast.Ident) bool {
		if fn := av.getKnownCloserFromIdent(id); fn != nil {
			knownCloser = fn
			return false
		}

		return true
	})

	return knownCloser
}

func (av *AssignVisitor) visitSelectors(sel *ast.SelectorExpr, cb func(id *ast.Ident) bool) {
	if !cb(sel.Sel) {
		return
	}

	if newSel, ok := sel.X.(*ast.SelectorExpr); ok {
		av.visitSelectors(newSel, cb)
	} else if ident, ok := sel.X.(*ast.Ident); ok {
		// Also check the base identifier (e.g., 'res' in 'res.Body')
		cb(ident)
	}
}

func (av *AssignVisitor) findKnownReceiverFromCall(pos token.Pos, call *ast.CallExpr) *ioCloserFunc {
	fndecl, _ := typeutil.Callee(av.pass.TypesInfo, call).(*types.Func)
	if fndecl == nil {
		return nil
	}

	fn := &ioCloserFunc{}
	av.pass.ImportObjectFact(fndecl, fn)

	return fn
}

func (av *AssignVisitor) callsToKnownCloser(pos token.Pos, call *ast.CallExpr) bool {
	fndecl, _ := typeutil.Callee(av.pass.TypesInfo, call).(*types.Func)
	fn := &ioCloserFunc{}

	if fndecl != nil && av.pass.ImportObjectFact(fndecl, fn) && fn != nil {
		if fn.isCloser {
			// Special handling for functions that take struct types containing closers
			// (like *http.Response) vs functions that take io.Closer directly
			sig := fndecl.Type().(*types.Signature)
			params := sig.Params()
			
			hasDirectCloserParam := false
			for i := 0; i < params.Len(); i++ {
				param := params.At(i)
				if isCloserType(param.Type()) {
					hasDirectCloserParam = true
					break
				}
			}
			
			if hasDirectCloserParam {
				// For functions that take io.Closer directly (like closeBody),
				// check if arguments match the position we're tracking
				for i, arg := range call.Args {
					if i < len(fn.argsThatAreClosers) && fn.argsThatAreClosers[i] {
						if av.isPosInExpression(pos, arg) {
							return true
						}
					}
				}
				return false
			} else {
				// For functions that take struct types (like *http.Response),
				// use the old logic
				return true
			}
		}
		return false
	}

	switch castedFun := call.Fun.(type) {
	case *ast.CallExpr:
		return av.callsToKnownCloser(pos, castedFun)
	case *ast.Ident:
		return av.getKnownCloserFromIdent(castedFun) != nil
	case *ast.SelectorExpr:
		// Check if this is a Close() method call on the identifier we're tracking
		if castedFun.Sel.Name == "Close" && av.isPosInExpression(pos, castedFun.X) {
			return true
		}
		return av.getKnownCloserFromSelector(castedFun) != nil
	case *ast.FuncLit:
		return av.traverse(castedFun.Body.List)
	}

	return false
}

func (av *AssignVisitor) isPosInExpression(pos token.Pos, expr ast.Expr) bool {
	switch castedExpr := expr.(type) {
	case *ast.UnaryExpr:
		return av.isPosInExpression(pos, castedExpr.X)
	case *ast.CallExpr:
		return av.findKnownReceiverFromCall(pos, castedExpr) != nil
	case *ast.Ident:
		return av.isIdentInPos(castedExpr, pos)
	case *ast.SelectorExpr:
		// For selector expressions like res.Body, check if the base variable matches our position
		if baseIdent, ok := castedExpr.X.(*ast.Ident); ok {
			if av.isIdentInPos(baseIdent, pos) {
				return true
			}
		}
		
		// Fallback to the old logic for complex selectors
		wasFound := false

		av.visitSelectors(castedExpr, func(id *ast.Ident) bool {
			if av.isIdentInPos(id, pos) {
				wasFound = true
				return false
			}

			return true
		})

		return wasFound
	case *ast.CompositeLit:
		if castedExpr.Elts == nil {
			break
		}

		for _, e := range castedExpr.Elts {
			if av.isPosInExpression(pos, e) {
				return true
			}
		}
	case *ast.KeyValueExpr:
		// FIXME: this is not 100% accurate because we haven't checked that the Close is called in the future
		if av.isPosInExpression(pos, castedExpr.Value) {
			return true
		}
	}

	return false
}

func (av *AssignVisitor) isIdentInPos(id *ast.Ident, pos token.Pos) bool {
	if pos == id.Pos() {
		return true
	}

	decl := av.pass.TypesInfo.ObjectOf(id)
	if decl == nil {
		return false
	}

	return decl.Pos() == pos
}

func (av *AssignVisitor) isExprEqualToIdent(id *ast.Ident, x ast.Expr) bool {
	xIdent, ok := x.(*ast.Ident)
	if !ok {
		return false
	}

	if id.NamePos == xIdent.NamePos {
		return true
	}

	decl := av.pass.TypesInfo.ObjectOf(xIdent)

	return decl.Pos() == id.Pos()
}

func (av *AssignVisitor) shouldIgnoreGlobalVariable(id *ast.Ident) bool {
	if id.Obj == nil || id.Obj.Decl == nil {
		return false
	}

	val, ok := id.Obj.Decl.(*ast.ValueSpec)
	if !ok {
		return false
	}

	if len(val.Names) == 1 && av.localGlobalVars[val.Names[0].NamePos] {
		return true
	}

	return false
}
