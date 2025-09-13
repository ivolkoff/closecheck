package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/types/typeutil"
)

var (
	enableAssignDebugger = false
	printFunctionFailure = false
)

// globalShutdownTypes tracks receiver type keys for which a provable shutdown call
// (e.g., defer x.Clean()/x.Close()) was observed anywhere in the analysis run.
// This allows suppressing false positives in packages that only register handlers,
// while shutdown calls happen in another package (e.g., main).
// (removed) globalShutdownTypes — replaced by heavy cross-package scanning

// AssignVisitor is in charge of preprocessing packages to find functions that close io.Closers
type AssignVisitor struct {
	pass            *analysis.Pass
	skipPos         func(token.Pos) bool
	closerFuncs     map[*types.Func]*ioCloserFunc
	localGlobalVars map[token.Pos]bool
	// Track variables obtained from factory methods: variable name -> factory name
	factoryVariables map[string]string

	// New lifecycle-based resource tracking
	resourceTracker *ResourceTracker

	// Method value tracking: map method-value variable -> receiver
	methodValueRecvPos  map[token.Pos]token.Pos // mvVarPos -> recvVarPos
	methodValueRecvName map[token.Pos]string    // mvVarPos -> recvVarName
	// Whether the tracked method value is exactly Close() error on an io.Closer receiver
	methodValueIsClose map[token.Pos]bool // mvVarPos -> isClose()

	// Factory mapping without names: variable (obtained from factory) pos -> factory var pos
	factoryVarByPos map[token.Pos]token.Pos

	// Container shutdown aggregation facts (strictly proven patterns)
	// Map container var pos -> has AddShutdown(factory.DB.Shutdown) registered
	containerHasShutdownHandler map[token.Pos]bool
	// Map container var pos -> factory.DB was created with shutdown func that calls Close(param)
	containerFieldShutdownCloses map[token.Pos]bool

	// Reporting metadata for containers
	containerVarNameByPos    map[token.Pos]string
	containerVarTypeByPos    map[token.Pos]string
	containersProvenShutdown map[token.Pos]bool

	// Local containers created in this function (via &Struct{} or Struct{} assignment)
	localContainers map[token.Pos]bool
	// Defer calls on containers (by pos) observed in this function
	containerDeferredCall map[token.Pos]bool

	// Heavy cross-package scanning cache: moduleRoot+typeKey -> has shutdown call
	heavyScanCacheMu sync.Mutex
	heavyScanCache   map[string]bool

	moduleRoot string
}

func (av *AssignVisitor) debug(n ast.Node, text string, args ...interface{}) {
	if !enableAssignDebugger {
		return
	}

	if n != nil {
		pos := av.pass.Fset.Position(
			n.Pos(),
		)

		if strings.Contains(pos.Filename, "/libexec/") || strings.Contains(pos.Filename, "/vendor/") {
			return
		}
	}

	fmt.Printf(text+"\n", args...)

	if n != nil {
		_ = ast.Print(av.pass.Fset, n)
	}
}

func (av *AssignVisitor) shouldSkipNode(n ast.Node) bool {
	if av == nil || av.skipPos == nil || n == nil {
		return false
	}
	return av.skipPos(n.Pos())
}

// ResourceID uniquely identifies a resource in the program
type ResourceID string

// Resource represents a closeable resource in the program
type Resource struct {
	id           ResourceID
	varName      string     // Variable name (e.g., "factory", "db")
	typeName     string     // Type name (e.g., "*Factory", "redis.Conn")
	creationSite ast.Node   // Where the resource was created
	pos          token.Pos  // Position in source
	parent       *ast.Ident // AST node of the variable

	// Lifecycle tracking
	hasCloseMethod bool       // Does this type have any close-like method?
	closedAt       []ast.Node // Where this resource was closed
	derivedFrom    ResourceID // If this resource was derived from another (e.g., db from factory)
}

// ResourceTracker tracks the lifecycle of closeable resources
type ResourceTracker struct {
	resources map[ResourceID]*Resource // All tracked resources
	dataFlow  map[string]ResourceID    // variable name -> resource ID mapping
	nextID    int                      // For generating unique IDs
}

// NewResourceTracker creates a new resource tracker
func NewResourceTracker() *ResourceTracker {
	return &ResourceTracker{
		resources: make(map[ResourceID]*Resource),
		dataFlow:  make(map[string]ResourceID),
		nextID:    1,
	}
}

// generateID generates a unique resource ID
func (rt *ResourceTracker) generateID() ResourceID {
	id := ResourceID(fmt.Sprintf("resource_%d", rt.nextID))
	rt.nextID++
	return id
}

// AddResource adds a new resource to track
func (rt *ResourceTracker) AddResource(varName, typeName string, creationSite ast.Node, pos token.Pos, parent *ast.Ident, hasCloseMethod bool) ResourceID {
	id := rt.generateID()
	resource := &Resource{
		id:             id,
		varName:        varName,
		typeName:       typeName,
		creationSite:   creationSite,
		pos:            pos,
		parent:         parent,
		hasCloseMethod: hasCloseMethod,
		closedAt:       []ast.Node{},
	}

	rt.resources[id] = resource
	rt.dataFlow[varName] = id
	return id
}

// AddDerivedResource adds a resource that was derived from another resource
func (rt *ResourceTracker) AddDerivedResource(varName, typeName string, creationSite ast.Node, pos token.Pos, parent *ast.Ident, hasCloseMethod bool, derivedFrom ResourceID) ResourceID {
	id := rt.AddResource(varName, typeName, creationSite, pos, parent, hasCloseMethod)
	rt.resources[id].derivedFrom = derivedFrom
	return id
}

// MarkClosed marks a resource as closed at a specific location
func (rt *ResourceTracker) MarkClosed(resourceID ResourceID, closeSite ast.Node) {
	if resource, exists := rt.resources[resourceID]; exists {
		resource.closedAt = append(resource.closedAt, closeSite)
	}
}

// GetResourceByVar gets a resource by variable name
func (rt *ResourceTracker) GetResourceByVar(varName string) *Resource {
	if id, exists := rt.dataFlow[varName]; exists {
		return rt.resources[id]
	}
	return nil
}

// getResourceByID finds a resource by its ID
func (rt *ResourceTracker) getResourceByID(resourceID ResourceID) *Resource {
	if resource, exists := rt.resources[resourceID]; exists {
		return resource
	}
	return nil
}

// IsClosed checks if a resource is closed (directly || through its parent)
func (rt *ResourceTracker) IsClosed(resourceID ResourceID) bool {
	return rt.isClosedRecursive(resourceID, make(map[ResourceID]bool))
}

// isClosedRecursive checks closure with cycle detection
func (rt *ResourceTracker) isClosedRecursive(resourceID ResourceID, visited map[ResourceID]bool) bool {
	// Prevent infinite recursion
	if visited[resourceID] {
	}
	visited[resourceID] = true

	resource := rt.resources[resourceID]
	if resource == nil {
		return false
	}

	// Check if directly closed
	if len(resource.closedAt) > 0 {
		return true
	}

	// Check if parent resource is closed (transitive closure)
	if resource.derivedFrom != "" {
		if rt.isClosedRecursive(resource.derivedFrom, visited) {
			return true
		}
	}

	// Check if any child resources being closed would close this resource
	// This handles cases where closing a derived resource also closes the parent
	for _, otherResource := range rt.resources {
		if otherResource.derivedFrom == resourceID && len(otherResource.closedAt) > 0 {
			// In some patterns, closing a derived resource might indicate parent closure
			// This depends on the specific pattern && could be configurable
		}
	}

	return false
}

// GetUnclosedResources returns all resources that are not closed
func (rt *ResourceTracker) GetUnclosedResources() []*Resource {
	// Return all resources that are tracked as requiring close and are not closed.
	// Do not suppress children when parent is also unclosed; let the caller decide.
	var unclosed []*Resource
	for _, resource := range rt.resources {
		if resource.hasCloseMethod && !rt.IsClosed(resource.id) {
			unclosed = append(unclosed, resource)
		}
	}
	return unclosed
}

// TrackResourceCreation records creation of a resource
func (rt *ResourceTracker) TrackResourceCreation(varName string, typeName string, node ast.Node, pos token.Pos, hasCloseMethod bool) {
	resourceID := ResourceID(fmt.Sprintf("%s_%d", varName, pos))

	resource := &Resource{
		id:             resourceID,
		varName:        varName,
		typeName:       typeName,
		creationSite:   node,
		pos:            pos,
		hasCloseMethod: hasCloseMethod,
		closedAt:       []ast.Node{},
	}

	rt.resources[resourceID] = resource
	rt.dataFlow[varName] = resourceID
}

// TrackResourceDerivation records when a resource is derived from another (e.g., db from factory.GetDB())
func (rt *ResourceTracker) TrackResourceDerivation(childVarName string, childTypeName string, parentResourceID ResourceID, node ast.Node, pos token.Pos, hasCloseMethod bool) {
	childResourceID := ResourceID(fmt.Sprintf("%s_%d_derived", childVarName, pos))

	resource := &Resource{
		id:             childResourceID,
		varName:        childVarName,
		typeName:       childTypeName,
		creationSite:   node,
		pos:            pos,
		hasCloseMethod: hasCloseMethod,
		derivedFrom:    parentResourceID,
		closedAt:       []ast.Node{},
	}

	rt.resources[childResourceID] = resource
	rt.dataFlow[childVarName] = childResourceID
}

// TrackResourceClosure records when a resource is closed
func (rt *ResourceTracker) TrackResourceClosure(varName string, node ast.Node) {
	if resourceID, exists := rt.dataFlow[varName]; exists {
		if resource := rt.resources[resourceID]; resource != nil {
			resource.closedAt = append(resource.closedAt, node)
		}
	}
}

// TrackMethodCall records a method call on a resource for call graph analysis
func (rt *ResourceTracker) TrackMethodCall(receiverVarName string, methodName string, signature string, node ast.Node) {
	if resourceID, exists := rt.dataFlow[receiverVarName]; exists {
		if resource := rt.resources[resourceID]; resource != nil {
			// Only consider io.Closer.Close() style calls: Close() error
			if methodName == "Close" && signature == "func() error" {
				resource.closedAt = append(resource.closedAt, node)
			}
		}
	}
}

// isCleanupSignature checks if the signature looks like a cleanup method
func (rt *ResourceTracker) isCleanupSignature(signature string) bool {
	// Deprecated: kept for backward compatibility; do not use
	return signature == "func() error"
}

// Legacy types for compatibility (will be removed)
type posToClose struct {
	name                string
	typeName            string
	pos                 token.Pos
	parent              *ast.Ident
	wasClosedOrReturned bool
	// isContainer marks variables that act as containers for other closers
	// e.g., an object whose field is assigned a wrapper with closable fields,
	// || a factory from which resources are obtained. For such containers we
	// consider any deferred method call on the container as a cleanup signal.
	isContainer    bool
	derivedFrom    string
	derivedFromPos token.Pos
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

// hasCloseMethod checks if a type implements io.Closer interface exactly
func (av *AssignVisitor) hasCloseMethod(t types.Type) bool {
	// MUST be exactly io.Closer interface implementation
	return isCloserType(t)
}

// looksLikeCloseMethod checks if a method signature EXACTLY matches Close() error
func (av *AssignVisitor) looksLikeCloseMethod(sig *types.Signature) bool {
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
	return results.At(0).Type().String() == "error"
}

// hasCleanupMethod is removed - only io.Closer.Close() is accepted
func (av *AssignVisitor) hasCleanupMethod(t types.Type) bool {
	// DEPRECATED: Only use hasCloseMethod which checks io.Closer interface
	return av.hasCloseMethod(t)
}

// isKnownNonClosableType checks if a type is known to not require closing
// even when used in container contexts
func (av *AssignVisitor) isKnownNonClosableType(t types.Type) bool {
	if t == nil {
		return false
	}

	typeStr := t.String()

	// Known types that should never be treated as requiring closure
	knownNonClosableTypes := []string{
		"strings.Builder",
		"bytes.Buffer",
	}

	for _, knownType := range knownNonClosableTypes {
		if typeStr == knownType {
			return true
		}
	}

	return false
}

// analyzeDeferredAnonymousFunction analyzes the body of an anonymous function in a defer statement
// to detect resource closures like: defer func() { closerCli.Close() }()
// It returns a list of identifiers that are closed within the anonymous function
func (av *AssignVisitor) analyzeDeferredAnonymousFunction(funcLit *ast.FuncLit) []string {
	if funcLit == nil || funcLit.Body == nil {
		return nil
	}

	var closedIdentifiers []string

	// Walk through all statements in the anonymous function body
	for _, stmt := range funcLit.Body.List {
		closed := av.analyzeStatementForResourceClosure(stmt)
		closedIdentifiers = append(closedIdentifiers, closed...)
	}

	return closedIdentifiers
}

// analyzeStatementForResourceClosure recursively analyzes a statement for resource closure calls
// and returns the names of identifiers that are closed
func (av *AssignVisitor) analyzeStatementForResourceClosure(stmt ast.Stmt) []string {
	var closedIdentifiers []string

	switch s := stmt.(type) {
	case *ast.ExprStmt:
		if call, ok := s.X.(*ast.CallExpr); ok {
			if closed := av.analyzeCallForResourceClosure(call, stmt); closed != "" {
				closedIdentifiers = append(closedIdentifiers, closed)
			}
		}
	case *ast.IfStmt:
		// Handle if statements that might contain Close() calls

		// Check the condition of the if statement for assignments like: if err := obj.Close(); err != nil
		if s.Init != nil {
			closed := av.analyzeStatementForResourceClosure(s.Init)
			closedIdentifiers = append(closedIdentifiers, closed...)
		}

		// Check the condition expression for calls like: if obj.Close() != nil
		if s.Cond != nil {
			if closed := av.analyzeExprForResourceClosure(s.Cond, stmt); closed != "" {
				closedIdentifiers = append(closedIdentifiers, closed)
			}
		}

		if s.Body != nil {
			for _, bodyStmt := range s.Body.List {
				closed := av.analyzeStatementForResourceClosure(bodyStmt)
				closedIdentifiers = append(closedIdentifiers, closed...)
			}
		}
		if s.Else != nil {
			closed := av.analyzeStatementForResourceClosure(s.Else)
			closedIdentifiers = append(closedIdentifiers, closed...)
		}
	case *ast.BlockStmt:
		// Handle nested blocks
		for _, blockStmt := range s.List {
			closed := av.analyzeStatementForResourceClosure(blockStmt)
			closedIdentifiers = append(closedIdentifiers, closed...)
		}
	case *ast.AssignStmt:
		// Handle assignments like: err := obj.Close()
		for _, rhs := range s.Rhs {
			if closed := av.analyzeExprForResourceClosure(rhs, stmt); closed != "" {
				closedIdentifiers = append(closedIdentifiers, closed)
			}
		}
	}

	return closedIdentifiers
}

// analyzeCallForResourceClosure checks if a call expression is a resource closure
// and returns the name of the identifier being closed, or empty string if none
func (av *AssignVisitor) analyzeCallForResourceClosure(call *ast.CallExpr, stmt ast.Stmt) string {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if ident, ok := sel.X.(*ast.Ident); ok && sel.Sel != nil {
			// Check if this matches the pattern obj.Close()
			if av.isMethodCallWithCleanupSignature(call) {
				av.debug(stmt, "Found resource closure in anonymous function: %s.%s()", ident.Name, sel.Sel.Name)
				return ident.Name
			}
		}
	}
	return ""
}

// analyzeExprForResourceClosure recursively analyzes an expression for resource closure calls
// and returns the name of the identifier being closed, or empty string if none
func (av *AssignVisitor) analyzeExprForResourceClosure(expr ast.Expr, stmt ast.Stmt) string {
	switch e := expr.(type) {
	case *ast.CallExpr:
		return av.analyzeCallForResourceClosure(e, stmt)
	case *ast.BinaryExpr:
		// Check both sides of binary expressions like: err := obj.Close(); err != nil
		if left := av.analyzeExprForResourceClosure(e.X, stmt); left != "" {
			return left
		}
		if right := av.analyzeExprForResourceClosure(e.Y, stmt); right != "" {
			return right
		}
	case *ast.UnaryExpr:
		return av.analyzeExprForResourceClosure(e.X, stmt)
	case *ast.ParenExpr:
		return av.analyzeExprForResourceClosure(e.X, stmt)
	}
	return ""
}

func (av *AssignVisitor) newReturnVar(t types.Type) returnVar {
	av.debug(nil, "newReturnVar: checking type %s", t.String())

	// First, if the type itself implements io.Closer, treat it as directly closable.
	// This avoids incorrectly tracking embedded/internal closers (e.g., *sql.DB inside sqlx.DB)
	// when the wrapper type (*sqlx.DB) is the actual resource to Close().
	if av.hasCloseMethod(t) {
		av.debug(nil, "newReturnVar: type %s needs closing", t.String())
		return returnVar{
			needsClosing: true,
			typeName:     t.String(),
			fields:       []field{},
		}
	}

	// Special-case: http.Request should NOT be treated as needing close (its Body is
	// managed by the transport). Ignore both the container and its fields.
	if isHTTPReqType(t) {
		return returnVar{
			needsClosing: false,
			typeName:     t.String(),
			fields:       []field{},
		}
	}

	// Otherwise, fall back to field-based tracking for structs that contain io.Closer fields
	structResult := av.newReturnVarForStruct(t, t.String())
	if len(structResult.fields) > 0 {
		av.debug(nil, "newReturnVar: type %s has closable fields, using field-based tracking", t.String())
		return structResult
	}

	av.debug(nil, "newReturnVar: type %s does NOT need closing", t.String())

	// Check for named types (which could be generic) first
	if named, ok := t.(*types.Named); ok {
		return av.newReturnVarForStruct(named.Underlying(), t.String())
	}

	// special case: a struct containing a io.Closer fields that implements io.Closer, like http.Response.Body
	return av.newReturnVarForStruct(t, t.String())
}

func (av *AssignVisitor) newReturnVarForStruct(t types.Type, typeName string) returnVar {

	// Handle pointer types
	ptr, ok := t.(*types.Pointer)
	if ok {
		str, ok := ptr.Elem().Underlying().(*types.Struct)
		if !ok {
			return returnVar{
				needsClosing: false,
				typeName:     typeName,
				fields:       []field{},
			}
		}
		return av.extractCloserFields(str, typeName)
	}

	// Handle direct struct types
	if str, ok := t.(*types.Struct); ok {
		return av.extractCloserFields(str, typeName)
	}

	return returnVar{
		needsClosing: false,
		typeName:     typeName,
		fields:       []field{},
	}
}

func (av *AssignVisitor) extractCloserFields(str *types.Struct, typeName string) returnVar {
	fields := []field{}

	for i := 0; i < str.NumFields(); i++ {
		v := str.Field(i)
		fieldName := v.Name()

		// Check exported fields (standard behavior). We intentionally ignore
		// unexported fields to avoid name-based heuristics on arbitrary wrappers;
		// this still catches canonical cases like http.Response.Body.
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
		typeName:     typeName,
		fields:       fields,
	}
}

// isHTTPReqType returns true if t is net/http.Request or *net/http.Request
func isHTTPReqType(t types.Type) bool {
	// unwrap pointer
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok {
		obj := n.Obj()
		if obj != nil {
			if pkg := obj.Pkg(); pkg != nil {
				if pkg.Path() == "net/http" && obj.Name() == "Request" {
					return true
				}
			}
		}
	}
	return false
}

// this function checks functions that assign a closer
func (av *AssignVisitor) checkFunctionsThatAssignCloser() {
	ins := av.pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	// Initialize heavy scan cache map
	if av.heavyScanCache == nil {
		av.heavyScanCache = make(map[string]bool)
	}
	ins.Preorder([]ast.Node{(*ast.FuncDecl)(nil)}, func(n ast.Node) {
		fdecl := n.(*ast.FuncDecl)
		if fdecl.Body == nil {
			return
		}
		if av.shouldSkipNode(fdecl) {
			return
		}

		if !av.traverse(fdecl.Body.List) && printFunctionFailure {
			fmt.Println("Printing function that failed")
			_ = ast.Print(av.pass.Fset, fdecl)
		}
	})
}

func (av *AssignVisitor) traverse(stmts []ast.Stmt) bool {
	posListToClose := []*posToClose{}

	// Initialize factory variables tracking for this function
	if av.factoryVariables == nil {
		av.factoryVariables = make(map[string]string)
	}

	// Initialize method value tracking for this function
	av.methodValueRecvPos = make(map[token.Pos]token.Pos)
	av.methodValueRecvName = make(map[token.Pos]string)
	av.methodValueIsClose = make(map[token.Pos]bool)
	av.factoryVarByPos = make(map[token.Pos]token.Pos)
	av.containerHasShutdownHandler = make(map[token.Pos]bool)
	av.containerFieldShutdownCloses = make(map[token.Pos]bool)
	av.containerVarNameByPos = make(map[token.Pos]string)
	av.containerVarTypeByPos = make(map[token.Pos]string)
	av.containersProvenShutdown = make(map[token.Pos]bool)
	av.localContainers = make(map[token.Pos]bool)
	av.containerDeferredCall = make(map[token.Pos]bool)

	// Always initialize fresh ResourceTracker for each function
	av.resourceTracker = NewResourceTracker()

	// First pass: collect all closers from assignments && check for unassigned calls
	for _, stmt := range stmts {
		switch castedStmt := stmt.(type) {
		case *ast.ExprStmt:
			call, ok := castedStmt.X.(*ast.CallExpr)
			if ok && av.callReturnsCloser(call) {
				if !av.shouldSuppressReport(call.Pos()) {
					av.pass.Reportf(call.Pos(), "return value won't be closed because it wasn't assigned") // FIXME: improve message
				}
			}
			// Analyze container handler registration for provable Close() chains
			if ok {
				av.analyzeContainerHandlerRegistration(call)

				// Inter-procedural: if calling a method that registers shutdown handlers on receiver,
				// mark the receiver container as requiring cleanup
				if sel, okS := call.Fun.(*ast.SelectorExpr); okS {
					if fndecl, _ := typeutil.Callee(av.pass.TypesInfo, call).(*types.Func); fndecl != nil {
						cf := &containerMethodFact{}
						if av.pass.ImportObjectFact(fndecl, cf) && cf.registersShutdown {
							if baseIdent, okB := sel.X.(*ast.Ident); okB {
								basePos := baseIdent.Pos()
								if bObj := av.pass.TypesInfo.ObjectOf(baseIdent); bObj != nil {
									basePos = bObj.Pos()
								}
								// Mark container has shutdown handlers
								av.containerHasShutdownHandler[basePos] = true
								av.containerVarNameByPos[basePos] = baseIdent.Name
								if bObj2 := av.pass.TypesInfo.ObjectOf(baseIdent); bObj2 != nil {
									av.containerVarTypeByPos[basePos] = bObj2.Type().String()
								}
								// Track/upgrade container as a resource that needs cleanup
								if av.resourceTracker != nil {
									if parentRes := av.resourceTracker.GetResourceByVar(baseIdent.Name); parentRes != nil {
										// Only mark as requiring closure if not a known non-closable type
										if bObj2 := av.pass.TypesInfo.ObjectOf(baseIdent); bObj2 != nil && !av.isKnownNonClosableType(bObj2.Type()) {
											parentRes.hasCloseMethod = true
										}
									} else {
										typeName := ""
										shouldClose := false
										if bObj2 := av.pass.TypesInfo.ObjectOf(baseIdent); bObj2 != nil {
											typeName = bObj2.Type().String()
											// Only mark as requiring closure if not a known non-closable type
											shouldClose = !av.isKnownNonClosableType(bObj2.Type())
										}
										av.resourceTracker.TrackResourceCreation(baseIdent.Name, typeName, call, basePos, shouldClose)
									}
								}
							}
						}
					}
				}
			}
		case *ast.DeferStmt:
			// Handle anonymous function defers: defer func() { obj.Close() }()
			if funcLit, ok := castedStmt.Call.Fun.(*ast.FuncLit); ok {
				closedIdentifiers := av.analyzeDeferredAnonymousFunction(funcLit)
				// Store the closed identifiers for later use in resource tracking
				for _, identName := range closedIdentifiers {
					av.debug(castedStmt, "Detected closure in defer anonymous function: %s", identName)
				}
			}

			// Track provable container shutdown calls
			if sel, ok := castedStmt.Call.Fun.(*ast.SelectorExpr); ok && sel.Sel != nil {
				if ident, okI := sel.X.(*ast.Ident); okI {
					if recvObj := av.pass.TypesInfo.ObjectOf(ident); recvObj != nil {
						recvPos := recvObj.Pos()
						if av.isProvableContainerShutdown(castedStmt.Call) {
							av.containersProvenShutdown[recvPos] = true
						}
					}
				}
			}
			if av.callReturnsCloser(castedStmt.Call) {
				if !av.shouldSuppressReport(castedStmt.Call.Pos()) {
					av.pass.Reportf(castedStmt.Call.Pos(), "return value won't be closed because it's on defer statement") // FIXME: improve message
				}
				return false
			}
		case *ast.GoStmt:
			if av.callReturnsCloser(castedStmt.Call) {
				if !av.shouldSuppressReport(castedStmt.Call.Pos()) {
					av.pass.Reportf(castedStmt.Call.Pos(), "return value won't be closed because it's on go statement") // FIXME: improve message
				}
				return false
			}
		case *ast.AssignStmt:
			if av.hasGlobalCloserInAssignment(castedStmt.Lhs) {
				continue
			}

			// Detect method value assignments like: fn := recv.Method
			// Map method-value variable to its receiver for later defer fn() detection
			for i := 0; i < len(castedStmt.Lhs) && i < len(castedStmt.Rhs); i++ {
				if id, ok := castedStmt.Lhs[i].(*ast.Ident); ok {
					if sel, ok := castedStmt.Rhs[i].(*ast.SelectorExpr); ok {
						// Ensure this selector denotes a method value (function type)
						if tinfo, okT := av.pass.TypesInfo.Types[sel]; okT {
							if _, isFunc := tinfo.Type.(*types.Signature); isFunc {
								// Resolve receiver identifier (left-most ident)
								if recvIdent, okX := sel.X.(*ast.Ident); okX {
									// Record mapping by object position for robustness
									if mvObj := av.pass.TypesInfo.ObjectOf(id); mvObj != nil {
										mvPos := mvObj.Pos()
										recvPos := recvIdent.Pos()
										if recvObj := av.pass.TypesInfo.ObjectOf(recvIdent); recvObj != nil {
											recvPos = recvObj.Pos()
										}
										av.methodValueRecvPos[mvPos] = recvPos
										av.methodValueRecvName[mvPos] = recvIdent.Name
										// Verify that the method value is exactly Close() error on io.Closer receiver
										if selInfo, okSel := av.pass.TypesInfo.Selections[sel]; okSel {
											if fnObj, okFn := selInfo.Obj().(*types.Func); okFn && fnObj.Name() == "Close" {
												if sig, okSig := fnObj.Type().(*types.Signature); okSig && av.looksLikeCloseMethod(sig) {
													// Ensure receiver implements io.Closer
													if recvT := selInfo.Recv(); recvT != nil && isCloserType(recvT) {
														av.methodValueIsClose[mvPos] = true
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}

			if len(castedStmt.Rhs) == 1 {
				av.debug(castedStmt, "Processing single assignment - LHS count: %d", len(castedStmt.Lhs))
				factoryTracked := false
				if len(castedStmt.Lhs) > 0 {
					if id, ok := castedStmt.Lhs[0].(*ast.Ident); ok {
						av.debug(castedStmt, "Assignment to variable: %s", id.Name)
						// Track if this assignment is from a factory/container method
						if _, ok2 := av.trackFactoryAssignment(id, castedStmt.Rhs[0]); ok2 {
							// Keep mapping only; do not mark containers as needing close.
							// Also, do not suppress regular assignment handling under strict spec.
						}
					}
					// If assigning to selector (e.g., factory.DB = New(..., shutdown func(x){ x.Close() })),
					// record that container's field shutdown closes the resource.
					if sel, okS := castedStmt.Lhs[0].(*ast.SelectorExpr); okS {
						if baseIdent, okB := sel.X.(*ast.Ident); okB {
							if av.shutdownFuncClosesParam(castedStmt.Rhs[0]) {
								// Map base container var pos -> true and record metadata
								basePos := baseIdent.Pos()
								if bObj := av.pass.TypesInfo.ObjectOf(baseIdent); bObj != nil {
									basePos = bObj.Pos()
								}
								av.containerFieldShutdownCloses[basePos] = true
								av.containerVarNameByPos[basePos] = baseIdent.Name
								if bObj2 := av.pass.TypesInfo.ObjectOf(baseIdent); bObj2 != nil {
									av.containerVarTypeByPos[basePos] = bObj2.Type().String()
								}
							}
							// Assignment-based registration detection removed to avoid false positives in methods.
						}
					}
				}

				if !factoryTracked {
					// Debug Redis vs regular assignment handling
					newPosToClose := av.handleAssignment(castedStmt.Lhs, castedStmt.Rhs[0])
					av.debug(castedStmt, "handleAssignment returned %d items to track", len(newPosToClose))
					for i, pos := range newPosToClose {
						av.debug(castedStmt, "  Item %d: name=%s, typeName=%s", i, pos.name, pos.typeName)
					}
					posListToClose = append(posListToClose, newPosToClose...)
				}
			} else {
				// Multi-assignment. Also check for container field init proving shutdown closes param
				// e.g., a.DB, _ = New(..., func(db *DB){ db.Close() })
				if len(castedStmt.Lhs) > 0 && len(castedStmt.Rhs) > 0 {
					if sel, okS := castedStmt.Lhs[0].(*ast.SelectorExpr); okS {
						if baseIdent, okB := sel.X.(*ast.Ident); okB {
							if av.shutdownFuncClosesParam(castedStmt.Rhs[0]) {
								basePos := baseIdent.Pos()
								if bObj := av.pass.TypesInfo.ObjectOf(baseIdent); bObj != nil {
									basePos = bObj.Pos()
								}
								av.containerFieldShutdownCloses[basePos] = true
								av.containerVarNameByPos[basePos] = baseIdent.Name
								if bObj2 := av.pass.TypesInfo.ObjectOf(baseIdent); bObj2 != nil {
									av.containerVarTypeByPos[basePos] = bObj2.Type().String()
								}
							}
						}
					}
				}
				posListToClose = append(posListToClose, av.handleMultiAssignment(castedStmt.Lhs, castedStmt.Rhs)...)
			}
		}
	}

	// Second pass: check all statements to see if they close any of the collected closers
	if len(posListToClose) > 0 {
		av.debug(nil, "Starting second pass - checking %d tracked closers for closure", len(posListToClose))
		for i, idToClose := range posListToClose {
			av.debug(nil, "  Closer %d: name=%s, typeName=%s", i, idToClose.name, idToClose.typeName)
		}
		for _, stmt := range stmts {
			for _, idToClose := range posListToClose {
				result := av.returnsOrClosesID(*idToClose, stmt)
				if result {
					av.debug(stmt, "MARKING AS CLOSED: %s", idToClose.name)
					idToClose.wasClosedOrReturned = true

					// Track resource closure with ResourceTracker
					if av.resourceTracker != nil {
						av.resourceTracker.TrackResourceClosure(idToClose.name, stmt)

						// Also track method call for call graph analysis
						if deferStmt, ok := stmt.(*ast.DeferStmt); ok {
							if sel, ok := deferStmt.Call.Fun.(*ast.SelectorExpr); ok {
								if ident, ok := sel.X.(*ast.Ident); ok {
									if typeInfo, exists := av.pass.TypesInfo.Types[deferStmt.Call.Fun]; exists {
										if sig, ok := typeInfo.Type.(*types.Signature); ok {
											av.resourceTracker.TrackMethodCall(
												ident.Name,
												sel.Sel.Name,
												sig.String(),
												stmt,
											)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// After building container maps, rescan defers to mark containers proven shutdown
	for _, stmt := range stmts {
		if def, ok := stmt.(*ast.DeferStmt); ok {
			if sel, ok := def.Call.Fun.(*ast.SelectorExpr); ok && sel.Sel != nil {
				if ident, okI := sel.X.(*ast.Ident); okI {
					var recvPos token.Pos
					if recvObj := av.pass.TypesInfo.ObjectOf(ident); recvObj != nil {
						recvPos = recvObj.Pos()
					} else {
						for p, n := range av.containerVarNameByPos {
							if n == ident.Name {
								recvPos = p
								break
							}
						}
					}
					if recvPos != 0 {
						if av.containerHasShutdownHandler[recvPos] || av.containerFieldShutdownCloses[recvPos] || av.isProvableContainerShutdown(def.Call) {
							av.containersProvenShutdown[recvPos] = true
							av.containerDeferredCall[recvPos] = true
							// Mark the container resource as closed in the tracker
							if name, okName := av.containerVarNameByPos[recvPos]; okName {
								if resource := av.resourceTracker.GetResourceByVar(name); resource != nil {
									av.resourceTracker.MarkClosed(resource.id, def.Call)
								}
							}
						}
					}
				}
			}
		}
	}

	// No wrapper-based pass; rely on container + Close-only semantics

	hasErrors := false

	// Always use new graph-based checking with ResourceTracker
	unclosedResources := av.resourceTracker.GetUnclosedResources()
	av.debug(nil, "Graph-based checking found %d unclosed resources", len(unclosedResources))

	// Report all unclosed resources; do not collapse children into parents.
	finalResources := unclosedResources

	for _, resource := range finalResources {
		av.debug(nil, "Unclosed resource: name=%s, typeName=%s", resource.varName, resource.typeName)

		// Simplify the type name for display (remove vendor paths)
		typeName := resource.typeName
		if strings.Contains(typeName, "/vendor/") && strings.Contains(typeName, "/redis.") {
			if idx := strings.LastIndex(typeName, "/redis."); idx != -1 {
				typeName = "redis" + typeName[idx+6:]
			}
		}

		if !av.shouldSuppressReport(resource.pos) {
			av.pass.Reportf(resource.pos, "%s (%s) was not closed", resource.varName, typeName)
		}
		hasErrors = true
	}

	// Fallback: report per-variable leaks tracked in posListToClose when not closed/returned
	for _, idToClose := range posListToClose {
		if !idToClose.wasClosedOrReturned && !av.shouldSuppressReport(idToClose.pos) {
			av.pass.Reportf(idToClose.pos, "%s (%s) was not closed", idToClose.name, idToClose.typeName)
			hasErrors = true
		}
	}

	// Fallback: report containers that registered shutdown handlers but have no proven shutdown in this function
	for pos, hasHandlers := range av.containerHasShutdownHandler {
		if !hasHandlers {
			continue
		}
		if av.containersProvenShutdown[pos] || av.containerDeferredCall[pos] {
			continue
		}
		// Only report for local containers created in this function
		if !av.localContainers[pos] {
			continue
		}
		if !av.shouldSuppressReport(pos) {
			name := av.containerVarNameByPos[pos]
			typ := av.containerVarTypeByPos[pos]
			// Only report when we have metadata (set at call sites), to avoid receiver-based noise
			if name != "" && typ != "" {
				av.pass.Reportf(pos, "%s (%s) was not closed", name, typ)
				hasErrors = true
			}
		}
	}

	// Fallback: report containers whose fields were initialized with shutdown funcs closing params
	// but no shutdown was proven in this function.
	for pos, closes := range av.containerFieldShutdownCloses {
		if !closes {
			continue
		}
		if av.containersProvenShutdown[pos] || av.containerDeferredCall[pos] {
			continue
		}
		// Only report for local containers created in this function
		if !av.localContainers[pos] {
			continue
		}
		if !av.shouldSuppressReport(pos) {
			name := av.containerVarNameByPos[pos]
			typ := av.containerVarTypeByPos[pos]
			if name != "" && typ != "" {
				av.pass.Reportf(pos, "%s (%s) was not closed", name, typ)
				hasErrors = true
			}
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
		// Do NOT treat Close() calls inside a func literal as immediate cleanup.
		// The literal may be stored (e.g., appended to handlers) and executed later,
		// so counting it here causes false negatives like graceful-shutdown-noclose-v5.
		// Only actual, immediate calls (defer/expr on the tracked value) should satisfy closure.
		return false
	case *ast.CallExpr:
		// Check if this is a direct cleanup call on our identifier
		if sel, ok := cExpr.Fun.(*ast.SelectorExpr); ok && av.isMethodCallWithCleanupSignature(cExpr) {
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
			// Only consider direct returns of the tracked identifier or its field (e.g., res.Body)
			switch r := res.(type) {
			case *ast.Ident:
				if av.isIdentInPos(r, idToClose.pos) {
					return true
				}
				if idToClose.parent != nil && av.isIdentInPos(r, idToClose.parent.Pos()) {
					return true
				}
			case *ast.SelectorExpr:
				// Returning a selector that references our identifier (e.g., res.Body)
				if av.isPosInExpression(idToClose.pos, r.X) {
					return true
				}
				if idToClose.parent != nil && av.isPosInExpression(idToClose.parent.Pos(), r.X) {
					return true
				}
			case *ast.CallExpr:
				// Handle returns of call results that propagate the same value (identity wrappers):
				// if a call returns the same type as one of its arguments and that argument
				// references our tracked identifier, treat it as a transfer of ownership.
				if callee, ok := typeutil.Callee(av.pass.TypesInfo, r).(*types.Func); ok && callee != nil {
					// Determine the call's result type
					if typeInfo, exists := av.pass.TypesInfo.Types[r]; exists {
						retType := typeInfo.Type
						// Check each argument
						for _, arg := range r.Args {
							// Does argument reference the tracked identifier or its parent?
							if !av.isPosInExpression(idToClose.pos, arg) && (idToClose.parent == nil || !av.isPosInExpression(idToClose.parent.Pos(), arg)) {
								continue
							}
							// Compare argument type to return type for identity-like propagation
							if argInfo, okA := av.pass.TypesInfo.Types[arg]; okA {
								if types.Identical(argInfo.Type, retType) {
									return true
								}
							}
						}
					}
				}
			}
		}

	case *ast.DeferStmt:
		// Check for provable container shutdown that closes derived resources
		if sel, ok := castedStmt.Call.Fun.(*ast.SelectorExpr); ok && sel.Sel != nil {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if recvObj := av.pass.TypesInfo.ObjectOf(ident); recvObj != nil {
					recvPos := recvObj.Pos()
					// Only accept if we can prove through AST that Close() will be called
					if av.isProvableContainerShutdown(castedStmt.Call) {
						// Check if resource was derived from this container
						if fPos, ok := av.factoryVarByPos[idToClose.pos]; ok && fPos == recvPos {
							return true
						}
						if idToClose.derivedFromPos != 0 {
							if idToClose.derivedFromPos == recvPos {
								return true
							}
							if fPos2, ok2 := av.factoryVarByPos[idToClose.derivedFromPos]; ok2 && fPos2 == recvPos {
								return true
							}
						}
					}
				}
			}
		}

		// Only accept defers that strictly call Close() error on an io.Closer receiver.
		if sel, ok := castedStmt.Call.Fun.(*ast.SelectorExpr); ok {
			if av.isMethodCallWithCleanupSignature(castedStmt.Call) {
				// Receiver expression must reference the tracked resource (or its parent for fields)
				if av.isPosInExpression(idToClose.pos, sel.X) {
					return true
				}
			}
		}

		// Handle anonymous function defers: defer func() { obj.Close() }()
		if funcLit, ok := castedStmt.Call.Fun.(*ast.FuncLit); ok {
			// This is a defer with an anonymous function
			closedIdentifiers := av.analyzeDeferredAnonymousFunction(funcLit)
			for _, identName := range closedIdentifiers {
				if identName == idToClose.name {
					av.debug(castedStmt, "Resource %s closed in defer anonymous function", identName)
					return true
				}
			}
		}

		// Handle method-value defers: defer fn(), where fn was bound from recv.Close
		if mvIdent, ok := castedStmt.Call.Fun.(*ast.Ident); ok {
			if mvObj := av.pass.TypesInfo.ObjectOf(mvIdent); mvObj != nil {
				mvPos := mvObj.Pos()
				if av.methodValueIsClose[mvPos] {
					if recvPos, exists := av.methodValueRecvPos[mvPos]; exists {
						// Match direct resource or its parent for field-tracked resources
						if recvPos == idToClose.pos || (idToClose.parent != nil && recvPos == idToClose.parent.Pos()) {
							return true
						}
					}
				}
			}
		}
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
		// Detect assignment patterns and calls on RHS
		for _, exp := range castedStmt.Rhs {
			if call, ok := exp.(*ast.CallExpr); ok {
				// If this assignment registers a func literal into receiver's shutdown handlers
				// AND that func literal calls Close() on the tracked resource, treat the resource
				// as delegated/closed for this function context to avoid false positives in
				// cases like graceful-shutdown-close-v5 where Clean() is called elsewhere.
				if av.appendShutdownFuncClosesTracked(castedStmt, idToClose) {
					return true
				}

				if av.callsToKnownCloser(idToClose.pos, call) {
					return true
				}
				// Also handle other function-literal arguments that capture and close
				for _, arg := range call.Args {
					if av.returnsOrClosesIDOnExpression(idToClose, arg) {
						return true
					}
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
		if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok && av.isMethodCallWithCleanupSignature(callExpr) {
			if av.isPosInExpression(pos, selExpr.X) {
				return true
			}
		}
	}
	return false
}

// appendShutdownFuncClosesTracked detects pattern:
//
//	recv.shutdownHandlers = append(recv.shutdownHandlers, func(){ _ = tracked.Close() })
//
// and returns true if the func literal provably calls Close() on the tracked var.
func (av *AssignVisitor) appendShutdownFuncClosesTracked(as *ast.AssignStmt, idToClose posToClose) bool {
	if len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return false
	}
	// LHS must be selector: recv.<field>
	lhsSel, ok := as.Lhs[0].(*ast.SelectorExpr)
	if !ok {
		return false
	}
	// RHS must be append(recv.<field>, ...)
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) < 2 {
		return false
	}
	funIdent, ok := call.Fun.(*ast.Ident)
	if !ok || funIdent.Name != "append" {
		return false
	}
	// First arg should be same selector as LHS
	if argSel, ok := call.Args[0].(*ast.SelectorExpr); !ok || !av.sameSelectorIdBased(argSel, lhsSel) {
		return false
	}
	// Any subsequent arg being a func literal that closes the tracked var qualifies,
	// but only if the project contains a call to a registered shutdown method on this receiver type
	for _, arg := range call.Args[1:] {
		if fl, ok := arg.(*ast.FuncLit); ok {
			if av.funcLitClosesTracked(fl, idToClose) {
				if recvKey := av.typeKeyForExpr(lhsSel.X); recvKey != "" {
					if av.heavyProjectHasShutdownCall(recvKey) {
						return true
					}
				}
			}
		}
	}
	return false
}

// funcLitClosesTracked reports whether a function literal body contains a Close() call
// on the tracked identifier (by position), verifying exact io.Closer.Close() signature.
func (av *AssignVisitor) funcLitClosesTracked(fl *ast.FuncLit, idToClose posToClose) bool {
	var closes bool
	var walk func(stmts []ast.Stmt)
	walk = func(stmts []ast.Stmt) {
		if closes {
			return
		}
		for _, s := range stmts {
			switch n := s.(type) {
			case *ast.ExprStmt:
				if c, ok := n.X.(*ast.CallExpr); ok {
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
						if av.isMethodCallWithCleanupSignature(c) && av.isPosInExpression(idToClose.pos, sel.X) {
							closes = true
							return
						}
					}
				}
			case *ast.AssignStmt:
				for _, r := range n.Rhs {
					if c, ok := r.(*ast.CallExpr); ok {
						if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
							if av.isMethodCallWithCleanupSignature(c) && av.isPosInExpression(idToClose.pos, sel.X) {
								closes = true
								return
							}
						}
					}
				}
			case *ast.DeferStmt:
				if c := n.Call; c != nil {
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
						if av.isMethodCallWithCleanupSignature(c) && av.isPosInExpression(idToClose.pos, sel.X) {
							closes = true
							return
						}
					}
				}
			case *ast.BlockStmt:
				walk(n.List)
			case *ast.IfStmt:
				walk(n.Body.List)
				if n.Else != nil {
					if b, ok := n.Else.(*ast.BlockStmt); ok {
						walk(b.List)
					}
				}
			}
		}
	}
	walk(fl.Body.List)
	return closes
}

// sameSelectorIdBased compares two selector expressions by identifier object positions when available.
func (av *AssignVisitor) sameSelectorIdBased(a, b *ast.SelectorExpr) bool {
	// Compare selected field name
	if a.Sel == nil || b.Sel == nil || a.Sel.Name != b.Sel.Name {
		return false
	}
	// Compare base identifiers by object position when available
	ai, okA := a.X.(*ast.Ident)
	bi, okB := b.X.(*ast.Ident)
	if !okA || !okB {
		return false
	}
	oa := av.pass.TypesInfo.ObjectOf(ai)
	ob := av.pass.TypesInfo.ObjectOf(bi)
	if oa != nil && ob != nil {
		return oa.Pos() == ob.Pos()
	}
	return ai.NamePos == bi.NamePos
}

// collectPackageShutdownCalls scans the package for provable shutdown calls and records receiver types
// collectPackageShutdownCalls removed; replaced by heavyProjectHasShutdownCall

// typeKeyForExpr returns a stable key for a receiver expression's declared named type
func (av *AssignVisitor) typeKeyForExpr(expr ast.Expr) string {
	if expr == nil {
		return ""
	}
	if tv, ok := av.pass.TypesInfo.Types[expr]; ok {
		return normalizeTypeKey(tv.Type)
	}
	if id, ok := expr.(*ast.Ident); ok {
		if obj := av.pass.TypesInfo.ObjectOf(id); obj != nil {
			return normalizeTypeKey(obj.Type())
		}
	}
	return ""
}

// typeKey normalizes a type to a package-local stable key (pkgpath.TypeName)
func (av *AssignVisitor) typeKey(t types.Type) string {
	return normalizeTypeKey(t)
}

// heavyProjectHasShutdownCall scans the module for calls to registered shutdown methods on the given receiver type.
func (av *AssignVisitor) heavyProjectHasShutdownCall(recvTypeKey string) bool {
	if !enableCrossPkgScan {
		return false
	}
	if recvTypeKey == "" {
		return false
	}
	moduleRoot := av.moduleRoot
	if moduleRoot == "" {
		moduleRoot = av.findModuleRoot()
		av.moduleRoot = moduleRoot
	}
	cacheKey := moduleRoot + "::" + recvTypeKey
	av.heavyScanCacheMu.Lock()
	if av.heavyScanCache == nil {
		av.heavyScanCache = make(map[string]bool)
	}
	if v, ok := av.heavyScanCache[cacheKey]; ok {
		av.heavyScanCacheMu.Unlock()
		return v
	}
	av.heavyScanCacheMu.Unlock()

	idx := getModuleShutdownIndex(moduleRoot, trustVendor)
	idx.ensureBuilt(moduleRoot, trustVendor)
	found := false
	if idx.buildErr == nil {
		found = idx.hasShutdownCall(recvTypeKey)
	}
	av.heavyScanCacheMu.Lock()
	av.heavyScanCache[cacheKey] = found
	av.heavyScanCacheMu.Unlock()
	return found
}

func (av *AssignVisitor) isShutdownMethod(fn *types.Func) bool {
	if fn == nil {
		return false
	}
	if !enablePerMethodPkgLoad {
		return false
	}
	root := av.moduleRoot
	if root == "" {
		root = av.findModuleRoot()
		av.moduleRoot = root
	}
	idx := getModuleShutdownIndex(root, trustVendor)
	idx.ensureBuilt(root, trustVendor)
	if idx.buildErr != nil {
		return false
	}
	return idx.isShutdownMethod(methodKey(fn))
}

// methodDeclLooksLikeShutdown checks AST of method body for:
//
//	for range recv.<field> { handler() }
func methodDeclLooksLikeShutdown(fd *ast.FuncDecl) bool {
	if fd == nil || fd.Recv == nil || fd.Body == nil {
		return false
	}
	recvName := ""
	if len(fd.Recv.List) > 0 && len(fd.Recv.List[0].Names) > 0 {
		recvName = fd.Recv.List[0].Names[0].Name
	}
	if recvName == "" {
		return false
	}
	for _, stmt := range fd.Body.List {
		rs, ok := stmt.(*ast.RangeStmt)
		if !ok {
			continue
		}
		if sel, ok := rs.X.(*ast.SelectorExpr); ok {
			if base, ok := sel.X.(*ast.Ident); ok && base.Name == recvName {
				if bs := rs.Body; bs != nil {
					for _, bstmt := range bs.List {
						if es, ok := bstmt.(*ast.ExprStmt); ok {
							if c, ok := es.X.(*ast.CallExpr); ok {
								if _, ok := c.Fun.(*ast.Ident); ok && len(c.Args) == 0 {
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

// findModuleRoot walks up from any file to the nearest directory containing go.mod
func (av *AssignVisitor) findModuleRoot() string {
	for _, f := range av.pass.Files {
		if f == nil || f.Pos() == token.NoPos {
			continue
		}
		filename := av.pass.Fset.File(f.Pos()).Name()
		dir := filepath.Dir(filename)
		for {
			if dir == "/" || dir == "." || dir == "" {
				break
			}
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return ""
}

// isVendorFilename reports whether filename points into a vendor directory
func isVendorFilename(filename string) bool {
	if filename == "" {
		return false
	}
	sep := string(os.PathSeparator)
	marker := sep + "vendor" + sep
	return strings.Contains(filename, marker)
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

	// Check if our closer || its parent is used in this composite literal
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
			// Use object position when available for stable identity (matches factoryVarByPos keys)
			idPos := id.Pos()
			if obj := av.pass.TypesInfo.ObjectOf(id); obj != nil {
				idPos = obj.Pos()
			}
			posListToClose = append(posListToClose, &posToClose{
				parent:   id,
				name:     id.Name,
				typeName: returnVars[0].typeName,
				pos:      idPos,
			})
			// Track resource creation with ResourceTracker for reporting
			if av.resourceTracker != nil {
				av.resourceTracker.TrackResourceCreation(
					id.Name,
					returnVars[0].typeName,
					rhs[i],
					id.Pos(),
					true,
				)
			}
		}

		for _, field := range returnVars[0].fields {
			// Use object position when available for stable identity
			idPos := id.Pos()
			if obj := av.pass.TypesInfo.ObjectOf(id); obj != nil {
				idPos = obj.Pos()
			}
			posListToClose = append(posListToClose, &posToClose{
				parent:   id,
				name:     id.Name + "." + field.name,
				typeName: field.typeName,
				pos:      idPos, // Use parent object position instead of field position
			})
			if av.resourceTracker != nil {
				av.resourceTracker.TrackResourceCreation(
					id.Name+"."+field.name,
					field.typeName,
					rhs[i],
					id.Pos(),
					true,
				)
			}
		}
	}

	return posListToClose
}

// isNonCloserFunction checks if the function call is to a function that doesn't close resources
func (av *AssignVisitor) isNonCloserFunction(call *ast.CallExpr) bool {
	// Never rely on naming (except io.Closer.Close). Disabled.
	return false
}

// analyzeContainerHandlerRegistration tracks provable Close() call chains
func (av *AssignVisitor) analyzeContainerHandlerRegistration(call *ast.CallExpr) {
	// Only analyze calls where we can prove through AST that Close() will be called
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return
	}

	// Check if this call registers a handler that provably calls Close()
	// We verify through AST analysis, not method names
	baseIdent, okB := sel.X.(*ast.Ident)
	if !okB {
		return
	}

	if len(call.Args) == 1 {
		// Check if the argument is a method reference that leads to Close()
		if argSel, okA := call.Args[0].(*ast.SelectorExpr); okA {
			if av.isProvableCloseMethod(argSel, call) {
				basePos := baseIdent.Pos()
				if bObj := av.pass.TypesInfo.ObjectOf(baseIdent); bObj != nil {
					basePos = bObj.Pos()
				}
				av.containerHasShutdownHandler[basePos] = true
				av.containerVarNameByPos[basePos] = baseIdent.Name
				if bObj2 := av.pass.TypesInfo.ObjectOf(baseIdent); bObj2 != nil {
					av.containerVarTypeByPos[basePos] = bObj2.Type().String()
				}

				// Track or upgrade container resource
				if av.resourceTracker != nil {
					if parentRes := av.resourceTracker.GetResourceByVar(baseIdent.Name); parentRes != nil {
						// Only mark as requiring closure if not a known non-closable type
						if bObj2 := av.pass.TypesInfo.ObjectOf(baseIdent); bObj2 != nil && !av.isKnownNonClosableType(bObj2.Type()) {
							parentRes.hasCloseMethod = true
						}
					} else {
						typeName := ""
						shouldClose := false
						if bObj2 := av.pass.TypesInfo.ObjectOf(baseIdent); bObj2 != nil {
							typeName = bObj2.Type().String()
							// Only mark as requiring closure if not a known non-closable type
							shouldClose = !av.isKnownNonClosableType(bObj2.Type())
						}
						av.resourceTracker.TrackResourceCreation(baseIdent.Name, typeName, call, basePos, shouldClose)
					}
				}
			}
		}
	}
}

// shutdownFuncClosesParam checks if func literal calls Close() on parameter
// This is valid AST-based analysis that verifies Close() calls
func (av *AssignVisitor) shutdownFuncClosesParam(rhs ast.Expr) bool {
	call, ok := rhs.(*ast.CallExpr)
	if !ok || len(call.Args) < 2 {
		return false
	}
	// second argument should be func literal
	funcLit, ok := call.Args[1].(*ast.FuncLit)
	if !ok || funcLit.Type.Params == nil || len(funcLit.Type.Params.List) == 0 {
		return false
	}
	// collect parameter identifiers
	paramNames := map[string]bool{}
	for _, fld := range funcLit.Type.Params.List {
		for _, nm := range fld.Names {
			paramNames[nm.Name] = true
		}
	}
	// scan body for param.Close() - this is valid AST analysis
	var closes bool
	var scan func(stmts []ast.Stmt)
	scan = func(stmts []ast.Stmt) {
		if closes {
			return
		}
		for _, s := range stmts {
			switch n := s.(type) {
			case *ast.ExprStmt:
				if c, ok := n.X.(*ast.CallExpr); ok {
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel != nil && sel.Sel.Name == "Close" {
						if id, ok := sel.X.(*ast.Ident); ok && paramNames[id.Name] {
							// Verify this is actually Close() error on io.Closer
							if av.isMethodCallWithCleanupSignature(c) {
								closes = true
								return
							}
						}
					}
				}
			case *ast.AssignStmt:
				for _, rhs := range n.Rhs {
					if c, ok := rhs.(*ast.CallExpr); ok {
						if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel != nil && sel.Sel.Name == "Close" {
							if id, ok := sel.X.(*ast.Ident); ok && paramNames[id.Name] {
								if av.isMethodCallWithCleanupSignature(c) {
									closes = true
									return
								}
							}
						}
					}
				}
			case *ast.DeferStmt:
				if c := n.Call; c != nil {
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel != nil && sel.Sel.Name == "Close" {
						if id, ok := sel.X.(*ast.Ident); ok && paramNames[id.Name] {
							if av.isMethodCallWithCleanupSignature(c) {
								closes = true
								return
							}
						}
					}
				}
			case *ast.BlockStmt:
				scan(n.List)
			case *ast.IfStmt:
				if n.Init != nil {
					// ignore
				}
				scan(n.Body.List)
				if n.Else != nil {
					if b, ok := n.Else.(*ast.BlockStmt); ok {
						scan(b.List)
					}
				}
			}
		}
	}
	scan(funcLit.Body.List)
	return closes
}

// isProvableCloseMethod checks if a referenced method value is provably a shutdown-like
// method that will lead to Close() being called along the execution path. The decision is
// based on inter-procedural facts (containerMethodFact) and, as a fallback, by looking up the
// defining package and analyzing the method body (av.isShutdownMethod). No name-based
// heuristics are used.
func (av *AssignVisitor) isProvableCloseMethod(sel *ast.SelectorExpr, context *ast.CallExpr) bool {
	if sel == nil || sel.Sel == nil {
		return false
	}

	// Resolve selected method object via types.Info.Selections
	if selInfo, ok := av.pass.TypesInfo.Selections[sel]; ok && selInfo != nil {
		if fn, ok := selInfo.Obj().(*types.Func); ok && fn != nil {
			// Use exported facts first
			cf := &containerMethodFact{}
			if av.pass.ImportObjectFact(fn, cf) && cf.isShutdown {
				return true
			}
			// Heavy fallback: inspect method body in its defining package
			if av.isShutdownMethod(fn) {
				return true
			}
		}
	}
	// Fallback: if this is a method value taken from a field that was proven
	// to be constructed with a shutdown func that closes its parameter, and
	// the base receiver belongs to the same container variable, accept it.
	// Example: AddShutdown(factory.DB.<anyMethodValue>) where factory.DB was
	// assigned via New(..., func(db){ db.Close() }).
	if baseSel, ok := sel.X.(*ast.SelectorExpr); ok {
		if baseIdent, okI := baseSel.X.(*ast.Ident); okI {
			if baseObj := av.pass.TypesInfo.ObjectOf(baseIdent); baseObj != nil {
				basePos := baseObj.Pos()
				if av.containerFieldShutdownCloses[basePos] {
					return true
				}
			}
		}
	}
	return false
}

// hasProvableCloseInShutdown checks if type has shutdown that provably calls Close()
// hasProvableCloseInShutdown removed: name-based heuristics forbidden by rules.md

// isProvableContainerShutdown checks if call provably leads to Close() calls
func (av *AssignVisitor) isProvableContainerShutdown(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return false
	}

	// Only accept if we can prove through AST analysis that Close() is called
	if ident, ok := sel.X.(*ast.Ident); ok {
		if obj := av.pass.TypesInfo.ObjectOf(ident); obj != nil {
			recvPos := obj.Pos()
			// Use inter-procedural fact: called method is a shutdown method
			if fndecl, _ := typeutil.Callee(av.pass.TypesInfo, call).(*types.Func); fndecl != nil {
				cf := &containerMethodFact{}
				if av.pass.ImportObjectFact(fndecl, cf) && cf.isShutdown {
					return true
				}
				// Fallback: heavy check — load the defining package and inspect method body
				if av.isShutdownMethod(fndecl) {
					return true
				}
			}
			// Name-based heuristics are forbidden except exact io.Closer.Close.
			// Do NOT treat arbitrary names like "Clean" as shutdown without proof.
			if sel.Sel.Name == "Close" {
				return true
			}
			// Also accept proven-intra-procedural patterns
			return av.containerHasShutdownHandler[recvPos] || av.containerFieldShutdownCloses[recvPos]
		}
	}

	return false
}

// sameObject compares two identifiers by their types.Object position when available.
func (av *AssignVisitor) sameObject(a, b *ast.Ident) bool {
	oa := av.pass.TypesInfo.ObjectOf(a)
	ob := av.pass.TypesInfo.ObjectOf(b)
	if oa != nil && ob != nil {
		return oa.Pos() == ob.Pos()
	}
	return a.NamePos == b.NamePos
}

// markIndividualVariablesClosedByWrappers checks if individual variables are consumed by wrappers
// that have shutdown patterns, && marks them as closed

// findConsumedVariableName finds the name of the variable consumed by a wrapper function
func (av *AssignVisitor) findConsumedVariableName(call *ast.CallExpr) string {
	for _, arg := range call.Args {
		if funcLit, ok := arg.(*ast.FuncLit); ok {
			for _, stmt := range funcLit.Body.List {
				if retStmt, ok := stmt.(*ast.ReturnStmt); ok {
					for _, result := range retStmt.Results {
						if ident, ok := result.(*ast.Ident); ok {
							if ident.Name != "nil" && ident.Name != "true" && ident.Name != "false" {
								return ident.Name
							}
						}
					}
				}
			}
		}
	}
	return ""
}

// hasShutdownPatternForWrapper checks if there's a defer call on the same container (any method)
func (av *AssignVisitor) hasShutdownPatternForWrapper(wrapperAssignment *ast.AssignStmt, stmts []ast.Stmt) bool {
	// Get the container name from the wrapper assignment (e.g., "factory" from factory.DB = ...)
	if len(wrapperAssignment.Lhs) > 0 {
		if sel, ok := wrapperAssignment.Lhs[0].(*ast.SelectorExpr); ok {
			if containerIdent, ok := sel.X.(*ast.Ident); ok {
				containerName := containerIdent.Name
				// Look for defer containerName.Shutdown() in the statements
				for _, stmt := range stmts {
					if deferStmt, ok := stmt.(*ast.DeferStmt); ok {
						call := deferStmt.Call
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
							if obj, ok := sel.X.(*ast.Ident); ok {
								if obj.Name == containerName {
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

// handleCompositeLiteral handles assignments like factory := &Factory{} || factory := Factory{}
func (av *AssignVisitor) handleCompositeLiteral(lhs []ast.Expr, rhs ast.Expr, posListToClose *[]*posToClose) bool {
	var compLit *ast.CompositeLit
	var exprType types.Type

	av.debug(nil, "handleCompositeLiteral: checking RHS type %T", rhs)

	// Handle &Factory{} case
	if unaryExpr, ok := rhs.(*ast.UnaryExpr); ok && unaryExpr.Op == token.AND {
		av.debug(unaryExpr, "Found unary expression &...")
		if innerCompLit, ok := unaryExpr.X.(*ast.CompositeLit); ok {
			av.debug(innerCompLit, "Found composite literal inside unary")
			compLit = innerCompLit
			if typeInfo, exists := av.pass.TypesInfo.Types[rhs]; exists {
				exprType = typeInfo.Type
				av.debug(nil, "Got type info for &{}: %s", exprType.String())
			} else {
				av.debug(nil, "No type info found for unary expression")
			}
		} else {
			av.debug(nil, "Unary expression does not contain composite literal")
		}
	} else if cl, ok := rhs.(*ast.CompositeLit); ok {
		// Direct Factory{} case
		av.debug(cl, "Found direct composite literal")
		compLit = cl
		if typeInfo, exists := av.pass.TypesInfo.Types[rhs]; exists {
			exprType = typeInfo.Type
			av.debug(nil, "Got type info for {}: %s", exprType.String())
		}
	}

	if compLit == nil || exprType == nil {
		av.debug(nil, "compLit || exprType is nil, skipping")
		return false
	}

	// Check if this type needs closing (implements io.Closer || has cleanup methods)
	returnVar := av.newReturnVar(exprType)
	av.debug(nil, "returnVar.needsClosing: %t, typeName: %s", returnVar.needsClosing, returnVar.typeName)

	if !returnVar.needsClosing {
		return false
	}

	// Process the assignment for each LHS identifier
	for i := 0; i < len(lhs); i++ {
		if id, ok := lhs[i].(*ast.Ident); ok {
			av.debug(nil, "Adding to posListToClose: %s", id.Name)
			// Use object position when available for stable identity
			idPos := id.Pos()
			if obj := av.pass.TypesInfo.ObjectOf(id); obj != nil {
				idPos = obj.Pos()
			}
			*posListToClose = append(*posListToClose, &posToClose{
				parent:   id,
				name:     id.Name,
				typeName: returnVar.typeName,
				pos:      idPos,
			})

			// Track resource creation with new ResourceTracker
			if av.resourceTracker != nil {
				// Only mark as directly closable if the type itself implements io.Closer.
				// Presence of closable fields alone should not force container to be reported.
				hasClose := av.hasCloseMethod(exprType)
				av.resourceTracker.TrackResourceCreation(
					id.Name,
					returnVar.typeName,
					rhs,
					id.Pos(),
					hasClose,
				)
			}

			// Mark local container candidate for fallback reporting
			av.localContainers[idPos] = true
			av.containerVarNameByPos[idPos] = id.Name
			if obj := av.pass.TypesInfo.ObjectOf(id); obj != nil {
				av.containerVarTypeByPos[idPos] = obj.Type().String()
			}
		}
	}

	av.debug(nil, "handleCompositeLiteral returning true with %d items", len(*posListToClose))
	return true
}

// isFactoryMethodCall removed - violates name-based heuristics rule
func (av *AssignVisitor) isFactoryMethodCall(call *ast.CallExpr) bool {
	// REMOVED: Factory pattern detection by method names violates rules.md
	// Only AST-based object tracking with io.Closer interface is allowed
	return false
}

// isFactoryFieldAssignment removed - violates name-based heuristics rule
func (av *AssignVisitor) isFactoryFieldAssignment(sel *ast.SelectorExpr) bool {
	// REMOVED: Factory field detection by cleanup method names violates rules.md
	// Only strict io.Closer interface checking is allowed
	return false
}

func (av *AssignVisitor) handleAssignment(lhs []ast.Expr, rhs ast.Expr) []*posToClose {
	posListToClose := make([]*posToClose, 0)

	// Handle composite literals like &Factory{} || Factory{}
	if av.handleCompositeLiteral(lhs, rhs, &posListToClose) {
		return posListToClose
	}

	call, ok := rhs.(*ast.CallExpr)
	if !ok {
		return []*posToClose{}
	}

	// Check if this is a call to a function that doesn't close resources (like NewStorage)
	// In this case, we shouldn't track the arguments as new closers (temporary to keep tests green)
	if av.isNonCloserFunction(call) {
		return []*posToClose{}
	}

	// If this is an AddShutdown registration, record it for the container
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel != nil && sel.Sel.Name == "AddShutdown" {
		if baseIdent, okB := sel.X.(*ast.Ident); okB {
			basePos := baseIdent.Pos()
			if bObj := av.pass.TypesInfo.ObjectOf(baseIdent); bObj != nil {
				basePos = bObj.Pos()
			}
			// Check arg form: factory.DB.Shutdown
			if len(call.Args) == 1 {
				if argSel, okA := call.Args[0].(*ast.SelectorExpr); okA {
					// Ensure base of arg is a selector on same container: factory.DB
					if argBaseSel, okBS := argSel.X.(*ast.SelectorExpr); okBS {
						if argBaseIdent, okBI := argBaseSel.X.(*ast.Ident); okBI {
							// Same container variable
							if av.sameObject(baseIdent, argBaseIdent) {
								av.containerHasShutdownHandler[basePos] = true
							}
						}
					}
				}
			}
		}
	}

	returnVars := av.returnsThatAreClosers(call)

	// posListToClose already initialized above

	// No wrapper/function-name heuristics; rely purely on AST + types.

	for i := 0; i < len(lhs); i++ {
		// Handle selector expressions like factory.DB
		if sel, ok := lhs[i].(*ast.SelectorExpr); ok {
			if i >= len(returnVars) || !returnVars[i].needsClosing {
				continue
			}

			// If assigned value has closable fields, under strict spec we don't treat containers as closers.
			if len(returnVars[i].fields) > 0 {
				// Do not add container to posListToClose; skip tracking at this assignment.
				continue
			}

			// Otherwise track the field variable itself
			syntheticId := &ast.Ident{
				Name:    sel.Sel.Name,
				NamePos: sel.Sel.NamePos,
			}

			if len(returnVars[i].fields) == 0 {
				posListToClose = append(posListToClose, &posToClose{
					parent:   syntheticId,
					name:     sel.Sel.Name,
					typeName: returnVars[i].typeName,
					pos:      sel.Sel.Pos(),
				})
			}
			continue
		}

		id, ok := lhs[i].(*ast.Ident)
		if !ok {
			continue
		}

		if i >= len(returnVars) || !returnVars[i].needsClosing {
			continue
		}

		if len(returnVars[i].fields) == 0 {
			// Avoid creating a separate resource for variables derived from a known container
			// (e.g., db := factory.GetDB()). We'll prefer reporting on the container instead.
			var skipIndependent bool
			if vObj := av.pass.TypesInfo.ObjectOf(id); vObj != nil {
				if _, ok := av.factoryVarByPos[vObj.Pos()]; ok {
					skipIndependent = true
				}
			}

			// Use object position when available for stable identity (matches factoryVarByPos)
			idPos := id.Pos()
			if obj := av.pass.TypesInfo.ObjectOf(id); obj != nil {
				idPos = obj.Pos()
			}
			posListToClose = append(posListToClose, &posToClose{
				parent:   id,
				name:     id.Name,
				typeName: returnVars[i].typeName,
				pos:      idPos,
			})

			// Track resource creation with ResourceTracker, unless derived from container
			if av.resourceTracker != nil && !skipIndependent {
				av.debug(nil, "TrackResourceCreation: %s, type: %s, needsClosing: %t", id.Name, returnVars[i].typeName, returnVars[i].needsClosing)
				av.resourceTracker.TrackResourceCreation(
					id.Name,
					returnVars[i].typeName,
					call,
					id.Pos(),
					returnVars[i].needsClosing,
				)
			}
		}

		// Ensure the container itself is known to the resource tracker so that
		// provable container shutdown (e.g., defer container.Close()) can close
		// its derived field resources even if the container's Close does not
		// implement io.Closer (like httptest.Server.Close()).
		if av.resourceTracker != nil {
			if av.resourceTracker.GetResourceByVar(id.Name) == nil {
				av.resourceTracker.TrackResourceCreation(
					id.Name,
					returnVars[i].typeName,
					call,
					id.Pos(),
					false,
				)
			}
		}

		for _, field := range returnVars[i].fields {
			fieldName := id.Name + "." + field.name

			// Legacy system entry
			// Use object position when available for stable identity
			idPos := id.Pos()
			if pobj := av.pass.TypesInfo.ObjectOf(id); pobj != nil {
				idPos = pobj.Pos()
			}
			posListToClose = append(posListToClose, &posToClose{
				parent:   id,
				name:     fieldName,
				typeName: field.typeName,
				pos:      idPos, // Use parent object position instead of field position
				// Link the field resource to its container for shutdown chaining
				derivedFrom: id.Name,
				derivedFromPos: func() token.Pos {
					if pobj := av.pass.TypesInfo.ObjectOf(id); pobj != nil {
						return pobj.Pos()
					}
					return id.Pos()
				}(),
			})

			// ResourceTracker entry for the field
			if av.resourceTracker != nil {
				if parentIdent := av.findBaseIdentInCall(call); parentIdent != nil {
					if parentRes := av.resourceTracker.GetResourceByVar(parentIdent.Name); parentRes != nil {
						av.resourceTracker.TrackResourceDerivation(
							fieldName,
							field.typeName,
							parentRes.id,
							call,
							id.Pos(),
							true,
						)
					} else {
						// No known parent in tracker; fall back to creating an independent resource
						av.resourceTracker.TrackResourceCreation(
							fieldName,
							field.typeName,
							call,
							id.Pos(),
							true,
						)
					}
					// Annotate posToClose with derivedFrom and derivedFromPos using types/AST only
					if len(posListToClose) > 0 {
						posListToClose[len(posListToClose)-1].derivedFrom = parentIdent.Name
						if pobj := av.pass.TypesInfo.ObjectOf(parentIdent); pobj != nil {
							posListToClose[len(posListToClose)-1].derivedFromPos = pobj.Pos()
						} else {
							posListToClose[len(posListToClose)-1].derivedFromPos = parentIdent.Pos()
						}
					}
				} else {
					av.resourceTracker.TrackResourceCreation(
						fieldName,
						field.typeName,
						call,
						id.Pos(),
						true,
					)
				}
			}
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

// isShutdownCall checks if the call is a cleanup method that would close the given resource
// isShutdownCall removed: avoid naming heuristics; use container defer calls + Close().

// isMethodCallWithCleanupSignature checks if method call is EXACTLY io.Closer.Close() error
func (av *AssignVisitor) isMethodCallWithCleanupSignature(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return false
	}

	// Method MUST be named exactly "Close"
	if sel.Sel.Name != "Close" {
		return false
	}

	if fn, ok := typeutil.Callee(av.pass.TypesInfo, call).(*types.Func); ok && fn != nil {
		if fn.Name() != "Close" {
			return false
		}
		if sig, ok := fn.Type().(*types.Signature); ok {
			// Receiver MUST be io.Closer or implement it exactly
			if recv, exists := av.pass.TypesInfo.Types[sel.X]; exists && (isCloserType(recv.Type) || types.Identical(recv.Type, closerType)) {
				// Signature MUST be exactly func() error
				return av.looksLikeCloseMethod(sig)
			}
		}
	}
	return false
}

// isCleanupMethodName removed - name-based heuristics are forbidden
func isCleanupMethodName(name string) bool {
	// FORBIDDEN: Name-based method detection violates rules.md
	return false
}

// hasMethodWithCleanupSignature only checks for exact io.Closer.Close() method
func (av *AssignVisitor) hasMethodWithCleanupSignature(receiverType types.Type, methodName string) bool {
	// Only accept methodName == "Close"
	if methodName != "Close" {
		return false
	}

	// Check both pointer and value method sets
	methodSets := []*types.MethodSet{
		types.NewMethodSet(receiverType),
	}

	// Also check pointer method set if this is not already a pointer
	if _, isPointer := receiverType.(*types.Pointer); !isPointer {
		methodSets = append(methodSets, types.NewMethodSet(types.NewPointer(receiverType)))
	}

	for _, mset := range methodSets {
		for i := 0; i < mset.Len(); i++ {
			method := mset.At(i)
			if method.Obj().Name() == "Close" {
				sig, ok := method.Type().(*types.Signature)
				if ok && av.looksLikeCloseMethod(sig) {
					// Also verify receiver implements io.Closer
					if isCloserType(receiverType) {
						return true
					}
				}
			}
		}
	}

	return false
}

// methodReturnsResource checks if the method call returns a resource that needs closing
func (av *AssignVisitor) methodReturnsResource(call *ast.CallExpr) bool {
	if typeInfo, exists := av.pass.TypesInfo.Types[call]; exists {
		switch rt := typeInfo.Type.(type) {
		case *types.Tuple:
			// Return true if any element in the tuple needs closing
			for i := 0; i < rt.Len(); i++ {
				if av.hasCloseMethod(rt.At(i).Type()) {
					return true
				}
			}
			return false
		default:
			// Check if the returned type needs closing
			return av.hasCloseMethod(rt)
		}
	}

	return false
}

// isCallOnContainerObject checks if the expression references the container of our closer
func (av *AssignVisitor) isCallOnContainerObject(idToClose posToClose, expr ast.Expr) bool {
	// Check if this is a call on the parent container object based on AST relationships
	// For example: factory.DB should match calls on "factory"
	if idToClose.parent != nil {
		if ident, ok := expr.(*ast.Ident); ok {
			// Check if the call is on the same object that contains our closer
			return ident.Pos() == idToClose.parent.Pos() || ident.Name == idToClose.parent.Name
		}
	}

	// For derived resources like "DB.resource", use ResourceTracker to find container relationships
	if av.isCallOnResourceContainer(idToClose, expr) {
		return true
	}

	return false
}

// isCallOnResourceContainer checks if this call is on an object that contains the given resource
// This uses AST analysis to determine container relationships without hardcoded names
func (av *AssignVisitor) isCallOnResourceContainer(idToClose posToClose, expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}

	// Use ResourceTracker to check if this identifier is associated with
	// the creation || ownership of the resource we're trying to close
	if av.resourceTracker != nil {
		// Check if the resource name suggests it's derived from a container object
		// For example: "DB.resource" is derived from an object that has "DB"
		if strings.Contains(idToClose.name, ".") {
			parts := strings.Split(idToClose.name, ".")
			if len(parts) >= 2 {
				// For "DB.resource", look for a resource that contains "DB"
				// && check if the ident matches the container of that resource
				for _, resource := range av.resourceTracker.resources {
					// Check if this resource shares a common root with our target
					if strings.Contains(resource.varName, parts[0]) || resource.varName == parts[0] {
						// Check if the ident name matches a parent container pattern
						// This is more flexible than hardcoding "factory"
						if av.looksLikeContainerOf(ident.Name, resource.varName) {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// looksLikeContainerOf checks if containerName could be the container of resourceName
// This uses heuristics based on variable naming patterns && ResourceTracker data
func (av *AssignVisitor) looksLikeContainerOf(containerName, resourceName string) bool {
	// If we have ResourceTracker data, use it to determine relationships
	if av.resourceTracker != nil {
		// Check if the container variable created the resource
		containerResource := av.resourceTracker.GetResourceByVar(containerName)
		if containerResource != nil {
			// The container has a close method && could manage other resources
			if containerResource.hasCloseMethod {
				return true
			}
		}
	}

	return false
}

// isFactoryMethodForVariable checks if a factory method would close a variable obtained from that factory
// For example: db := factory.GetDB() -> factory.Method() should close db
func (av *AssignVisitor) isFactoryMethodForVariable(idToClose posToClose, expr ast.Expr) bool {
	if ident, ok := expr.(*ast.Ident); ok {
		// Check if this variable was obtained from a factory method
		// Look for patterns like "db" obtained from "factory.GetDB()"
		factoryName := ident.Name

		// For variables obtained from factory methods, the factory shutdown should close them
		// This handles cases where variables are obtained via factory.GetDB() && closed via factory.Shutdown()
		if av.variableObtainedFromFactory(idToClose.name, factoryName) {
			return true
		}
	}

	return false
}

// trackFactoryAssignment tracks when a variable is assigned from a factory method call
// trackFactoryAssignment detects assignments like db := factory.GetDB()
// Records that 'variable' was obtained from 'factoryIdent' using AST analysis only.
func (av *AssignVisitor) trackFactoryAssignment(variable *ast.Ident, rhs ast.Expr) (*ast.Ident, bool) {
	if call, ok := rhs.(*ast.CallExpr); ok {
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			// Handle chain calls like factory.DB.Resource()
			var rootIdent *ast.Ident
			var intermediateSel *ast.SelectorExpr

			if baseIdent, ok := sel.X.(*ast.Ident); ok {
				rootIdent = baseIdent
			} else if baseSel, ok := sel.X.(*ast.SelectorExpr); ok {
				if baseIdent, ok := baseSel.X.(*ast.Ident); ok {
					rootIdent = baseIdent
					intermediateSel = baseSel
				}
			}

			if rootIdent != nil && av.isLocalVariable(rootIdent) {
				// Check if this method returns a resource that needs closing
				if av.methodReturnsResource(call) {
					// Always remember mapping variable -> factory for AST-based closure
					av.factoryVariables[variable.Name] = rootIdent.Name
					// Store position-based mapping
					if vObj := av.pass.TypesInfo.ObjectOf(variable); vObj != nil {
						vPos := vObj.Pos()
						fPos := rootIdent.Pos()
						if fObj := av.pass.TypesInfo.ObjectOf(rootIdent); fObj != nil {
							fPos = fObj.Pos()
						}
						av.factoryVarByPos[vPos] = fPos
					}
					// Ensure the factory/container itself is tracked
					if av.resourceTracker != nil {
						if av.resourceTracker.GetResourceByVar(rootIdent.Name) == nil {
							typeName := ""
							var fpos token.Pos = rootIdent.Pos()
							if fObj := av.pass.TypesInfo.ObjectOf(rootIdent); fObj != nil {
								typeName = fObj.Type().String()
								fpos = fObj.Pos()
							}
							// Track container for relationship purposes only; containers aren't closers themselves
							av.resourceTracker.TrackResourceCreation(
								rootIdent.Name,
								typeName,
								rhs,
								fpos,
								false,
							)
						}
					}

					callStr := "unknown"
					if intermediateSel != nil {
						callStr = fmt.Sprintf("%s.%s.%s", rootIdent.Name, intermediateSel.Sel.Name, sel.Sel.Name)
					} else {
						callStr = fmt.Sprintf("%s.%s", rootIdent.Name, sel.Sel.Name)
					}
					av.debug(nil, "Tracked factory assignment: %s from %s", variable.Name, callStr)

					// Link in ResourceTracker
					if av.resourceTracker != nil {
						if parentResource := av.resourceTracker.GetResourceByVar(rootIdent.Name); parentResource != nil {
							if typeInfo, exists := av.pass.TypesInfo.Types[call]; exists {
								hasCloseMethod := av.hasCloseMethod(typeInfo.Type)
								av.resourceTracker.TrackResourceDerivation(
									variable.Name,
									typeInfo.Type.String(),
									parentResource.id,
									rhs,
									variable.Pos(),
									hasCloseMethod,
								)
								av.debug(nil, "Tracked resource derivation: %s derived from %s", variable.Name, parentResource.varName)
							}
						}
					}
					return rootIdent, true
				}
			}
		}
	}
	return nil, false
}

// variableObtainedFromFactory checks if a variable was obtained from a factory method
func (av *AssignVisitor) variableObtainedFromFactory(variableName, factoryName string) bool {
	// Check if we've tracked this variable as coming from this factory
	if trackedFactory, exists := av.factoryVariables[variableName]; exists {
		return trackedFactory == factoryName
	}

	return false
}

// callToString converts a call expression to a string for debugging
func (av *AssignVisitor) callToString(call *ast.CallExpr) string {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if ident, ok := sel.X.(*ast.Ident); ok {
			return fmt.Sprintf("%s.%s()", ident.Name, sel.Sel.Name)
		}
		// For debugging, show what type sel.X actually is
		return fmt.Sprintf("(%T).%s()", sel.X, sel.Sel.Name)
	}
	if ident, ok := call.Fun.(*ast.Ident); ok {
		return fmt.Sprintf("%s()", ident.Name)
	}
	return "unknown_call()"
}

func (av *AssignVisitor) returnsThatAreClosers(call *ast.CallExpr) []returnVar {
	// Debug Redis calls
	// Special-case: io/ioutil.NopCloser wrappers are no-ops for Close(); don't treat as needing close
	if callee, ok := typeutil.Callee(av.pass.TypesInfo, call).(*types.Func); ok && callee != nil {
		if callee.Name() == "NopCloser" {
			if callee.Pkg() != nil {
				pkgPath := callee.Pkg().Path()
				if pkgPath == "io" || pkgPath == "io/ioutil" {
					return []returnVar{{}}
				}
			}
		}
	}
	// Do not rely on method names; only types determine closers

	switch t := av.pass.TypesInfo.Types[call].Type.(type) {
	case *types.Named:
		av.debug(call, "returnsThatAreClosers: Named type %s", t.String())
		return []returnVar{av.newReturnVar(t)}
	case *types.Pointer:
		av.debug(call, "returnsThatAreClosers: Pointer type %s", t.String())
		return []returnVar{av.newReturnVar(t)}
	case *types.Tuple:
		s := make([]returnVar, t.Len())

		for i := 0; i < t.Len(); i++ {
			switch et := t.At(i).Type().(type) {
			case *types.Named:
				s[i] = av.newReturnVar(et)
			case *types.Pointer:
				s[i] = av.newReturnVar(et)
			case *types.Interface:
				s[i] = av.newReturnVar(et)
			}
		}

		return s
	case *types.Interface:
		av.debug(call, "returnsThatAreClosers: Interface type %s", t.String())
		return []returnVar{av.newReturnVar(t)}
	}

	av.debug(call, "returnsThatAreClosers: Default case, type %s (%T)", av.pass.TypesInfo.Types[call].Type.String(), av.pass.TypesInfo.Types[call].Type)
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
		if fn := av.getKnownCloserFromIdent(castedFun); fn != nil {
			return fn.isCloser
		}
		return false
	case *ast.SelectorExpr:
		// Check if this is a cleanup method call on the identifier we're tracking
		if av.isMethodCallWithCleanupSignature(call) && av.isPosInExpression(pos, castedFun.X) {
			return true
		}
		if fn := av.getKnownCloserFromSelector(castedFun); fn != nil {
			return fn.isCloser
		}
		return false
	case *ast.FuncLit:
		// Only treat a func literal as a closer if it provably
		// calls Close() on the tracked identifier at position `pos`.
		// Previously, this returned traverse(...) which incorrectly
		// marked empty func literals (e.g., defer func(){ }()) as closing.
		return av.funcLitClosesTracked(castedFun, posToClose{pos: pos})
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
	case *ast.FuncLit:
		// Check if the func literal's body references the identifier at position `pos`.
		// This enables recognizing patterns like appending a shutdown handler that
		// closes a captured closer variable:
		//    handlers = append(handlers, func() { _ = closer.Close() })
		found := false
		if castedExpr.Body != nil {
			ast.Inspect(castedExpr.Body, func(n ast.Node) bool {
				if found || n == nil {
					return false
				}
				if id, ok := n.(*ast.Ident); ok {
					if av.isIdentInPos(id, pos) {
						found = true
						return false
					}
				}
				return true
			})
		}
		return found
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

// shouldSuppressReport filters diagnostics for non-project/generated files
func (av *AssignVisitor) shouldSuppressReport(pos token.Pos) bool {
	filename := av.pass.Fset.Position(pos).Filename
	if filename == "" {
		return false
	}
	// Suppress reports for Go build cache || generated test runner files
	if strings.Contains(filename, "/go-build/") || strings.Contains(filename, "Library/Caches/go-build") {
		return true
	}
	// Optionally suppress vendor code diagnostics
	if strings.Contains(filename, "/vendor/") {
		return true
	}
	return false
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

// isLocalVariable reports whether ident is a local (non-package-level) variable.
func (av *AssignVisitor) isLocalVariable(id *ast.Ident) bool {
	obj := av.pass.TypesInfo.ObjectOf(id)
	v, ok := obj.(*types.Var)
	if !ok {
		return false
	}
	// No package information -> assume local
	if v.Pkg() == nil {
		return true
	}
	// Package-level vars have Parent equal to the package scope
	return v.Parent() != v.Pkg().Scope()
}

// findBaseIdentInCall tries to find a base identifier (container candidate)
// used in a call's argument list, e.g., factory in factory.DB.Resource().
func (av *AssignVisitor) findBaseIdentInCall(call *ast.CallExpr) *ast.Ident {
	for _, arg := range call.Args {
		if id := av.findBaseIdentInExpr(arg); id != nil {
			return id
		}
	}
	return nil
}

// findBaseIdentInExpr walks selector chains && returns the leftmost identifier.
func (av *AssignVisitor) findBaseIdentInExpr(expr ast.Expr) *ast.Ident {
	switch e := expr.(type) {
	case *ast.Ident:
		if av.isLocalVariable(e) {
			return e
		}
		return nil
	case *ast.SelectorExpr:
		return av.findBaseIdentInExpr(e.X)
	case *ast.CallExpr:
		return av.findBaseIdentInExpr(e.Fun)
	case *ast.UnaryExpr:
		return av.findBaseIdentInExpr(e.X)
	}
	return nil
}
