package analyzer

import "go/types"

// normalizeTypeKey strips pointer indirections and returns a stable key for named types
// in the form of "pkgpath.TypeName". For unnamed types it falls back to types.Type.String().
func normalizeTypeKey(t types.Type) string {
	if t == nil {
		return ""
	}
	for {
		ptr, ok := t.(*types.Pointer)
		if !ok {
			break
		}
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		if obj := named.Obj(); obj != nil && obj.Pkg() != nil {
			return obj.Pkg().Path() + "." + obj.Name()
		}
	}
	return t.String()
}

// methodKey builds a stable key for a method based on package path, receiver type key and method name.
func methodKey(fn *types.Func) string {
	if fn == nil {
		return ""
	}
	pkgPath := ""
	if pkg := fn.Pkg(); pkg != nil {
		pkgPath = pkg.Path()
	}
	recvKey := ""
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		recvKey = normalizeTypeKey(sig.Recv().Type())
	}
	return pkgPath + "|" + recvKey + "|" + fn.Name()
}
