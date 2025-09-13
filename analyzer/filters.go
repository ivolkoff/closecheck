package analyzer

import (
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/tools/go/analysis"
)

func shouldSkipPackage(pass *analysis.Pass) bool {
	if pass == nil || pass.Pkg == nil {
		return false
	}
	if skipStdlib && isStdlibPackage(pass) {
		return true
	}
	if excludePkgPatterns.matches(pass.Pkg.Path()) {
		return true
	}
	if !includeTests && isTestOnlyPackage(pass) {
		return true
	}
	return false
}

func isStdlibPackage(pass *analysis.Pass) bool {
	if pass == nil {
		return false
	}
	goroot := runtime.GOROOT()
	if goroot == "" {
		return false
	}
	gorootSrc := filepath.Join(goroot, "src") + string(os.PathSeparator)
	for _, file := range pass.Files {
		filename := filenameForFile(pass.Fset, file)
		if filename == "" {
			continue
		}
		if strings.HasPrefix(filename, gorootSrc) {
			return true
		}
		// First non-empty filename is sufficient for heuristic
		break
	}
	return false
}

func isTestOnlyPackage(pass *analysis.Pass) bool {
	if pass == nil || pass.Pkg == nil {
		return false
	}
	if strings.HasSuffix(pass.Pkg.Name(), "_test") {
		return true
	}
	if len(pass.Files) == 0 {
		return false
	}
	allTests := true
	for _, file := range pass.Files {
		filename := filenameForFile(pass.Fset, file)
		if filename == "" {
			continue
		}
		if !strings.HasSuffix(filename, "_test.go") {
			allTests = false
			break
		}
	}
	return allTests
}

func determineFileFilters(pass *analysis.Pass) (map[string]bool, bool) {
	skip := make(map[string]bool, len(pass.Files))
	analyzedAny := false
	for _, file := range pass.Files {
		filename := filenameForFile(pass.Fset, file)
		if filename == "" {
			continue
		}
		if shouldSkipFilename(filename) {
			skip[filename] = true
			continue
		}
		if excludeGenerated && isGeneratedFile(file) {
			skip[filename] = true
			continue
		}
		if _, ok := skip[filename]; !ok {
			skip[filename] = false
		}
		analyzedAny = true
	}
	return skip, analyzedAny
}

func shouldSkipFilename(filename string) bool {
	if filename == "" {
		return false
	}
	if excludePathPatterns.matches(filename) {
		return true
	}
	if !includeTests && strings.HasSuffix(filename, "_test.go") {
		return true
	}
	return false
}

func filenameForFile(fset *token.FileSet, file *ast.File) string {
	if fset == nil || file == nil {
		return ""
	}
	pos := file.Package
	return fset.PositionFor(pos, true).Filename
}

func isGeneratedFile(file *ast.File) bool {
	if file == nil {
		return false
	}
	for _, group := range file.Comments {
		if group.Pos() > file.Package {
			break
		}
		if strings.Contains(group.Text(), "Code generated") {
			return true
		}
	}
	if file.Doc != nil && strings.Contains(file.Doc.Text(), "Code generated") {
		return true
	}
	return false
}

func makeSkipPosFunc(fset *token.FileSet, skip map[string]bool) func(token.Pos) bool {
	if len(skip) == 0 {
		return nil
	}
	return func(pos token.Pos) bool {
		if fset == nil {
			return false
		}
		position := fset.PositionFor(pos, true)
		if position.Filename == "" {
			return false
		}
		return skip[position.Filename]
	}
}
