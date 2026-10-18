package core

import (
	"os"
	"path/filepath"
)

func ArtifactDir() string {
	dir := filepath.Join(os.TempDir(), "gosmuggler")
	os.MkdirAll(dir, 0o755)
	return dir
}

func ArtifactPath(name string) string {
	return filepath.Join(ArtifactDir(), name)
}
