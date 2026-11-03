package goci

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type BndlLoader struct {
}

func (b *BndlLoader) Load(path string) (Bndl, error) {
	bundle := Bndl{}
	err := readJSONInto(filepath.Join(path, "config.json"), &bundle.Spec)
	if err != nil {
		return bundle, fmt.Errorf("Failed to load bundle: %w", err)
	}

	return bundle, nil
}

type BundleSaver struct{}

func (b BundleSaver) Save(bundle Bndl, path string) error {
	return save(bundle.Spec, filepath.Join(path, "config.json"))
}

// save writes value as JSON to a temporary file beside path and renames it
// into place, so that a reader sees either the old file or the whole new
// one, never one that is empty or half written. The file is readable only
// by its owner.
func save(value interface{}, path string) error {
	w, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("Failed to save bundle: %s", err)
	}
	defer os.Remove(w.Name())

	if err := json.NewEncoder(w).Encode(value); err != nil {
		w.Close()
		return fmt.Errorf("Failed to save bundle: %s", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("Failed to save bundle: %s", err)
	}
	if err := os.Rename(w.Name(), path); err != nil {
		return fmt.Errorf("Failed to save bundle: %s", err)
	}
	return nil
}

func readJSONInto(path string, object interface{}) error {
	runtimeContents, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(runtimeContents, object)
}
