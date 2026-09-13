package control_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFixturesParse(t *testing.T) {
	fixturesDir := filepath.Join("..", "fixtures")

	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatalf("failed to read fixtures directory: %v", err)
	}

	found := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		found++
		path := filepath.Join(fixturesDir, entry.Name())
		t.Run(entry.Name(), func(t *testing.T) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read fixture %s: %v", entry.Name(), err)
			}

			var target map[string]interface{}
			if err := json.Unmarshal(b, &target); err != nil {
				t.Fatalf("failed to parse fixture %s: %v", entry.Name(), err)
			}
		})
	}

	if found == 0 {
		t.Fatal("expected to find at least one JSON fixture, but found none")
	}
}
