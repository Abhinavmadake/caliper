package control_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Abhinavmadake/caliper/control"
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

			fingerprint, err := control.DecodeFingerprint(b)
			if err != nil {
				t.Fatalf("failed to parse fixture %s: %v", entry.Name(), err)
			}
			encoded, err := control.EncodeFingerprint(fingerprint)
			if err != nil {
				t.Fatalf("failed to encode fixture %s: %v", entry.Name(), err)
			}
			var original, roundTripped map[string]any
			if err := json.Unmarshal(b, &original); err != nil {
				t.Fatalf("failed to parse original fixture %s: %v", entry.Name(), err)
			}
			if err := json.Unmarshal(encoded, &roundTripped); err != nil {
				t.Fatalf("failed to parse encoded fixture %s: %v", entry.Name(), err)
			}
			if !reflect.DeepEqual(original, roundTripped) {
				for key, originalValue := range original {
					if !reflect.DeepEqual(originalValue, roundTripped[key]) {
						t.Errorf("fixture %s field %q changed during round trip", entry.Name(), key)
					}
				}
				for key := range roundTripped {
					if _, existed := original[key]; !existed {
						if roundTripped[key] == nil {
							continue // A missing optional slice decodes to nil and re-encodes as null.
						}
						t.Errorf("fixture %s gained field %q during round trip", entry.Name(), key)
					}
				}
			}
		})
	}

	if found == 0 {
		t.Fatal("expected to find at least one JSON fixture, but found none")
	}
}

func TestDecodeFingerprintAllowsUnknownFieldsAndRejectsUnknownVersion(t *testing.T) {
	const additive = `{"format_version":1,"corpus_revision":"0.1.0","cell":{},"results":[],"unmeasured":[],"future_field":{"value":true}}`
	if _, err := control.DecodeFingerprint([]byte(additive)); err != nil {
		t.Fatalf("DecodeFingerprint rejected an additive field: %v", err)
	}

	const unsupported = `{"format_version":2,"corpus_revision":"0.1.0","cell":{},"results":[],"unmeasured":[]}`
	if _, err := control.DecodeFingerprint([]byte(unsupported)); err == nil {
		t.Fatal("DecodeFingerprint accepted unsupported format_version")
	}
}
