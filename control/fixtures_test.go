package control_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Abhinavmadake/caliper/control"
)

// fixtureFiles lists the recorded fingerprints: fixtures/*.json and the
// per-cell recordings in fixtures/cells (#39).
func fixtureFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, dir := range []string{filepath.Join("..", "fixtures"), filepath.Join("..", "fixtures", "cells")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("failed to read fixtures directory: %v", err)
		}
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
				files = append(files, filepath.Join(dir, entry.Name()))
			}
		}
	}
	return files
}

func TestFixturesParse(t *testing.T) {
	found := 0
	for _, path := range fixtureFiles(t) {
		found++
		name := filepath.Join(filepath.Base(filepath.Dir(path)), filepath.Base(path))
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read fixture %s: %v", name, err)
			}

			fingerprint, err := control.DecodeFingerprint(b)
			if err != nil {
				t.Fatalf("failed to parse fixture %s: %v", name, err)
			}
			encoded, err := control.EncodeFingerprint(fingerprint)
			if err != nil {
				t.Fatalf("failed to encode fixture %s: %v", name, err)
			}
			var original, roundTripped map[string]any
			if err := json.Unmarshal(b, &original); err != nil {
				t.Fatalf("failed to parse original fixture %s: %v", name, err)
			}
			if err := json.Unmarshal(encoded, &roundTripped); err != nil {
				t.Fatalf("failed to parse encoded fixture %s: %v", name, err)
			}
			if !reflect.DeepEqual(original, roundTripped) {
				for key, originalValue := range original {
					if !reflect.DeepEqual(originalValue, roundTripped[key]) {
						t.Errorf("fixture %s field %q changed during round trip", name, key)
					}
				}
				for key := range roundTripped {
					if _, existed := original[key]; !existed {
						if roundTripped[key] == nil {
							continue // A missing optional slice decodes to nil and re-encodes as null.
						}
						t.Errorf("fixture %s gained field %q during round trip", name, key)
					}
				}
			}
		})
	}

	if found == 0 {
		t.Fatal("expected to find at least one JSON fixture, but found none")
	}
}

func TestRecordedFixtureDigestsMatchCanonicalFingerprint(t *testing.T) {
	for _, path := range fixtureFiles(t) {
		name := filepath.Join(filepath.Base(filepath.Dir(path)), filepath.Base(path))
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read fixture: %v", err)
			}
			fingerprint, err := control.DecodeFingerprint(data)
			if err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			got, err := control.ComputeFingerprintDigest(fingerprint)
			if err != nil {
				t.Fatalf("compute digest: %v", err)
			}
			if got != fingerprint.Digest {
				t.Errorf("digest = %q, recomputed %q", fingerprint.Digest, got)
			}
		})
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
