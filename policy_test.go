// Copyright 2026 OCI Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package digest

import (
	"crypto"
	"errors"
	"testing"
)

func TestPolicyAllowed(t *testing.T) {
	policy := Policy{SHA512, SHA256}

	if !policy.Allowed(SHA256) {
		t.Fatal("sha256 should be allowed")
	}
	if !policy.Allowed(SHA512) {
		t.Fatal("sha512 should be allowed")
	}
	if policy.Allowed(SHA384) {
		t.Fatal("sha384 should not be allowed")
	}

	var empty Policy
	if empty.Allowed(SHA256) {
		t.Fatal("an empty policy must not allow any algorithm")
	}
}

func TestPolicySelect(t *testing.T) {
	// SHA-384 is not registered by default, but used in this test.
	RegisterAlgorithm(SHA384, crypto.SHA384)

	content := []byte("policy-selection-content")
	sha256Dgst := SHA256.FromBytes(content)
	sha384Dgst := SHA384.FromBytes(content)
	sha512Dgst := SHA512.FromBytes(content)

	tests := []struct {
		name       string
		policy     Policy
		candidates []Digest
		expected   Digest
		wantErr    error
	}{
		{
			name:       "default policy picks sha512 when present",
			policy:     DefaultPolicy,
			candidates: []Digest{sha256Dgst, sha384Dgst, sha512Dgst},
			expected:   sha512Dgst,
		},
		{
			name:       "default policy falls through to sha384",
			policy:     DefaultPolicy,
			candidates: []Digest{sha256Dgst, sha384Dgst},
			expected:   sha384Dgst,
		},
		{
			name:       "default policy falls through to sha256",
			policy:     DefaultPolicy,
			candidates: []Digest{sha256Dgst},
			expected:   sha256Dgst,
		},
		{
			name:       "strict sha256 policy ignores a stronger sha512 candidate",
			policy:     Policy{SHA256},
			candidates: []Digest{sha512Dgst, sha256Dgst},
			expected:   sha256Dgst,
		},
		{
			name:       "missing strong digest does not fall back to a weak algorithm",
			policy:     Policy{SHA256},
			candidates: []Digest{sha512Dgst},
			wantErr:    ErrDigestNotAllowed,
		},
		{
			name:       "unregistered algorithm is skipped when a verifiable candidate exists",
			policy:     DefaultPolicy,
			candidates: []Digest{Digest("bean:0123456789abcdef"), sha256Dgst},
			expected:   sha256Dgst,
		},
		{
			name:       "unregistered algorithm alone cannot be selected",
			policy:     DefaultPolicy,
			candidates: []Digest{Digest("blake3:" + repeatRune('a', 64))},
			wantErr:    ErrDigestNotAllowed,
		},
		{
			name:       "malformed candidates are skipped",
			policy:     DefaultPolicy,
			candidates: []Digest{Digest("not-a-digest"), Digest(":"), sha256Dgst},
			expected:   sha256Dgst,
		},
		{
			name:       "malformed candidate of the strongest allowed algorithm is skipped",
			policy:     DefaultPolicy,
			candidates: []Digest{Digest("sha512:too-short"), sha512Dgst},
			expected:   sha512Dgst,
		},
		{
			name:       "empty policy rejects every candidate",
			policy:     nil,
			candidates: []Digest{sha256Dgst, sha512Dgst},
			wantErr:    ErrDigestNotAllowed,
		},
		{
			name:       "no candidates",
			policy:     DefaultPolicy,
			candidates: nil,
			wantErr:    ErrDigestNotAllowed,
		},
	}

	for _, testcase := range tests {
		t.Run(testcase.name, func(t *testing.T) {
			got, err := testcase.policy.Select(testcase.candidates...)
			if !errors.Is(err, testcase.wantErr) {
				t.Fatalf("Select() error = %v, want %v", err, testcase.wantErr)
			}
			if got != testcase.expected {
				t.Fatalf("Select() = %v, want %v", got, testcase.expected)
			}
		})
	}
}

func TestPolicySelectIsOrderIndependent(t *testing.T) {
	content := []byte("order-independent-content")
	sha256Dgst := SHA256.FromBytes(content)
	sha512Dgst := SHA512.FromBytes(content)

	first, err := DefaultPolicy.Select(sha256Dgst, sha512Dgst)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DefaultPolicy.Select(sha512Dgst, sha256Dgst)
	if err != nil {
		t.Fatal(err)
	}
	if first != sha512Dgst || second != sha512Dgst {
		t.Fatalf("selection depended on iteration order: %v vs %v", first, second)
	}
}

func TestDefaultPolicyRanking(t *testing.T) {
	expected := Policy{SHA512, SHA384, SHA256, BLAKE3}
	if len(DefaultPolicy) != len(expected) {
		t.Fatalf("DefaultPolicy = %v, want %v", DefaultPolicy, expected)
	}
	for i := range expected {
		if DefaultPolicy[i] != expected[i] {
			t.Fatalf("DefaultPolicy = %v, want %v", DefaultPolicy, expected)
		}
	}
}

func repeatRune(r rune, count int) string {
	runes := make([]rune, count)
	for i := range runes {
		runes[i] = r
	}
	return string(runes)
}
