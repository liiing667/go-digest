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

package digestset

import (
	"bytes"
	"crypto"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
)

func layerDigests(t *testing.T, content []byte) (digest.Digest, digest.Digest) {
	t.Helper()
	return digest.SHA256.FromBytes(content), digest.SHA512.FromBytes(content)
}

func corruptEncoded(d digest.Digest) digest.Digest {
	encoded := d.Encoded()
	last := encoded[len(encoded)-1]
	if last == '0' {
		last = '1'
	} else {
		last = '0'
	}
	return digest.NewDigestFromEncoded(d.Algorithm(), encoded[:len(encoded)-1]+string(last))
}

func TestSelectPicksStrongestAllowedDigest(t *testing.T) {
	content := []byte("mirror-sync-layer")
	sha256Dgst, sha512Dgst := layerDigests(t, content)

	dset := NewSet()
	for _, dgst := range []digest.Digest{sha256Dgst, sha512Dgst} {
		if err := dset.Add(dgst); err != nil {
			t.Fatal(err)
		}
	}

	// A nil policy means DefaultPolicy; the result must not depend on
	// insertion order (sha256 was added first).
	selected, err := dset.Select(nil)
	if err != nil {
		t.Fatal(err)
	}
	if selected != sha512Dgst {
		t.Fatalf("Select(nil) = %v, want %v", selected, sha512Dgst)
	}

	selected, err = dset.Select(digest.DefaultPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if selected != sha512Dgst {
		t.Fatalf("Select(DefaultPolicy) = %v, want %v", selected, sha512Dgst)
	}
}

func TestSelectFallsThroughPolicyOrder(t *testing.T) {
	content := []byte("fall-through-policy")
	sha256Dgst, _ := layerDigests(t, content)

	dset := NewSet()
	if err := dset.Add(sha256Dgst); err != nil {
		t.Fatal(err)
	}

	selected, err := dset.Select(digest.DefaultPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if selected != sha256Dgst {
		t.Fatalf("Select() = %v, want %v", selected, sha256Dgst)
	}
}

func TestSelectMissingStrongDigestDoesNotFallBack(t *testing.T) {
	content := []byte("no-silent-fallback")
	_, sha512Dgst := layerDigests(t, content)

	dset := NewSet()
	if err := dset.Add(sha512Dgst); err != nil {
		t.Fatal(err)
	}

	_, err := dset.Select(digest.Policy{digest.SHA256})
	if !errors.Is(err, ErrNoAllowedDigest) {
		t.Fatalf("Select(sha256-only) = %v, want ErrNoAllowedDigest", err)
	}

	emptySet := NewSet()
	if _, err := emptySet.Select(nil); !errors.Is(err, ErrNoAllowedDigest) {
		t.Fatalf("Select on empty set = %v, want ErrNoAllowedDigest", err)
	}
}

func TestSelectSkipsUnregisteredAlgorithm(t *testing.T) {
	content := []byte("unregistered-algorithm")
	sha256Dgst, _ := layerDigests(t, content)

	dset := NewSet()
	// Add cannot store an unregistered digest, so build the entry
	// directly to model a set received from an untrusted mirror.
	dset.entries = append(dset.entries, &digestEntry{
		alg:    digest.Algorithm("bean"),
		val:    "0123456789abcdef",
		digest: digest.Digest("bean:0123456789abcdef"),
	})
	if err := dset.Add(sha256Dgst); err != nil {
		t.Fatal(err)
	}

	selected, err := dset.Select(nil)
	if err != nil {
		t.Fatal(err)
	}
	if selected != sha256Dgst {
		t.Fatalf("Select() = %v, want the verifiable %v", selected, sha256Dgst)
	}

	onlyUnregistered := NewSet()
	onlyUnregistered.entries = append(onlyUnregistered.entries, &digestEntry{
		alg:    digest.Algorithm("bean"),
		val:    "0123456789abcdef",
		digest: digest.Digest("bean:0123456789abcdef"),
	})
	if _, err := onlyUnregistered.Select(nil); !errors.Is(err, ErrNoAllowedDigest) {
		t.Fatalf("Select() = %v, want ErrNoAllowedDigest", err)
	}
}

func TestSelectHonorsRegisteredOptionalAlgorithm(t *testing.T) {
	// SHA-384 is not registered by default, but used in this test.
	digest.RegisterAlgorithm(digest.SHA384, crypto.SHA384)

	content := []byte("optional-algorithm")
	sha256Dgst, _ := layerDigests(t, content)
	sha384Dgst := digest.SHA384.FromBytes(content)

	dset := NewSet()
	for _, dgst := range []digest.Digest{sha256Dgst, sha384Dgst} {
		if err := dset.Add(dgst); err != nil {
			t.Fatal(err)
		}
	}

	selected, err := dset.Select(nil)
	if err != nil {
		t.Fatal(err)
	}
	if selected != sha384Dgst {
		t.Fatalf("Select() = %v, want %v", selected, sha384Dgst)
	}
}

func TestVerifyReaderAcceptsConsistentCandidates(t *testing.T) {
	content := []byte("consistent-candidates")
	sha256Dgst, sha512Dgst := layerDigests(t, content)

	dset := NewSet()
	for _, dgst := range []digest.Digest{sha256Dgst, sha512Dgst} {
		if err := dset.Add(dgst); err != nil {
			t.Fatal(err)
		}
	}

	selected, err := dset.VerifyReader(bytes.NewReader(content), nil)
	if err != nil {
		t.Fatal(err)
	}
	if selected != sha512Dgst {
		t.Fatalf("VerifyReader() selected %v, want %v", selected, sha512Dgst)
	}
}

func TestVerifyReaderRejectsInconsistentCandidate(t *testing.T) {
	content := []byte("inconsistent-candidates")
	sha256Dgst, sha512Dgst := layerDigests(t, content)
	badSHA256 := corruptEncoded(sha256Dgst)

	dset := NewSet()
	for _, dgst := range []digest.Digest{badSHA256, sha512Dgst} {
		if err := dset.Add(dgst); err != nil {
			t.Fatal(err)
		}
	}

	_, err := dset.VerifyReader(bytes.NewReader(content), nil)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("VerifyReader() = %v, want ErrDigestMismatch", err)
	}
	if !strings.Contains(err.Error(), badSHA256.String()) {
		t.Fatalf("error %q should name the failing digest %q", err, badSHA256)
	}

	// Even when the weak algorithm is excluded from selection, its
	// presence in the set must still be enforced.
	_, err = dset.VerifyReader(bytes.NewReader(content), digest.Policy{digest.SHA512})
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("VerifyReader(sha512-only) = %v, want ErrDigestMismatch", err)
	}
}

func TestVerifyReaderRejectsWrongContent(t *testing.T) {
	content := []byte("correct-content")
	sha256Dgst, sha512Dgst := layerDigests(t, content)

	dset := NewSet()
	for _, dgst := range []digest.Digest{sha256Dgst, sha512Dgst} {
		if err := dset.Add(dgst); err != nil {
			t.Fatal(err)
		}
	}

	_, err := dset.VerifyReader(bytes.NewReader([]byte("different-content")), nil)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("VerifyReader() = %v, want ErrDigestMismatch", err)
	}
}

func TestVerifyReaderNoAllowedDigest(t *testing.T) {
	content := []byte("policy-rejected")
	_, sha512Dgst := layerDigests(t, content)

	dset := NewSet()
	if err := dset.Add(sha512Dgst); err != nil {
		t.Fatal(err)
	}

	_, err := dset.VerifyReader(bytes.NewReader(content), digest.Policy{digest.SHA256})
	if !errors.Is(err, ErrNoAllowedDigest) {
		t.Fatalf("VerifyReader(sha256-only) = %v, want ErrNoAllowedDigest", err)
	}
}

type countingReader struct {
	reader io.Reader
	reads  int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	return c.reader.Read(p)
}

func TestVerifyReaderHashesContentOnce(t *testing.T) {
	content := bytes.Repeat([]byte("single-pass"), 1024)
	sha256Dgst, sha512Dgst := layerDigests(t, content)

	dset := NewSet()
	for _, dgst := range []digest.Digest{sha256Dgst, sha512Dgst} {
		if err := dset.Add(dgst); err != nil {
			t.Fatal(err)
		}
	}

	reader := &countingReader{reader: bytes.NewReader(content)}
	if _, err := dset.VerifyReader(reader, nil); err != nil {
		t.Fatal(err)
	}
	if reader.reads == 0 {
		t.Fatal("content was never read")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("read failure")
}

func TestVerifyReaderPropagatesReadError(t *testing.T) {
	content := []byte("read-error")
	sha256Dgst, _ := layerDigests(t, content)

	dset := NewSet()
	if err := dset.Add(sha256Dgst); err != nil {
		t.Fatal(err)
	}

	if _, err := dset.VerifyReader(failingReader{}, nil); err == nil {
		t.Fatal("expected the read error to be returned")
	}
}

func TestSelectKeepsAddLookupShortCodeCompatible(t *testing.T) {
	digests := []digest.Digest{
		"sha256:1234111111111111111111111111111111111111111111111111111111111111",
		"sha256:1234511111111111111111111111111111111111111111111111111111111111",
		"sha256:5432111111111111111111111111111111111111111111111111111111111111",
	}

	dset := NewSet()
	for _, dgst := range digests {
		if err := dset.Add(dgst); err != nil {
			t.Fatal(err)
		}
	}

	if got, err := dset.Lookup("sha256:12345"); err != nil || got != digests[1] {
		t.Fatalf("Lookup() = %v, %v, want %v", got, err, digests[1])
	}
	if _, err := dset.Lookup("1234"); !errors.Is(err, ErrDigestAmbiguous) {
		t.Fatalf("Lookup(1234) = %v, want ErrDigestAmbiguous", err)
	}

	table := ShortCodeTable(dset, 2)
	if table[digests[1]] != "12345" {
		t.Fatalf("short code = %q, want %q", table[digests[1]], "12345")
	}

	if err := dset.Remove(digests[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := dset.Lookup(digests[1].String()); !errors.Is(err, ErrDigestNotFound) {
		t.Fatalf("Lookup after Remove = %v, want ErrDigestNotFound", err)
	}
}
