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
	"errors"
	"fmt"
	"io"

	"github.com/opencontainers/go-digest"
)

var (
	// ErrNoAllowedDigest is returned when the set contains no digest
	// whose algorithm is both permitted by the selection policy and
	// available for verification. It is a hard failure: callers must
	// not silently fall back to a weaker or unregistered digest.
	ErrNoAllowedDigest = errors.New("digest set contains no digest allowed by the selection policy")

	// ErrDigestMismatch is returned by [Set.VerifyReader] when at least
	// one verifiable candidate digest does not match the content.
	ErrDigestMismatch = errors.New("content did not match a digest in the set")
)

// Select returns the strongest digest in the set permitted by policy.
// Algorithms are ranked by their position in policy, the first entry
// being the strongest, matching [digest.Policy.Select]. Digests using
// an algorithm outside the policy or an unregistered algorithm are
// skipped because they cannot be verified, so Select never degrades to
// a weaker digest without the caller opting in through policy.
//
// It returns [ErrNoAllowedDigest] when the set has no selectable
// digest. A nil policy is treated as [digest.DefaultPolicy].
func (dst *Set) Select(policy digest.Policy) (digest.Digest, error) {
	if policy == nil {
		policy = digest.DefaultPolicy
	}

	dst.mutex.RLock()
	defer dst.mutex.RUnlock()

	candidates := make([]digest.Digest, 0, len(dst.entries))
	for _, entry := range dst.entries {
		candidates = append(candidates, entry.digest)
	}

	selected, err := policy.Select(candidates...)
	if err != nil {
		return "", ErrNoAllowedDigest
	}
	return selected, nil
}

// VerifyReader selects the strongest digest permitted by policy and
// verifies the complete content of rd against every verifiable digest
// in the set. All verifiable candidates must match: any mismatch,
// including a mismatch from a digest weaker than the selected one,
// fails verification with [ErrDigestMismatch]. The content is hashed
// only once, fan-out to every candidate verifier.
//
// Digests whose algorithm is unregistered are not verifiable and are
// skipped rather than treated as failures. Selection itself follows
// [Set.Select], so an empty set or a set without any permitted,
// verifiable digest returns [ErrNoAllowedDigest] instead of silently
// falling back to a weak algorithm.
//
// On success the selected digest is returned. A nil policy is treated
// as [digest.DefaultPolicy].
func (dst *Set) VerifyReader(rd io.Reader, policy digest.Policy) (digest.Digest, error) {
	if policy == nil {
		policy = digest.DefaultPolicy
	}

	selected, err := dst.Select(policy)
	if err != nil {
		return "", err
	}

	dst.mutex.RLock()
	candidates := make([]digest.Digest, 0, len(dst.entries))
	for _, entry := range dst.entries {
		if entry.alg.Available() {
			candidates = append(candidates, entry.digest)
		}
	}
	dst.mutex.RUnlock()

	verifiers := make([]digest.Verifier, 0, len(candidates))
	writers := make([]io.Writer, 0, len(candidates))
	for _, candidate := range candidates {
		verifier := candidate.Verifier()
		verifiers = append(verifiers, verifier)
		writers = append(writers, verifier)
	}

	if _, err := io.Copy(io.MultiWriter(writers...), rd); err != nil {
		return "", fmt.Errorf("reading content for digest verification: %w", err)
	}

	for index, verifier := range verifiers {
		if !verifier.Verified() {
			return "", fmt.Errorf("%w: %s", ErrDigestMismatch, candidates[index])
		}
	}

	return selected, nil
}
