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
	"errors"
)

// ErrDigestNotAllowed is returned by [Policy.Select] when none of the
// candidate digests uses an algorithm that is both permitted by the
// policy and available for verification. It deliberately replaces any
// implicit fall back to a weaker digest: callers must treat this error
// as a hard failure instead of picking another digest themselves.
var ErrDigestNotAllowed = errors.New("no digest allowed by the selection policy")

// Policy is an ordered allowlist of digest algorithms used to select and
// verify digests explicitly. Algorithms appearing earlier in the list
// take precedence, so the list order defines the strength ranking. A
// digest whose algorithm is not listed is never selected, and neither is
// a digest whose algorithm is not registered (see [RegisterAlgorithm]),
// since such a digest cannot be verified.
//
// A nil or empty Policy rejects every digest. Callers that require a
// specific algorithm should list only that algorithm; a missing strong
// digest then surfaces as [ErrDigestNotAllowed] instead of silently
// degrading verification to a weaker algorithm.
type Policy []Algorithm

// DefaultPolicy is the default algorithm allowlist, ordered from
// strongest to weakest. SHA-512 and SHA-384 rank above the canonical
// SHA-256; BLAKE3 with its default 256-bit output ranks last, below the
// canonical algorithm of equal size. Algorithms that are not registered
// in the current binary are skipped automatically, so the list may name
// optional algorithms such as SHA-384 and BLAKE3.
var DefaultPolicy = Policy{SHA512, SHA384, SHA256, BLAKE3}

// Allowed reports whether a may be selected under p. It only checks the
// allowlist; combine with [Algorithm.Available] when the digest must
// also be verifiable.
func (p Policy) Allowed(a Algorithm) bool {
	for _, allowed := range p {
		if allowed == a {
			return true
		}
	}
	return false
}

// Select returns the strongest candidate digest permitted by p.
// Strength follows the policy order: p is traversed from the strongest
// algorithm and the first candidate using an available, permitted
// algorithm wins. Candidates using an algorithm absent from p, an
// unregistered algorithm, or an invalid digest format are skipped
// because they cannot be verified.
//
// Select never falls back to an algorithm outside the policy. It
// returns [ErrDigestNotAllowed] when no candidate is selectable.
func (p Policy) Select(candidates ...Digest) (Digest, error) {
	for _, allowed := range p {
		if !allowed.Available() {
			continue
		}
		for _, candidate := range candidates {
			if candidate.Validate() == nil && candidate.Algorithm() == allowed {
				return candidate, nil
			}
		}
	}
	return "", ErrDigestNotAllowed
}
