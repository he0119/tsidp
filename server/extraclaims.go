// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"fmt"
	"log/slog"
	"slices"
)

// protectedClaims lists the claims that extraClaims is never allowed to overwrite. They either
// identify the subject or make the token verifiable, so a grant able to rewrite them could
// impersonate another user. Overwriting one of these is an error.
//
// This list is intentionally kept separate from openIDSupportedClaims, which is what the
// discovery document advertises: adding a claim to the metadata must not silently turn it into
// a claim that grants cannot extend.
//
// "email" is deliberately absent. The login name Tailscale reports is not always a real mailbox
// ("alice@github" after GitHub SSO, "alice@passkey" after a passkey login), so tailnets that
// front real mailboxes need to map it to their own address through extraClaims.
var protectedClaims = []string{
	// Standard JWT claims, these correspond to fields in jwt.Claims.
	"sub", "aud", "exp", "iat", "iss", "jti", "nbf",

	// Tailscale claims, these correspond to fields in tailscaleClaims.
	"username", "key", "addresses", "nid", "node", "tailnet", "tags", "user", "uid",
}

// withExtraClaims merges flattened extra claims from a list of capRule into the provided map[string]any,
// returning a map[string]any that combines both sources.
//
// Extra claims are flattened and merged into the base map unless they conflict with protectedClaims.
// If an extra claim attempts to overwrite a protected claim, an error is returned.
//
// Returns the merged claims map or an error if any protected claim is violated.
func withExtraClaims(claimMap map[string]any, rules []capRule) (map[string]any, error) {
	for k, v := range flattenExtraClaims(rules) {
		if slices.Contains(protectedClaims, k) {
			slog.Info("Skip overwriting of existing claim", slog.String("claim", k))
			return nil, fmt.Errorf("extra claim %q overwriting existing claim", k)
		}

		claimMap[k] = v
	}

	return claimMap, nil
}

// flattenExtraClaims merges all ExtraClaims from a slice of capRule into a single map.
// It deduplicates values for each claim and preserves the original input type:
// scalar values remain scalars, and slices are returned as deduplicated []any slices.
func flattenExtraClaims(rules []capRule) map[string]any {
	// sets stores deduplicated stringified values for each claim key.
	sets := make(map[string]map[string]struct{})

	// originalValues stores the original value for scalar claims to preserve types
	originalValues := make(map[string]any)

	// isSlice tracks whether each claim was originally provided as a slice.
	isSlice := make(map[string]bool)

	for _, rule := range rules {
		for claim, raw := range rule.ExtraClaims {
			// Track whether the claim was provided as a slice
			switch raw.(type) {
			case []string, []any:
				isSlice[claim] = true
			default:
				// Only mark as scalar if this is the first time we've seen this claim
				if _, seen := isSlice[claim]; !seen {
					isSlice[claim] = false
					// Store the original value for scalar claims
					originalValues[claim] = raw
				}
			}

			// Add the claim value(s) into the deduplication set
			addClaimValue(sets, claim, raw)
		}
	}

	// Build final result: either scalar or slice depending on original type
	result := make(map[string]any)
	for claim, valSet := range sets {
		if isSlice[claim] {
			// Claim was provided as a slice: output as []any
			var vals []any
			for val := range valSet {
				vals = append(vals, val)
			}
			result[claim] = vals
		} else {
			result[claim] = originalValues[claim]
		}
	}

	return result
}

// addClaimValue adds a claim value to the deduplication set for a given claim key.
// It accepts scalars (string, int, float64, bool), slices of strings or interfaces,
// and recursively handles nested slices. Unsupported types are ignored with a log message.
func addClaimValue(sets map[string]map[string]struct{}, claim string, val any) {
	switch v := val.(type) {
	case string, float64, int, int64, bool:
		// Ensure the claim set is initialized
		if sets[claim] == nil {
			sets[claim] = make(map[string]struct{})
		}
		// Add the stringified scalar to the set
		sets[claim][fmt.Sprintf("%v", v)] = struct{}{}

	case []string:
		// Ensure the claim set is initialized
		if sets[claim] == nil {
			sets[claim] = make(map[string]struct{})
		}
		// Add each string value to the set
		for _, s := range v {
			sets[claim][s] = struct{}{}
		}

	case []any:
		// Recursively handle each item in the slice
		for _, item := range v {
			addClaimValue(sets, claim, item)
		}

	default:
		// Log unsupported types for visibility and debugging
		slog.Warn("unsupported claim type",
			slog.String("claim", claim),
			slog.Any("value", v),
			slog.String("type", fmt.Sprintf("%T", v)),
		)
	}
}
