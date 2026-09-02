// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package mfa decides whether enough factors answered, and says which ones.
//
// It holds no cryptography and speaks to no device. A [Factor] is anything that
// can be asked "is this person here, now?" and answer yes, no, or "I cannot be
// asked at the moment" -- Touch ID through go-macos/localauthentication, a
// security key through go-authn/fido, a passphrase, a code from a phone. What
// is here is the part that has to be right whatever those are: how many
// answers, of which kinds, and what to say when some of them fail.
//
// # Two of the same thing is one factor
//
// The phrase is multi-FACTOR, not multi-check. A password and a security
// question are both things you know: someone who learned one has usually
// learned the other from the same place, and requiring both buys far less than
// the count suggests. The classification is the point of the exercise, so
// [Policy.DistinctKinds] asks for answers of DIFFERENT kinds and is the setting
// that means what "two-factor" is normally taken to mean.
//
// [Policy.Count] alone is also offered, because a caller who wants two keys --
// two of the same kind, deliberately, so that losing one is survivable -- is
// asking for something real. It is simply not the same request, and the two are
// not spelled the same way here.
package mfa

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Kind is what a factor proves. The three are the classical ones, and the
// distinction is not decoration: [Policy.DistinctKinds] counts by it.
type Kind int

// The kinds of proof.
const (
	// Unknown is a factor that did not say. It never satisfies a policy that
	// asks for distinct kinds, because an unclassified factor cannot be shown
	// to differ from another.
	Unknown Kind = iota
	// Knowledge is something the person knows: a passphrase, a PIN, a recovery
	// code.
	Knowledge
	// Possession is something they have: a security key, a phone, a smart
	// card.
	Possession
	// Inherence is something they are: a fingerprint, a face, a voice.
	Inherence
)

// String names the kind.
func (k Kind) String() string {
	switch k {
	case Knowledge:
		return "knowledge"
	case Possession:
		return "possession"
	case Inherence:
		return "inherence"
	case Unknown:
		return "unknown"
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}

// Factor is one way of asking whether the person is here.
//
// Verify returns nil when the factor is satisfied. It should return
// [ErrUnavailable], wrapped or not, when it cannot be asked at all -- no key
// plugged in, no sensor on this machine -- which a policy treats differently
// from a refusal: a factor that was never asked has not failed.
type Factor interface {
	// Name is what a person is told to do: "Touch ID", "your security key".
	Name() string
	// Kind is what this factor proves.
	Kind() Kind
	// Verify asks it.
	Verify(ctx context.Context) error
}

// ErrUnavailable means a factor could not be asked. It is not a failure: a
// laptop with no fingerprint reader has not refused anyone.
var ErrUnavailable = errors.New("mfa: this factor cannot be asked here")

// Policy is what "enough" means.
//
// The zero Policy is not usable and [Verify] says so rather than guessing:
// there is no sensible default for how much proof is enough, and a library that
// picked one would be deciding something that belongs to whoever is protecting
// the thing.
type Policy struct {
	// Count is how many factors must be satisfied.
	Count int
	// DistinctKinds requires the satisfied factors to be of different kinds --
	// what "two-factor" is normally taken to mean. With it, two passphrases
	// never satisfy a Count of two.
	DistinctKinds bool
	// StopOnFirstFailure abandons the attempt as soon as one factor refuses,
	// instead of asking the rest.
	//
	// It is false by default, deliberately. Asking every factor and reporting
	// all of the answers is what lets a person be told "your key answered, your
	// fingerprint did not" -- and asking a security key AFTER a fingerprint has
	// already failed costs nothing but a moment, while stopping early tells
	// them one thing at a time across as many attempts as they have factors.
	StopOnFirstFailure bool
}

// Answer is what one factor said.
type Answer struct {
	Name string
	Kind Kind
	// Err is nil when the factor was satisfied, [ErrUnavailable] when it could
	// not be asked, and whatever it returned otherwise.
	Err error
}

// OK reports whether this factor was satisfied.
func (a Answer) OK() bool { return a.Err == nil }

// Unavailable reports whether the factor could not be asked at all.
func (a Answer) Unavailable() bool { return errors.Is(a.Err, ErrUnavailable) }

// String renders the answer the way a log line reads.
func (a Answer) String() string {
	switch {
	case a.OK():
		return fmt.Sprintf("%s (%s): yes", a.Name, a.Kind)
	case a.Unavailable():
		return fmt.Sprintf("%s (%s): not available", a.Name, a.Kind)
	}
	return fmt.Sprintf("%s (%s): %v", a.Name, a.Kind, a.Err)
}

// Result is what every factor said, and whether that was enough.
type Result struct {
	// Answers is one entry per factor, in the order they were asked. A factor
	// not reached because [Policy.StopOnFirstFailure] ended the attempt has no
	// entry: it was not asked, and saying it failed would be a lie.
	Answers []Answer
	// Satisfied is how many answered yes, and Kinds how many DISTINCT kinds
	// those were.
	Satisfied int
	Kinds     int
}

// String summarises the attempt.
func (r Result) String() string {
	var parts []string
	for _, a := range r.Answers {
		parts = append(parts, a.String())
	}
	return fmt.Sprintf("%d satisfied across %d kind(s): %s",
		r.Satisfied, r.Kinds, strings.Join(parts, "; "))
}

// Verify asks the factors and decides.
//
// The error, when there is one, says what was missing in words a person can
// act on -- which factor refused, or that two answers of the same kind are not
// two factors. The [Result] is returned whether or not the policy was met,
// because a caller that must tell somebody what to try next needs the detail
// either way.
func Verify(ctx context.Context, p Policy, factors ...Factor) (Result, error) {
	if p.Count < 1 {
		return Result{}, fmt.Errorf("mfa: a policy that requires %d factors accepts anyone", p.Count)
	}
	if len(factors) < p.Count {
		return Result{}, fmt.Errorf("mfa: the policy needs %d factor(s) and %d were offered",
			p.Count, len(factors))
	}

	var r Result
	kinds := map[Kind]bool{}
	for _, f := range factors {
		if err := ctx.Err(); err != nil {
			return r, fmt.Errorf("mfa: gave up part way through: %w", err)
		}
		a := Answer{Name: f.Name(), Kind: f.Kind(), Err: f.Verify(ctx)}
		r.Answers = append(r.Answers, a)
		if a.OK() {
			r.Satisfied++
			// An unclassified factor counts towards the number satisfied but
			// never towards the kinds: it cannot be shown to differ from
			// anything.
			if a.Kind != Unknown {
				kinds[a.Kind] = true
			}
		}
		r.Kinds = len(kinds)
		if !a.OK() && !a.Unavailable() && p.StopOnFirstFailure {
			return r, fmt.Errorf("mfa: %s refused: %w", a.Name, a.Err)
		}
	}

	if r.Satisfied < p.Count {
		return r, fmt.Errorf("mfa: %d factor(s) needed, %d answered: %s",
			p.Count, r.Satisfied, refusals(r))
	}
	if p.DistinctKinds && r.Kinds < p.Count {
		return r, fmt.Errorf("mfa: %d factor(s) answered but only %d kind(s) among them (%s); "+
			"two of the same kind are not two factors",
			r.Satisfied, r.Kinds, kindList(r))
	}
	return r, nil
}

// refusals lists what went wrong, so the error names causes rather than a
// count.
func refusals(r Result) string {
	var parts []string
	for _, a := range r.Answers {
		if !a.OK() {
			parts = append(parts, a.String())
		}
	}
	if len(parts) == 0 {
		return "nothing refused"
	}
	return strings.Join(parts, "; ")
}

// kindList names the distinct kinds that answered, sorted so the message does
// not depend on the order the factors were given in.
func kindList(r Result) string {
	seen := map[string]bool{}
	var names []string
	for _, a := range r.Answers {
		if a.OK() && a.Kind != Unknown && !seen[a.Kind.String()] {
			seen[a.Kind.String()] = true
			names = append(names, a.Kind.String())
		}
	}
	if len(names) == 0 {
		return "none classified"
	}
	sort.Strings(names)
	return strings.Join(names, " and ")
}
