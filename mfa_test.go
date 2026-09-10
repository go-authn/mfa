// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package mfa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fake is a factor that answers however a test says.
type fake struct {
	name  string
	kind  Kind
	err   error
	asked *int
}

func (f fake) Name() string { return f.name }
func (f fake) Kind() Kind   { return f.kind }
func (f fake) Verify(context.Context) error {
	if f.asked != nil {
		*f.asked++
	}
	return f.err
}

func touchID(err error) fake { return fake{name: "Touch ID", kind: Inherence, err: err} }
func key(err error) fake     { return fake{name: "your security key", kind: Possession, err: err} }
func pass(err error) fake    { return fake{name: "your passphrase", kind: Knowledge, err: err} }

func TestTwoOfDifferentKindsIsTwoFactors(t *testing.T) {
	r, err := Verify(context.Background(), Policy{Count: 2, DistinctKinds: true}, touchID(nil), key(nil))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if r.Satisfied != 2 || r.Kinds != 2 {
		t.Errorf("%d satisfied across %d kinds", r.Satisfied, r.Kinds)
	}
	if got := r.String(); !strings.Contains(got, "Touch ID") || !strings.Contains(got, "security key") {
		t.Errorf("String() = %q", got)
	}
}

// TestTwoOfTheSameKindIsNotTwoFactors is the whole point of the package. A
// passphrase and a recovery code are both things you know: whoever learned one
// has usually learned the other from the same place.
func TestTwoOfTheSameKindIsNotTwoFactors(t *testing.T) {
	recovery := fake{name: "your recovery code", kind: Knowledge}
	r, err := Verify(context.Background(), Policy{Count: 2, DistinctKinds: true}, pass(nil), recovery)
	if err == nil {
		t.Fatal("two things the person knows were accepted as two factors")
	}
	if r.Satisfied != 2 {
		t.Errorf("%d satisfied, want both to have answered", r.Satisfied)
	}
	if r.Kinds != 1 {
		t.Errorf("%d kinds, want 1", r.Kinds)
	}
	if !strings.Contains(err.Error(), "not two factors") || !strings.Contains(err.Error(), "knowledge") {
		t.Errorf("the error says %q, which does not explain the refusal", err)
	}
	// And the same two ARE enough when the caller only asked for a count,
	// which is a different and legitimate request -- two keys, say, so that
	// losing one is survivable.
	if _, err := Verify(context.Background(), Policy{Count: 2}, pass(nil), recovery); err != nil {
		t.Errorf("a plain count of two refused two answers: %v", err)
	}
}

func TestAFactorThatCannotBeAskedHasNotFailed(t *testing.T) {
	// A laptop with no fingerprint reader has not refused anyone.
	absent := touchID(fmt.Errorf("no sensor: %w", ErrUnavailable))
	r, err := Verify(context.Background(), Policy{Count: 1}, absent, key(nil))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !r.Answers[0].Unavailable() {
		t.Error("an unavailable factor was not recognised as such")
	}
	if r.Answers[0].OK() {
		t.Error("an unavailable factor was counted as satisfied")
	}
	if got := r.Answers[0].String(); !strings.Contains(got, "not available") {
		t.Errorf("Answer.String() = %q", got)
	}
	// Even with StopOnFirstFailure, an unavailable factor does not end the
	// attempt: nothing refused.
	if _, err := Verify(context.Background(),
		Policy{Count: 1, StopOnFirstFailure: true}, absent, key(nil)); err != nil {
		t.Errorf("an unavailable factor ended the attempt: %v", err)
	}
}

func TestARefusalIsNamed(t *testing.T) {
	wrong := errors.New("wrong passphrase")
	r, err := Verify(context.Background(), Policy{Count: 2, DistinctKinds: true}, pass(wrong), key(nil))
	if err == nil {
		t.Fatal("a refused factor was accepted")
	}
	if !strings.Contains(err.Error(), "passphrase") || !strings.Contains(err.Error(), "wrong passphrase") {
		t.Errorf("the error says %q, which does not name what refused", err)
	}
	if r.Satisfied != 1 {
		t.Errorf("%d satisfied, want 1", r.Satisfied)
	}
}

// TestEveryFactorIsAskedByDefault. Telling a person "your key answered, your
// fingerprint did not" needs both answers; stopping at the first failure tells
// them one thing at a time, across as many attempts as they have factors.
func TestEveryFactorIsAskedByDefault(t *testing.T) {
	var asked int
	second := fake{name: "your security key", kind: Possession, asked: &asked}
	if _, err := Verify(context.Background(), Policy{Count: 2},
		pass(errors.New("no")), second); err == nil {
		t.Fatal("a failed attempt was accepted")
	}
	if asked != 1 {
		t.Errorf("the second factor was asked %d time(s), want 1", asked)
	}

	asked = 0
	_, err := Verify(context.Background(), Policy{Count: 2, StopOnFirstFailure: true},
		pass(errors.New("no")), second)
	if err == nil {
		t.Fatal("a failed attempt was accepted")
	}
	if asked != 0 {
		t.Errorf("StopOnFirstFailure still asked the second factor %d time(s)", asked)
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Errorf("the error says %q", err)
	}
}

// TestAFactorNotReachedIsNotReportedAsFailed: saying it failed would be a lie,
// and a person told to fix a factor nobody asked would be sent after nothing.
func TestAFactorNotReachedIsNotReportedAsFailed(t *testing.T) {
	r, _ := Verify(context.Background(), Policy{Count: 2, StopOnFirstFailure: true},
		pass(errors.New("no")), key(nil))
	if len(r.Answers) != 1 {
		t.Fatalf("%d answers, want only the one that was asked", len(r.Answers))
	}
}

func TestAPolicyThatCannotBeMet(t *testing.T) {
	for _, c := range []struct {
		name    string
		p       Policy
		factors []Factor
		want    string
	}{
		{"no factors required", Policy{Count: 0}, []Factor{key(nil)}, "accepts anyone"},
		{"a negative count", Policy{Count: -1}, []Factor{key(nil)}, "accepts anyone"},
		{"more required than offered", Policy{Count: 3}, []Factor{key(nil), pass(nil)}, "were offered"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Verify(context.Background(), c.p, c.factors...); err == nil {
				t.Fatal("accepted")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q, which does not mention %q", err, c.want)
			}
		})
	}
}

// TestAnUnclassifiedFactorNeverCountsTowardsKinds: it cannot be shown to differ
// from anything, so counting it would let two unclassified factors pass as
// two-factor.
func TestAnUnclassifiedFactorNeverCountsTowardsKinds(t *testing.T) {
	a := fake{name: "something", kind: Unknown}
	b := fake{name: "something else", kind: Unknown}
	r, err := Verify(context.Background(), Policy{Count: 2, DistinctKinds: true}, a, b)
	if err == nil {
		t.Fatal("two unclassified factors passed as two-factor")
	}
	if r.Kinds != 0 {
		t.Errorf("%d kinds counted among unclassified factors", r.Kinds)
	}
	if !strings.Contains(err.Error(), "none classified") {
		t.Errorf("the error says %q", err)
	}
}

func TestGivingUpPartWayThrough(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := Verify(ctx, Policy{Count: 1}, key(nil)); err == nil {
		t.Fatal("a cancelled attempt was accepted")
	} else if !strings.Contains(err.Error(), "part way") {
		t.Errorf("the error says %q", err)
	}
}

func TestKindsAreNamed(t *testing.T) {
	for k, want := range map[Kind]string{
		Knowledge: "knowledge", Possession: "possession",
		Inherence: "inherence", Unknown: "unknown",
	} {
		if got := k.String(); got != want {
			t.Errorf("Kind(%d) = %q, want %q", int(k), got, want)
		}
	}
	if got := Kind(9).String(); !strings.Contains(got, "9") {
		t.Errorf("an unnamed kind renders as %q", got)
	}
}

func TestTheSummaryNamesEveryAnswer(t *testing.T) {
	r, _ := Verify(context.Background(), Policy{Count: 3},
		touchID(nil), key(errors.New("not plugged in")), pass(fmt.Errorf("x: %w", ErrUnavailable)))
	got := r.String()
	for _, want := range []string{"Touch ID", "yes", "not plugged in", "not available"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q does not contain %q", got, want)
		}
	}
	// refusals() names causes rather than a count.
	_, err := Verify(context.Background(), Policy{Count: 3},
		touchID(nil), key(errors.New("not plugged in")), pass(nil))
	if err == nil || !strings.Contains(err.Error(), "not plugged in") {
		t.Errorf("the error says %v", err)
	}
}

// TestRefusalsWhenNothingRefused covers the case where the count is short but
// every answer was either yes or unavailable -- so the message must not claim
// something refused.
func TestRefusalsWhenNothingRefused(t *testing.T) {
	r := Result{Answers: []Answer{{Name: "a", Err: nil}}}
	if got := refusals(r); got != "nothing refused" {
		t.Errorf("refusals = %q", got)
	}
}

// Unavailable marks a reason without losing it, and reads as unavailable to
// the thing that has to count it.
func TestUnavailableKeepsTheReason(t *testing.T) {
	reason := errors.New("no key is plugged in")
	err := Unavailable(reason)
	if !errors.Is(err, ErrUnavailable) {
		t.Error("the marked error is not unavailable")
	}
	if !errors.Is(err, reason) {
		t.Error("the reason was lost")
	}
	if !strings.Contains(err.Error(), "no key is plugged in") {
		t.Errorf("the message reads %q", err)
	}
	// A factor answering it is counted as not asked, rather than as a refusal.
	r, err := Verify(context.Background(), Policy{Count: 1},
		touchID(Unavailable(reason)), key(nil))
	if err != nil {
		t.Fatalf("a satisfied policy reported %v", err)
	}
	if !r.Answers[0].Unavailable() {
		t.Error("the answer does not read as unavailable")
	}

	// Nothing to say is still unavailable: an adapter with no detail should
	// not have to invent one.
	if !errors.Is(Unavailable(nil), ErrUnavailable) {
		t.Error("Unavailable(nil) is not unavailable")
	}
}
