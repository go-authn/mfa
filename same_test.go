// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package mfa

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// opened is a factor that, like go-authn/keyfactor's, holds a func.
type opened struct {
	name  string
	check func(context.Context) error
}

func (f opened) Name() string { return f.name }
func (f opened) Kind() Kind   { return Possession }
func (f opened) Verify(ctx context.Context) error {
	if f.check == nil {
		return context.Canceled
	}
	return f.check(ctx)
}

func yes(context.Context) error { return nil }
func no(context.Context) error  { return context.Canceled }

// ⛔ A factor holding a func, passed twice, is one factor. reflect.DeepEqual is
// never true for two non-nil funcs, so the very same value passed twice was
// counted twice and satisfied a Count of two.
func TestTheSameFactorHoldingAFuncTwiceIsOneFactor(t *testing.T) {
	asked := 0
	f := opened{name: "your security key", check: func(context.Context) error { asked++; return nil }}
	for _, c := range []struct {
		name    string
		factors []Factor
	}{
		{"the same value", []Factor{f, f}},
		{"the same pointer", []Factor{&f, &f}},
		{"an equal copy", []Factor{f, opened{name: f.name, check: f.check}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			asked = 0
			r, err := Verify(context.Background(), Policy{Count: 2}, c.factors...)
			if err == nil {
				t.Fatalf("one factor holding a func, passed twice, satisfied a Count of two: %s", r)
			}
			if !strings.Contains(err.Error(), "twice") {
				t.Errorf("error = %q", err)
			}
			if asked != 0 {
				t.Errorf("the factor was asked %d time(s) before the refusal", asked)
			}
		})
	}
	// Two that run different code, or are named differently, are two.
	for _, pair := range [][2]Factor{
		{opened{"key A", yes}, opened{"key A", no}},
		{opened{"key A", yes}, opened{"key B", yes}},
		{opened{"key A", nil}, opened{"key A", yes}},
	} {
		if _, err := Verify(context.Background(), Policy{Count: 1}, pair[0], pair[1]); err != nil && strings.Contains(err.Error(), "twice") {
			t.Errorf("two different factors were taken for one: %v", err)
		}
	}
}

// node is a value that can point back at itself.
type node struct {
	next *node
	v    int
}

// TestSameComparesEveryShapeOfValue walks the comparison through each kind it
// recurses into, both ways round: a comparison that only ever said "same"
// would refuse every second factor, and one that only said "different" is the
// defect this replaced.
func TestSameComparesEveryShapeOfValue(t *testing.T) {
	type pair struct {
		name string
		a, b any
		want bool
	}
	one, other := 1, 1
	loopA := &node{v: 1}
	loopA.next = loopA
	loopB := &node{v: 1}
	loopB.next = loopB
	loopC := &node{v: 2}
	loopC.next = loopC
	for _, c := range []pair{
		{"different types", 1, "1", false},
		{"equal ints", 1, 1, true},
		{"different ints", 1, 2, false},
		{"nil funcs", (func())(nil), (func())(nil), true},
		{"a nil func and a func", (func())(nil), func() {}, false},
		{"pointers to equal values", &one, &other, true},
		{"a nil pointer and a pointer", (*int)(nil), &one, false},
		{"two nil pointers", (*int)(nil), (*int)(nil), true},
		{"equal cycles", loopA, loopB, true},
		{"different cycles", loopA, loopC, false},
		{"equal slices", []int{1, 2}, []int{1, 2}, true},
		{"slices of different lengths", []int{1}, []int{1, 2}, false},
		{"slices that differ", []int{1, 2}, []int{1, 3}, false},
		{"a nil slice and an empty one", []int(nil), []int{}, false},
		{"equal maps", map[string]int{"a": 1}, map[string]int{"a": 1}, true},
		{"maps that differ in a value", map[string]int{"a": 1}, map[string]int{"a": 2}, false},
		{"maps that differ in a key", map[string]int{"a": 1}, map[string]int{"b": 1}, false},
		{"maps of different sizes", map[string]int{"a": 1}, map[string]int{}, false},
		{"equal arrays", [2]int{1, 2}, [2]int{1, 2}, true},
		{"arrays that differ", [2]int{1, 2}, [2]int{1, 3}, false},
		{"equal interfaces", []any{1}, []any{1}, true},
		{"interfaces holding different types", []any{1}, []any{"1"}, false},
		{"a nil interface and a value", []any{nil}, []any{1}, false},
		{"two nil interfaces", []any{nil}, []any{nil}, true},
	} {
		if got := same(valueOf(c.a), valueOf(c.b), map[visit]bool{}); got != c.want {
			t.Errorf("%s: same = %v, want %v", c.name, got, c.want)
		}
	}
	// The same slice and the same map are the same without being walked.
	s, m := []int{1}, map[int]int{1: 1}
	if !same(valueOf(s), valueOf(s), map[visit]bool{}) || !same(valueOf(m), valueOf(m), map[visit]bool{}) {
		t.Error("a slice or map was not the same as itself")
	}
}

func valueOf(v any) reflect.Value { return reflect.ValueOf(v) }
