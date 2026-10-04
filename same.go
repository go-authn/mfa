// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package mfa

import "reflect"

// sameFactor reports whether two factors are the same factor: the same type
// holding the same values, where a func is the same func when it runs the same
// code.
//
// ⛔ It is not [reflect.DeepEqual], which was used here first and is never true
// for two non-nil funcs -- not even for one func compared with itself. Every
// factor that holds a func (an opener, a check, a callback: go-authn/keyfactor's
// does) was therefore never "the same" as anything, and the very same value,
// passed twice, satisfied a Count of two.
//
// A func is compared by its code pointer, which is all reflect can see. Two
// closures made from the same literal therefore compare equal whatever they
// captured, and two factors that differ ONLY in that are refused as one. That
// is the safe side to err on: the alternative counts one factor twice, and a
// caller who really holds two can tell them apart by any other field -- a name,
// a credential ID.
func sameFactor(a, b Factor) bool {
	return same(reflect.ValueOf(a), reflect.ValueOf(b), map[visit]bool{})
}

// visit is a pair of references already being compared, which is what stops a
// cyclic value from recursing for ever. As in reflect.DeepEqual, a pair met
// again is assumed equal: if it is not, the comparison in progress says so.
type visit struct {
	a, b uintptr
	t    reflect.Type
}

func same(a, b reflect.Value, seen map[visit]bool) bool {
	if !a.IsValid() || !b.IsValid() {
		return a.IsValid() == b.IsValid()
	}
	if a.Type() != b.Type() {
		return false
	}
	switch a.Kind() {
	case reflect.Func:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() && b.IsNil()
		}
		return a.Pointer() == b.Pointer()
	case reflect.Pointer, reflect.Map, reflect.Slice:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() && b.IsNil()
		}
		if a.Kind() != reflect.Pointer && a.Len() != b.Len() {
			return false
		}
		if a.Pointer() == b.Pointer() {
			return true
		}
		v := visit{a.Pointer(), b.Pointer(), a.Type()}
		if seen[v] {
			return true
		}
		seen[v] = true
		switch a.Kind() {
		case reflect.Pointer:
			return same(a.Elem(), b.Elem(), seen)
		case reflect.Map:
			for it := a.MapRange(); it.Next(); {
				if !same(it.Value(), b.MapIndex(it.Key()), seen) {
					return false
				}
			}
			return true
		}
		return sameElements(a, b, seen)
	case reflect.Interface:
		return same(a.Elem(), b.Elem(), seen)
	case reflect.Array:
		return sameElements(a, b, seen)
	case reflect.Struct:
		for i := range a.NumField() {
			if !same(a.Field(i), b.Field(i), seen) {
				return false
			}
		}
		return true
	}
	return a.Equal(b)
}

// sameElements compares two slices or arrays of the same length, element by
// element.
func sameElements(a, b reflect.Value, seen map[visit]bool) bool {
	for i := range a.Len() {
		if !same(a.Index(i), b.Index(i), seen) {
			return false
		}
	}
	return true
}
