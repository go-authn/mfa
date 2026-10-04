# mfa

[![Go Reference](https://pkg.go.dev/badge/github.com/go-authn/mfa.svg)](https://pkg.go.dev/github.com/go-authn/mfa)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/mfa/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/mfa/actions/workflows/ci.yml)

Decides whether enough factors answered, and says which ones. Pure Go, no
platform, no cryptography, no device.

```go
r, err := mfa.Verify(ctx, mfa.Policy{Count: 2, DistinctKinds: true},
    factors.TouchID("unlock the vault"),         // go-macos/factors, over LocalAuthentication
    factors.SecurityKey("example.test", credID), // go-macos/factors, over go-authn/fido
)
if err != nil {
    fmt.Println(err)   // "mfa: 2 factor(s) needed, 1 answered: your security key (possession): not available"
}
```

## Two of the same thing is one factor

The phrase is multi-**factor**, not multi-check. A passphrase and a recovery
code are both things you know: whoever learned one has usually learned the other
from the same place, and requiring both buys far less than the count suggests.

So the classification is the point. `Policy{Count: 2, DistinctKinds: true}` is
what *two-factor* is normally taken to mean, and two passphrases never satisfy
it. `Policy{Count: 2}` on its own is also offered, because a caller who wants
two keys — two of the same kind, deliberately, so losing one is survivable — is
asking for something real. It is simply not the same request, and the two are
not spelled the same way here.

The three kinds are the classical ones: `Knowledge` (something you know),
`Possession` (something you have), `Inherence` (something you are). A factor
that does not classify itself counts towards the number satisfied but never
towards the kinds — it cannot be shown to differ from anything.

## What it refuses to confuse

- **A factor that could not be asked has not failed.** A laptop with no
  fingerprint reader refused nobody. `ErrUnavailable` is reported separately,
  and it never ends an attempt. An adapter returns `mfa.Unavailable(err)`,
  which wraps that sentinel and keeps the reason (an empty USB port, nobody
  enrolled); `Answer.Unavailable` reads it back.
- **Every factor is asked by default.** Telling a person *your key answered,
  your fingerprint did not* needs both answers; stopping at the first failure
  tells them one thing at a time, across as many attempts as they have factors.
  `StopOnFirstFailure` is there when that is wanted, and off otherwise.
- **A factor not reached is not reported as failed.** It has no entry in the
  result at all, because saying it failed would send somebody after nothing.
- **The same factor twice is one factor.** Two factors of the same type
  holding the same values are refused before anything is asked: counted twice,
  one passphrase passed twice satisfied `Count: 2`. Two keys that differ in
  anything — a name, a credential ID — are two factors.
  ⛔ "The same values" includes funcs, which `reflect.DeepEqual` (used here
  first) never finds equal: a factor holding an opener or a callback, as
  `go-authn/keyfactor`'s does, passed twice, was counted twice. A func is now
  the same func when it runs the same code. That is all reflection can see, so
  two closures from one literal that differ only in what they captured are
  taken for one factor and refused — the safe side; give them any other field
  that differs.
- **A kind outside the enum is not a kind.** A factor whose `Kind()` is not
  `Unknown`, `Knowledge`, `Possession` or `Inherence` is refused, whatever the
  policy, before anything is asked: counted as a distinct kind, `Kind(42)` next
  to a passphrase passed as two-factor.
- **There is no default policy.** The zero `Policy` is refused rather than
  guessed at: how much proof is enough belongs to whoever is protecting the
  thing, not to a library.

## Where the factors come from

Nothing here reaches a device, on purpose: this package decides, and the
things it asks live elsewhere. On macOS they are
[go-macos/factors](https://github.com/go-macos/factors) — Touch ID over
LocalAuthentication, and a security key over
[go-authn/fido](https://github.com/go-authn/fido).

A binding does not implement `Factor` itself. If it did, every program that
only wanted to show a Touch ID prompt would pull in a policy package, so the
adapters sit above both and nothing below them knows what a policy is.

Covered to 100%, on every platform, with no hardware.
