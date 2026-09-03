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
    fmt.Println(err)   // "2 factor(s) needed, 1 answered: your security key (possession): not plugged in"
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
  and it never ends an attempt.
- **Every factor is asked by default.** Telling a person *your key answered,
  your fingerprint did not* needs both answers; stopping at the first failure
  tells them one thing at a time, across as many attempts as they have factors.
  `StopOnFirstFailure` is there when that is wanted, and off otherwise.
- **A factor not reached is not reported as failed.** It has no entry in the
  result at all, because saying it failed would send somebody after nothing.
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
