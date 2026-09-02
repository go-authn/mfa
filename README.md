# mfa

Decides whether enough factors answered, and says which ones. Pure Go, no
platform, no cryptography, no device.

```go
r, err := mfa.Verify(ctx, mfa.Policy{Count: 2, DistinctKinds: true},
    touchID,      // go-macos/localauthentication
    securityKey,  // go-authn/fido
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

Covered to 100%, on every platform, with no hardware.
