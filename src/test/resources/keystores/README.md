# Test signing keystore for OID4VCI (Keycloak 26.8+)

A ready-to-use RSA 2048 signing keystore for integration tests. The private key
certificate is signed by a dedicated test CA (not self-signed), which Keycloak
26.8 requires for the SD-JWT `x5c` header (HAIP-6.1.1). The private key is the
same one historically configured directly in `test-realm.json` under the
`custom-rsa` provider, so no test-private-key material changes are introduced.

## Files

| File               | Description                                                          |
| ------------------ | -------------------------------------------------------------------- |
| `keystore-rsa.p12` | PKCS#12 keystore: `oid4vci-issuer` key + chain `[leaf, test CA]`     |

## Credentials

- **Keystore password:** `password`
- **Key alias:** `oid4vci-issuer`
- **Key password:** `password`
- **Keystore type:** `PKCS12`
- **Algorithm:** `RS256` (RSA 2048)

## Test CA

The leaf certificate is signed by a dedicated EC P-256 test CA named
`Test Signing CA`. Its certificate and private key are reproduced below so the
keystore can be regenerated deterministically.

```text
-----BEGIN CERTIFICATE-----
MIIBiTCCAS+gAwIBAgIUCxWTgdyG6O5X+Sag6JwUQx4WvbQwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPVGVzdCBTaWduaW5nIENBMB4XDTI2MTAxMjEwMzc0NloXDTM2
MTAwOTEwMzc0NlowGjEYMBYGA1UEAwwPVGVzdCBTaWduaW5nIENBMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAE61gaU80eYFTzNCOtCbhS4E+3JnO/+/+pe+sUuZ03
BgKPatT+hdaY3SJ/wGlihwgiL+B6RjuLfTJudNSJpEU2IaNTMFEwHQYDVR0OBBYE
FJFQuvd9TLD/3B7miR1+T0v3JTSwMB8GA1UdIwQYMBaAFJFQuvd9TLD/3B7miR1+
T0v3JTSwMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgFpKp+lrY
EbR97C/IzssLL+mss+NP1iZep2goRHQpmJICIQDp4+RqUhMXkhQACEyImctgWR+n
9fhHV+aAV+DqngeSGA==
-----END CERTIFICATE-----
```

```text
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIN+n2gaWgP3Yhu5ayMHAW4q++lSSqqrs7IMufuwAOF8ToAoGCCqGSM49
AwEHoUQDQgAE61gaU80eYFTzNCOtCbhS4E+3JnO/+/+pe+sUuZ03BgKPatT+hdaY
3SJ/wGlihwgiL+B6RjuLfTJudNSJpEU2IQ==
-----END EC PRIVATE KEY-----
```

> Test-only credentials. Never use them in production.
