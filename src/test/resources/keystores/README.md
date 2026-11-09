# Test signing keystores for OID4VCI (Keycloak 26.8+)

Ready-to-use RSA 2048 signing keystores for integration tests. Their leaf
certificates are signed by dedicated test CAs (not self-signed), which Keycloak
26.8 requires for the SD-JWT `x5c` header (HAIP-6.1.1). The `oid4vci-issuer`
private key is the same one historically configured directly in
`test-realm.json` under the `custom-rsa` provider, so no test-private-key
material changes are introduced.

Both keystores share the **same RSA 2048 leaf private key** and the **same root
CA** (`Test Signing CA`). `keystore-chain-rsa.p12` reuses that same private key,
wrapped in a three-level chain `[leaf, intermediate, root]`, so the two realms
sign with the identical key while exercising different `x5c` chain shapes.

## Files

| File                     | Description                                                                                        |
|--------------------------|----------------------------------------------------------------------------------------------------|
| `keystore-rsa.p12`       | PKCS#12 keystore: `oid4vci-issuer` key + chain `[leaf, Test Signing CA]`                           |
| `keystore-chain-rsa.p12` | PKCS#12 keystore: `test-metadata-leaf` key + chain `[leaf, Test Intermediate CA, Test Signing CA]` |

## Credentials

Shared by both keystores:

- **Keystore/Key password:** `password`
- **Keystore type:** `PKCS12`
- **Algorithm:** `RS256` (RSA 2048)
- **Key alias (`keystore-rsa.p12`):** `oid4vci-issuer`
- **Key alias (`keystore-chain-rsa.p12`):** `test-metadata-leaf`

## Root CA (`Test Signing CA`)

The self-signed EC P-256 root CA named `Test Signing CA` roots both keystores.
It signs the `oid4vci-issuer` leaf directly in `keystore-rsa.p12`, and the `Test
Intermediate CA` of `keystore-chain-rsa.p12`. Its certificate and private key
are reproduced below so the keystores can be regenerated deterministically.

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

## Intermediate CA (`Test Intermediate CA`)

```text
-----BEGIN CERTIFICATE-----
MIIBoTCCAUegAwIBAgIUfA5pXRYhbKaU/sMugTgJYJQOjUIwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPVGVzdCBTaWduaW5nIENBMB4XDTI2MTEwOTA4MjEzMloXDTM2
MTEwNjA4MjEzMlowHzEdMBsGA1UEAwwUVGVzdCBJbnRlcm1lZGlhdGUgQ0EwWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAAT68cwVIIt8BETrme3x3BTMyij35i9iwwlm
pvf0bQDSYaeQ3dlCwYfSmgqRZZBSiVOKYlQsYfZC65foEf8SLbB0o2YwZDASBgNV
HRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUdP6gv8dz
we0LeXx8FI0BH4ecDdwwHwYDVR0jBBgwFoAUkVC6931MsP/cHuaJHX5PS/clNLAw
CgYIKoZIzj0EAwIDSAAwRQIhAJQb9DMKH5SoOcSCDNr/jzdz3N6jB4V3rSCO9P/N
zcgOAiB3Emx+0L0qnldNCNv47xMAKB5BqzWdjDWRWTX5MSjIpw==
-----END CERTIFICATE-----
```

```text
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpe8nxDw7vno0XqVL
CBLEsDJ2A+GH7rTODwpOc7D9MXehRANCAAT68cwVIIt8BETrme3x3BTMyij35i9i
wwlmpvf0bQDSYaeQ3dlCwYfSmgqRZZBSiVOKYlQsYfZC65foEf8SLbB0
-----END PRIVATE KEY-----
```

> Test-only credentials. Never use them in production.
