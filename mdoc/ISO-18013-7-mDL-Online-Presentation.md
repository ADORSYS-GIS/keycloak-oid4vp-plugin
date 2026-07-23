# ISO/IEC TS 18013-7 - mDL Online Presentation Guide

> **What is this?** This document explains ISO/IEC TS 18013-7, which extends the mDL (mobile Driving Licence) standard to support **remote/online presentation** via the internet, primarily using OID4VP (OpenID for Verifiable Presentations).

---

## Table of Contents
- [Introduction](#introduction)
- [Scope](#scope)
- [Relationship to Part 5](#relationship-to-part-5)
- [Key Terms](#key-terms)
- [Interfaces](#interfaces)
- [Design Objectives](#design-objectives)
- [Technical Requirements](#technical-requirements)
- [Data Exchange Flows](#data-exchange-flows)
- [Data Retrieval Methods](#data-retrieval-methods)
- [Device Retrieval Engagement](#device-retrieval-engagement)
- [Security Mechanisms](#security-mechanisms)
- [Protocol Considerations](#protocol-considerations)
- [mDL Data Model](#mdl-data-model)
- [Annex A: Device Retrieval to Website](#annex-a-device-retrieval-to-website)
  - [A.1 ReaderEngagement Structure](#a1-readerengagement-structure)
  - [A.2 DeviceEngagement Structure](#a2-deviceengagement-structure)
  - [A.3 OriginInfo Structure](#a3-origininfo-structure)
  - [A.4 mdoc URI Scheme](#a4-mdoc-uri-scheme)
  - [A.5 mdoc MAC Authentication](#a5-mdoc-mac-authentication)
  - [A.6 Device Retrieval to Website](#a6-device-retrieval-to-website)
  - [A.7 Session Encryption](#a7-session-encryption)
  - [A.8 Session Transcript](#a8-session-transcript)
- [Annex B: OID4VP Flow](#annex-b-oid4vp-flow)
  - [B.1 Sequence Diagrams](#b1-sequence-diagrams)
  - [B.2 Wallet Invocation](#b2-wallet-invocation)
  - [B.3 Metadata Exchange](#b3-metadata-exchange)
  - [B.4 Data Exchange](#b4-data-exchange)
  - [B.5 Security Mechanisms](#b5-security-mechanisms)
  - [B.6 Examples](#b6-examples)
- [Annex C: Digital Credentials API](#annex-c-digital-credentials-api)
  - [C.1 General](#c1-general)
  - [C.2 Request Structure](#c2-request-structure)
  - [C.3 Response Structure](#c3-response-structure)
  - [C.4 HPKE Encryption](#c4-hpke-encryption)
  - [C.5 Session Transcript](#c5-session-transcript)

---

## Introduction

**ISO/IEC 18013-5** defines how an mDL works for **in-person** presentation (NFC tap, BLE, QR code at a physical location).

**ISO/IEC TS 18013-7** (this document) **augments** Part 5 by adding:
- **Presentation over the internet** (remote/online scenarios)
- Integration with **OID4VP** (OpenID for Verifiable Presentations)

### What This Enables

| Part 5 (In-Person) | Part 7 (Remote/Online) |
|--------------------|------------------------|
| Traffic stop with police officer | Online age verification for e-commerce |
| Bar/club entry | Remote bank account opening |
| Car rental at counter | Digital onboarding without physical presence |
| Airport ID check | Online government services |

### Important Note

> The mDL verifier is still responsible for matching the received data to the person presenting the mdoc. Part 7 doesn't change this requirement from Part 5 - it just enables the presentation to happen remotely.

The transaction and security mechanisms are designed to work for:
- Mobile Driving Licences (mDL)
- **Other mobile documents** (ID cards, passports, professional credentials, etc.)

---

## Scope

This document adds **one key capability** to the mDL:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   ISO/IEC 18013-5 (Part 5)          ISO/IEC TS 18013-7 (Part 7)            │
│   ────────────────────────          ─────────────────────────────          │
│                                                                             │
│   ┌─────────┐    NFC/BLE    ┌─────────┐                                    │
│   │  mDL    │◄────────────►│ Reader  │   IN-PERSON presentation           │
│   │ (phone) │   QR code     │(device) │   (physical proximity required)    │
│   └─────────┘               └─────────┘                                    │
│                                                                             │
│                                  +                                          │
│                                                                             │
│   ┌─────────┐   Internet    ┌─────────┐                                    │
│   │  mDL    │◄────────────►│ Reader  │   REMOTE presentation              │
│   │ (phone) │   (OID4VP)    │(service)│   (over the internet)              │
│   └─────────┘               └─────────┘                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Relationship to Part 5

### Conformance Independence

> **Key Point:** Conformance with Part 5 is **NOT required** for conformance with Part 7!

This means:
- An mDL can implement Part 7 (online) without implementing Part 5 (in-person)
- An mDL can implement both
- An mDL reader can support online-only verification

| Scenario | Part 5 Conformance | Part 7 Conformance |
|----------|-------------------|-------------------|
| Online-only service (e-commerce age check) | ❌ Not needed | ✅ Required |
| In-person only (traffic stop device) | ✅ Required | ❌ Not needed |
| Full-featured wallet/verifier | ✅ Yes | ✅ Yes |

### What Part 7 Inherits from Part 5

Part 7 builds on Part 5 for:
- **Data structures** (CBOR encoding, CDDL definitions)
- **Data model** (same data elements: name, birth_date, portrait, etc.)
- **Security mechanisms** (MSO, issuer signatures, device authentication)
- **Interface 3** (Reader ↔ Issuing Authority) - no changes

---

## Key Terms

| Term | Definition |
|------|------------|
| **mdoc reader** | Either a **device** or **service** (or both) that can retrieve data from an mdoc and verify its authenticity. Includes hardware and software components. |
| **OID4VP** | OpenID for Verifiable Presentations - the protocol used for transmitting mdoc data over the internet |
| **Unattended transaction** | A remote verification where no human verifier is present (e.g., automated online age check) |
| **Attended transaction** | A verification with a human verifier (e.g., video call with bank employee) |

### Reader Definition Change

In **Part 5**: Reader = physical device (like a police officer's scanner)

In **Part 7**: Reader = **device OR service** (can be a web server!)

```
Part 5 Reader:                    Part 7 Reader:
┌─────────────────┐               ┌─────────────────┐
│   📟 Physical   │               │   📟 Physical   │
│     Device      │               │     Device      │
└─────────────────┘               └─────────────────┘
                                          OR
                                  ┌─────────────────┐
                                  │   🖥️ Web        │
                                  │    Service      │
                                  └─────────────────┘
```

---

## Interfaces

Part 7 defines the same three interfaces as Part 5, but with different scope:

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                              INTERFACES                                         │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│   ┌──────────────────┐                           ┌──────────────────┐          │
│   │ Issuing Authority│                           │    mDL Reader    │          │
│   │  Infrastructure  │                           │  (device/service)│          │
│   └────────┬─────────┘                           └────────┬─────────┘          │
│            │                                              │                    │
│            │ Interface 1                                  │ Interface 3        │
│            │ (OUT OF SCOPE)                               │ (Same as Part 5)   │
│            │                                              │                    │
│            ▼                                              │                    │
│   ┌──────────────────┐                                    │                    │
│   │       mDL        │◄───────────────────────────────────┘                    │
│   │     (phone)      │         Interface 2                                     │
│   └──────────────────┘    (DEFINED IN THIS DOCUMENT)                           │
│                                                                                │
│                           Used for:                                            │
│                           • Connection setup                                   │
│                           • Device retrieval over internet                     │
│                                                                                │
└────────────────────────────────────────────────────────────────────────────────┘
```

| Interface | Connection | In Scope? | Notes |
|-----------|------------|-----------|-------|
| **Interface 1** | Issuing Authority ↔ mDL | ❌ Out of scope | Same as Part 5 - provisioning is implementation-specific |
| **Interface 2** | mDL ↔ Reader | ✅ **Defined here** | Extended for internet-based communication |
| **Interface 3** | Reader ↔ Issuing Authority | ⚪ Part 5 applies | No new requirements added |

---

## Design Objectives

The goals of Part 7 mirror Part 5, adapted for remote scenarios:

### a) Verification Over Internet
> An mDL verifier together with an mDL reader is able to **request and receive an mDL** over the internet, and **validate its integrity and authenticity**.

### b) Third-Party Verification
> An mDL verifier **not associated with the Issuing Authority** can verify the mDL's integrity and authenticity.

*Same as Part 5 - you don't need a direct connection to the DMV to verify a licence.*

### c) Holder Binding
> An mDL verifier can **confirm the binding** between the person presenting the mDL and the mDL holder.

**Challenge for Remote:** In-person, a verifier can compare your face to the portrait. Online, this is harder!

> ⚠️ **Important Note from the spec:**  
> In an **unattended transaction** (no human verifier), the portrait image might **not be sufficient** to confirm the presenter is the holder. Other methods may be needed but are out of scope.

### d) Selective Disclosure
> The interface supports **selective release** of mDL data to the reader.

*Same as Part 5 - share only what's needed (e.g., "age_over_21" without birth date).*

---

## Technical Requirements

### Data Structures
- **CBOR** (Concise Binary Object Representation) - same as Part 5
- **CDDL** (Concise Data Definition Language) - same as Part 5
- **Version elements** - same as Part 5

### Forward Compatibility Rule
> An mDL or reader **shall not give an error** solely because it doesn't recognize a data structure.

This enables:
- Future extensions without breaking existing implementations
- Graceful handling of unknown fields

---

## Data Exchange Flows

Part 7 defines **three different flows** for remote presentation. An mDL or reader must support **at least one**:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     FLOWS FOR UNATTENDED (REMOTE) CASES                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐    │
│   │  Device Retrieval   │  │       OID4VP        │  │  Digital Credentials│    │
│   │     Messages        │  │                     │  │    API Retrieval    │    │
│   └──────────┬──────────┘  └──────────┬──────────┘  └──────────┬──────────┘    │
│              │                        │                        │               │
│   ┌──────────▼──────────┐  ┌──────────▼──────────┐  ┌──────────▼──────────┐    │
│   │    ENGAGEMENT       │  │    ENGAGEMENT       │  │    ENGAGEMENT       │    │
│   │  ┌───────────────┐  │  │  ┌───────────────┐  │  │  ┌───────────────┐  │    │
│   │  │ mdoc: scheme  │  │  │  │mdoc-openid4vp:│  │  │  │   Skipped     │  │    │
│   │  │ Other mechanism│  │  │  │    scheme    │  │  │  │  engagement   │  │    │
│   │  │ Skip engagement│  │  │  │Other mechanism│  │  │  │    phase     │  │    │
│   │  └───────────────┘  │  │  │Skip engagement│  │  │  └───────────────┘  │    │
│   └──────────┬──────────┘  │  └───────────────┘  │  └──────────┬──────────┘    │
│              │             │  └──────────┬──────────┘           │               │
│   ┌──────────▼──────────┐  ┌──────────▼──────────┐  ┌──────────▼──────────┐    │
│   │   TRANSMISSION      │  │   TRANSMISSION      │  │   TRANSMISSION      │    │
│   │  ┌───────────────┐  │  │  ┌───────────────┐  │  │  ┌───────────────┐  │    │
│   │  │Device retrieval│  │  │  │    OID4VP     │  │  │  │     API       │  │    │
│   │  │  to website   │  │  │  │               │  │  │  │               │  │    │
│   │  └───────────────┘  │  │  └───────────────┘  │  │  └───────────────┘  │    │
│   └─────────────────────┘  └─────────────────────┘  └─────────────────────┘    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Flow 1: Device Retrieval Messages

Uses the **same message structures** as Part 5, but transmitted over a website/internet connection.

| Aspect | Description |
|--------|-------------|
| **Engagement** | `mdoc:` scheme, other mechanism, or skipped |
| **Transmission** | Device retrieval to a website |
| **Use case** | When you want Part 5 compatibility over internet |

### Flow 2: OID4VP (OpenID for Verifiable Presentations)

Uses the **OID4VP protocol** (OpenID standard) for transmission.

| Aspect | Description |
|--------|-------------|
| **Engagement** | `mdoc-openid4vp:` scheme, other mechanism, or skipped |
| **Transmission** | OID4VP protocol |
| **Use case** | Primary method for web-based verification |

### Flow 3: Digital Credentials API Retrieval

Uses a **browser/platform API** for credential retrieval.

| Aspect | Description |
|--------|-------------|
| **Engagement** | Skipped (API handles it) |
| **Transmission** | API call |
| **Use case** | Native browser integration (e.g., Chrome's Digital Credentials API) |

---

## Summary: Part 5 vs Part 7

| Aspect | Part 5 | Part 7 |
|--------|--------|--------|
| **Presentation method** | In-person (NFC, BLE, QR) | Remote (Internet) |
| **Reader type** | Physical device | Device OR web service |
| **Primary protocol** | Custom (ISO-defined) | OID4VP |
| **Proximity required** | Yes | No |
| **Holder verification** | Visual (compare face to portrait) | Challenge (may need other methods) |
| **Use cases** | Traffic stops, bar entry, car rental | E-commerce, online banking, digital onboarding |

---

## Data Retrieval Methods

An mDL and mDL reader **must support at least one** of these methods (and may support more):

| Data Retrieval Method | mDL Support | Reader Support | Reference |
|-----------------------|-------------|----------------|-----------|
| **Device Retrieval** | Conditional* | Conditional* | 6.4.3.2 |
| **OID4VP** | Conditional* | Conditional* | Annex B |
| **Digital Credentials API** | Conditional* | Conditional* | Annex C |

*\* Support for at least one method is **mandatory**.*

### Future: HAIP (High Assurance Interoperability Profile)

> The OpenID Foundation Digital Credential Protocols working group is developing **HAIP** - a specification that enables mdoc presentation over the Digital Credentials API using OID4VP with additional features. Future revisions of Part 7 will reference HAIP.

---

## Device Retrieval Engagement

When using device retrieval over the internet, there's a specific **engagement flow** to establish a secure connection:

### Remote Engagement Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    DEVICE RETRIEVAL ENGAGEMENT FLOW                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   mDL Reader                                           mDL (Phone)              │
│   ──────────                                           ──────────               │
│                                                                                 │
│   1. Create ReaderEngagement                                                    │
│      ┌─────────────────────┐                                                   │
│      │ ReaderEngagement    │                                                   │
│      │ • Connection info   │ ──────────────────────────────────►               │
│      │ • Security params   │        (e.g., via mdoc: URI)                      │
│      └─────────────────────┘                                                   │
│                                                                                 │
│                                        2. Parse ReaderEngagement               │
│                                           Set up data transmission channel     │
│                                                                                 │
│                                        3. Send DeviceEngagement                │
│      ┌─────────────────────┐           ┌─────────────────────┐                │
│      │ DeviceEngagement    │ ◄──────── │ DeviceEngagement    │                │
│      │ received            │           │ • Device's ephemeral│                │
│      └─────────────────────┘           │   public key        │                │
│                                        │ • Origin info       │                │
│                                        └─────────────────────┘                │
│                                                                                 │
│   4. Secure channel established                                                │
│      Now can exchange mdoc request/response                                    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### The Three Steps

| Step | Actor | Action |
|------|-------|--------|
| **1** | Reader → mDL | Transmits `ReaderEngagement` structure (connection info) |
| **2** | mDL | Sets up data transmission channel using ReaderEngagement info |
| **3** | mDL → Reader | Sends `DeviceEngagement` structure over the new channel |

### Skipping Engagement

> If an **existing two-way data transmission channel** is already established out-of-band, the device retrieval engagement phase **can be skipped**.

### Data Transmission

Once engaged, the mDL and reader use the **same request/response structures** as ISO/IEC 18013-5:
- `mdoc request` - what data the reader wants
- `mdoc response` - the holder's response with selected data

---

## Security Mechanisms

### Security Architecture Goals

Part 7 maintains the same security triad as Part 5: **Confidentiality, Integrity, Availability**

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         SECURITY GOALS (Part 7)                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  a) PROTECTION AGAINST FORGERY                                                  │
│     ─────────────────────────────                                               │
│     • Data elements signed by Issuing Authority                                │
│     • Protection depends on how well IA keys are protected                     │
│     • Shorter validity periods = less valuable stolen data                     │
│                                                                                 │
│  b) PROTECTION AGAINST CLONING                                                  │
│     ──────────────────────────────                                              │
│     • mDL generates signature/MAC over session data                            │
│     • Private key stored ONLY on the mDL device                                │
│     • Public key signed by IA in the MSO                                       │
│     • Additional: User authentication before key use (PIN, biometric)          │
│       (depends on jurisdiction policy: eIDAS AAL, NIST SP 800-63, etc.)        │
│                                                                                 │
│  c) PROTECTION AGAINST EAVESDROPPING                                            │
│     ────────────────────────────────                                            │
│     • Communications encrypted and authenticated                               │
│     • Reader detects MITM via anti-cloning signature/MAC validation           │
│     • If reader auth used: mDL can detect MITM before returning data          │
│                                                                                 │
│  d) PROTECTION AGAINST UNAUTHORIZED ACCESS                                      │
│     ────────────────────────────────────────                                    │
│     • Session encryption with ephemeral keys from BOTH parties                 │
│     • Optional: mDL reader authentication (certificate + signature)            │
│     • Reader certificate signed by CA trusted by the mDL                       │
│                                                                                 │
│  e) PROTECTION AGAINST RELAYED ENGAGEMENT (NEW in Part 7!)                      │
│     ──────────────────────────────────────────────────────                      │
│     • mDL includes ORIGIN INFO in device engagement                            │
│     • Origin determined INDEPENDENTLY from reader engagement                   │
│     • Reader verifies origin matches expected value                            │
│     • Mismatch → transaction cancelled                                         │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Security Mechanisms Requirements

| Security Mechanism | Support | Reference |
|--------------------|---------|-----------|
| **Issuer Data Authentication** | **Mandatory** | ISO/IEC 18013-5 |
| **mdoc Authentication** | **Mandatory** | ISO/IEC 18013-5 |
| **Session Encryption** | Conditional (required for device retrieval to website) | Annex A.6 |
| **mdoc Reader Authentication** | Optional | ISO/IEC 18013-5 |

### Important: Session Transcript Changes

> **Critical:** mdoc authentication, reader authentication, and session encryption **must use the session transcript defined in Part 7** (A.8, B.4.4, or C.4) - **NOT** the one from Part 5!

This is necessary because the session context is different in remote scenarios.

### Origin Verification

When `OriginInfo` contains a domain origin, the reader **must verify** it matches where the mDL was requested from.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         ORIGIN VERIFICATION                                      │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   mDL determines origin                    Reader verifies                      │
│   INDEPENDENTLY                            ─────────────────                    │
│   ────────────────────                                                          │
│                                                                                 │
│   ┌─────────────────────┐                  ┌─────────────────────┐             │
│   │ DeviceEngagement    │                  │ Expected: example.com│             │
│   │ OriginInfo: {       │                  │                     │             │
│   │   domain: "example.com"                │ Received: example.com│             │
│   │ }                   │ ───────────────► │                     │             │
│   └─────────────────────┘                  │ Match? ✓ Continue   │             │
│                                            │ Mismatch? ✗ CANCEL  │             │
│                                            └─────────────────────┘             │
│                                                                                 │
│   If verification fails → Reader MUST terminate and invalidate received data   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Revocation

Revocation of an mDL is **out of scope** for Part 7. However:
- MSO includes update information and validity timeframes
- Reader can check data freshness
- IA should define appropriate validity periods balancing:
  - Freshness (security)
  - Offline capability (usability)

---

## Protocol Considerations

### Custom URI Scheme Limitations

The `mdoc:` and `mdoc-openid4vp:` URI schemes have known limitations:

| Issue | Description |
|-------|-------------|
| **iOS app selection** | Multiple apps can register same scheme - system chooses unpredictably |
| **Deprecation risk** | Some URI schemes may be deprecated, breaking implementations |
| **No wallet selection help** | User can't easily pick the right wallet (selection based only on protocol) |
| **Malformed input** | Apps must protect against malformed data in URIs |
| **Limited browser protection** | Custom schemes bypass some browser security features |

### Attack: Session Hijacking / Relay Attack

**The Threat:**
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    RELAY / SESSION HIJACKING ATTACK                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ATTACKER                  VICTIM                    RELYING PARTY            │
│   ────────                  ──────                    ─────────────            │
│                                                                                 │
│   1. Attacker visits relying party                                             │
│      (e.g., bank website)                                                       │
│   2. Gets authentication link                         ┌─────────────┐          │
│      ◄────────────────────────────────────────────── │ Auth link   │          │
│                                                       └─────────────┘          │
│   3. Forwards link to victim                                                   │
│      ───────────────────────►                                                  │
│                                                                                 │
│   4. Victim clicks, authenticates    5. Auth completes                         │
│      with their mDL                     for ATTACKER's session!                │
│                                         ───────────────────────►               │
│                                                                                 │
│   Result: Attacker logged in as victim                                         │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Mitigations by Method

| Method | Mitigation | Effectiveness |
|--------|------------|---------------|
| **Device Retrieval to Website** | User agent provides domain origin to mdoc | ⚠️ Some browsers block origin info or don't support it via schemes |
| **OID4VP** | Reader maintains binding between user session and `nonce` parameter | ⚠️ No standard mechanism defined; mdoc can't verify binding is maintained |
| **Digital Credentials API** | User agent provides origin to mdoc; both include origin in session transcript | ✅ Origin must match, preventing the attack |

### Digital Credentials API Advantage

The Digital Credentials API is the most secure against relay attacks because:
1. Browser **always** provides the origin to the mdoc
2. **Both** mdoc and reader include origin in session transcript
3. Origins **must match** - built-in protection

---

## mDL Data Model

The data model from Part 5 applies with **one key difference**:

### Reader Authentication for Mandatory Elements

> **Part 5:** Mandatory data elements must be released upon valid request  
> **Part 7:** mDL **MAY require reader authentication** before releasing ANY mandatory data elements

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    DATA RELEASE: PART 5 vs PART 7                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   PART 5 (In-Person):                                                          │
│   ───────────────────                                                          │
│                                                                                 │
│   Reader: "Give me family_name"                                                │
│   mDL: "OK, here it is"  (reader auth NOT required for mandatory elements)     │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   PART 7 (Remote):                                                             │
│   ────────────────                                                             │
│                                                                                 │
│   Reader: "Give me family_name"                                                │
│   mDL: "First, prove who you are!" (reader auth CAN be required)               │
│   Reader: <provides certificate + signature>                                   │
│   mDL: "OK, verified. Here's the data."                                        │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Why the change?** 

In remote scenarios, requiring reader authentication provides additional protection because:
- No physical presence to establish trust
- Higher risk of unauthorized data harvesting
- Holder can verify reader identity before releasing sensitive data

---

## Annex A: Device Retrieval to Website

> **Normative Annex:** This section defines the mechanisms for device retrieval to a website, enabling mDL presentation directly to web services.

### Overview

Device Retrieval to a Website allows an mDL to present data directly to a web service using:
- **ReaderEngagement** - Reader provides connection info to mDL
- **DeviceEngagement** - mDL responds with its capabilities  
- **HTTPS REST API** - Secure transport layer
- **CBOR encoding** - Binary data format

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     Device Retrieval to Website Flow                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌──────────┐                           ┌──────────────┐                       │
│   │  mDL     │                           │  Website     │                       │
│   │ (Wallet) │                           │  (Verifier)  │                       │
│   └────┬─────┘                           └──────┬───────┘                       │
│        │                                        │                               │
│        │    1. ReaderEngagement (via mdoc://)   │                               │
│        │◄───────────────────────────────────────┤                               │
│        │       Contains: EReaderKey.Pub,        │                               │
│        │       URI endpoint, cipher suite       │                               │
│        │                                        │                               │
│        │    2. DeviceEngagement (HTTP POST)     │                               │
│        ├───────────────────────────────────────►│                               │
│        │       Contains: EDeviceKey.Pub,        │                               │
│        │       OriginInfos, Capabilities        │                               │
│        │                                        │                               │
│        │    3. SessionEstablishment / Request   │                               │
│        │◄───────────────────────────────────────┤                               │
│        │       Encrypted DeviceRequest          │                               │
│        │       (optionally + new EReaderKey)    │                               │
│        │                                        │                               │
│        │    4. SessionData (Response)           │                               │
│        ├───────────────────────────────────────►│                               │
│        │       Encrypted DeviceResponse         │                               │
│        │                                        │                               │
│   └────┴─────┘                           └──────┴───────┘                       │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

### A.1 ReaderEngagement Structure

The **ReaderEngagement** structure contains information for the mdoc to connect to the reader. It is CBOR encoded:

```cddl
ReaderEngagement = {
  0: tstr,                      ; Version (shall be "1.1")
  1: Security,                  ; Cipher suite + EReaderKey
  ? 2: DeviceRetrievalMethods,  ; How to connect
  * int => any                  ; Extensions (negative keys for app-specific)
}

Security = [
  int,                          ; Cipher suite identifier (from Part 5)
  EReaderKeyBytes               ; Ephemeral reader public key
]

DeviceRetrievalMethods = [+ DeviceRetrievalMethod]

DeviceRetrievalMethod = [
  uint,                         ; Type (4 = website)
  uint,                         ; Version (1 for website)
  RetrievalOptions              ; Type-specific options
]

RetrievalOptions = RestApiOptions / any
```

| Element | Description |
|---------|-------------|
| **Version** | Always `"1.1"` for this spec |
| **Security** | Contains cipher suite ID + ephemeral reader public key (`EReaderKey.Pub`) |
| **DeviceRetrievalMethods** | Array of supported retrieval methods |

**DeviceRetrievalMethod Values for Website:**

| Field | Value | Meaning |
|-------|-------|---------|
| Type | `4` | Device Retrieval to Website |
| Version | `1` | Version 1 of this method |
| RetrievalOptions | `RestApiOptions` | Contains the URI endpoint |

---

### A.2 DeviceEngagement Structure

The **DeviceEngagement** structure is sent by the mdoc to the reader. It is CBOR encoded:

```cddl
DeviceEngagement = {
  0: tstr,           ; Version (shall be "1.1")
  1: Security,       ; Cipher suite + EDeviceKey  
  5: OriginInfos,    ; MANDATORY - channel info for relay protection
  ? 6: Capabilities, ; Optional capabilities
  * int => any       ; Extensions
}

Capabilities = {
  ? 0: MacKeysSupport,  ; bool - supports MacKeys in request?
  ? 1: MacKeysCurves,   ; array of supported curves
  * int => any
}

MacKeysSupport = bool
MacKeysCurves = [+ crv]
crv = int              ; From IANA COSE Elliptic Curves registry
```

| Element | Required | Description |
|---------|----------|-------------|
| **Version** | ✅ | Always `"1.1"` |
| **Security** | ✅ | Cipher suite + ephemeral device public key (`EDeviceKey.Pub`) |
| **OriginInfos** | ✅ | **Must be present** - relay attack protection |
| **Capabilities** | ❌ | Optional MAC key negotiation support |

**Capabilities Structure:**

| Field | Purpose |
|-------|--------|
| `MacKeysSupport` | If `true`, mdoc supports receiving multiple `MacKeys` in the request |
| `MacKeysCurves` | Which elliptic curves the mdoc supports for MAC authentication |

> **Privacy Note:** The contents of `MacKeysCurves` shall NOT be determined by actual presence of any mobile documents (to avoid fingerprinting).

---

### A.3 OriginInfo Structure

The **OriginInfos** structure provides relay attack protection by indicating through which channel the mdoc received the ReaderEngagement.

```cddl
OriginInfos = [* OriginInfo]

OriginInfo = {
  "cat": Category,     ; Category (shall be 1)
  "type": Type,        ; Type of origin info
  "details": Details   ; Type-specific details
}

Category = uint        ; 1 = standard, others RFU
Type = uint            ; 0 = Other, 1 = Domain origin
Details = {+ tstr: any}
```

**Origin Info Types:**

| Type | Name | Description |
|------|------|-------------|
| `0` | Other | Additional channel information (details out of scope) |
| `1` | Domain origin | Website domain that sent the engagement |

**Domain Origin (Type 1):**

For type 1, the `Details` map contains:

```cddl
Details = {
  "domain": tstr    ; Website domain (e.g., "gov.example.com")
}
```

**Example:**

| Referrer URL | Domain Value |
|--------------|-------------|
| `https://gov.example.com/present/session1?hi=2` | `"gov.example.com"` |

**Critical Security Rules:**

1. The domain value **MUST** come from a trusted source (e.g., browser referrer URL)
2. The mdoc **SHALL NOT** determine the domain from data in the ReaderEngagement itself
3. If the domain source is not trusted, the value **MAY** be an empty string
4. Reader validates OriginInfos to detect relay attacks

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        OriginInfo for Relay Protection                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   LEGITIMATE FLOW:                                                             │
│   ───────────────                                                              │
│                                                                                 │
│   ┌─────────┐       ReaderEngagement        ┌─────────────┐                    │
│   │  Wallet │ ◄──────────────────────────── │ bank.com    │                    │
│   │  (mDL)  │                               │ (Verifier)  │                    │
│   └────┬────┘                               └──────┬──────┘                    │
│        │                                           │                           │
│        │ OriginInfo: domain = "bank.com" ✅        │                           │
│        │ (from browser referrer)                   │                           │
│        ├──────────────────────────────────────────►│                           │
│        │                                           │                           │
│        │ Reader checks: domain matches? ✅ OK      │                           │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   RELAY ATTACK (BLOCKED):                                                      │
│   ──────────────────────                                                       │
│                                                                                 │
│   ┌─────────┐  ReaderEng   ┌──────────┐  Relayed   ┌─────────────┐             │
│   │  Wallet │ ◄─────────── │ Attacker │ ◄───────── │ bank.com    │             │
│   │  (mDL)  │  (attacker   │ (evil.co)│            │ (Verifier)  │             │
│   └────┬────┘   domain)    └──────────┘            └──────┬──────┘             │
│        │                                                  │                    │
│        │ OriginInfo: domain = "evil.co" ⚠️               │                    │
│        │ (attacker's actual domain)                       │                    │
│        ├─────────────────────────────────────────────────►│                    │
│        │                                                  │                    │
│        │ Reader checks: "evil.co" ≠ "bank.com" ❌ REJECT │                    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

> **Future Extension:** One of the reserved type values may be used for Qualified Website Authentication Certificates (QWAC) as defined in ETSI TS 119 495.

---

### A.4 mdoc URI Scheme

To invoke the mdoc wallet, the reader uses the registered `mdoc://` URI scheme:

```
mdoc://<base64url-encoded-ReaderEngagement>
```

**Format:**
- URI starts with `mdoc://`
- Followed by ReaderEngagement encoded as **base64url-without-padding** (RFC 4648)

**Example:**

```
mdoc://eyJ2ZXJzaW9uIjoiMS4xIiwic2VjdXJpdHkiOlsxLCJFUmVhZGVyS2V5Qnl0ZXMiXX0
```

> **Note:** The `mdoc://` URI scheme is officially reserved by ISO/IEC 18013-5 with IANA.

---

### A.5 mdoc MAC Authentication

#### The Problem

In Part 5 (in-person), MAC authentication works because:
1. mDL sends `EDeviceKey` first (in DeviceEngagement)
2. Reader sees the curve and generates matching `EReaderKey`
3. MAC key derived from both keys uses same curve

In Part 7 (remote), the flow is **reversed**:
1. Reader sends `EReaderKey` first (in ReaderEngagement)  
2. Reader doesn't know what curve the mDL's static device key uses
3. **Problem:** Curves might not match!

#### The Solution: MacKeys

Part 7 adds an optional `MacKeys` element to `DeviceRequest`:

```cddl
MacKeys = [+ COSE_Key]     ; Array of ephemeral reader keys, different curves

DeviceRequest = {
  "version": tstr,         ; "1.1" when MacKeys present
  "docRequests": [+ DocRequest],
  ? "macKeys": MacKeys      ; NEW: multiple keys for different curves
}
```

**How It Works:**

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          MacKeys Curve Negotiation                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Reader                                  mDL                                   │
│   ──────                                  ───                                   │
│                                                                                 │
│   DeviceRequest {                                                               │
│     "version": "1.1",                                                          │
│     "docRequests": [...],                                                      │
│     "macKeys": [                         ─────►  mDL receives multiple keys    │
│       { curve: P-256, key: ... },                                              │
│       { curve: P-384, key: ... },                                              │
│       { curve: P-521, key: ... }                                               │
│     ]                                                                          │
│   }                                                                            │
│                                                                                 │
│                                           mDL's static key uses P-384          │
│                                           ─────►  Picks P-384 key from MacKeys │
│                                           ─────►  Performs MAC authentication  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Rules:**

| Rule | Description |
|------|-------------|
| Only if supported | Reader shall NOT include `MacKeys` unless mDL indicated `MacKeysSupport: true` in DeviceEngagement |
| No duplicates | `MacKeys` shall NOT contain more than one key per curve |
| Version bump | When `MacKeys` present, version shall be `"1.1"` |
| Optimization | If mDL provides `MacKeysCurves`, reader should limit keys to those curves |

---

### A.6 Device Retrieval to Website

#### A.6.1 Engagement

The `RestApiOptions` element provides the URI endpoint:

```cddl
RestApiOptions = {
  0: tstr    ; URI of the website endpoint
}
```

The URI must include a path that identifies the session.

#### A.6.2 Transport Protocol

The mDL uses **HTTP/1.1 POST** (RFC 9112) for all communication:

**Request Format:**

```http
POST [path] HTTP/1.1
Host: [host]
Content-Length: [length]
Content-Type: application/cbor

[DeviceEngagementMessage or SessionData - CBOR encoded]
```

**Response Format:**

```http
HTTP/1.1 200 OK
Content-Length: [length]
Content-Type: application/cbor

[SessionEstablishment or SessionData - CBOR encoded]
```

**Requirements:**

| Requirement | Description |
|-------------|-------------|
| Content-Type | Must be `application/cbor` |
| TLS | **Required** - server authentication per Part 5 |
| OriginInfo | When using this method, mDL **SHALL** include "Domain origin" in OriginInfos |
| Error handling | Per RFC 9110 Section 15 |

**DeviceEngagementMessage Structure:**

```cddl
DeviceEngagementMessage = {
  "deviceEngagementBytes": DeviceEngagementBytes
}

DeviceEngagementBytes = #6.24(bstr .cbor DeviceEngagement)
```

---

### A.7 Session Encryption

Session encryption follows Part 5 with **modified steps** for the reversed flow:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    Session Encryption (Part 7 Modifications)                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  Step 0: READER ENGAGEMENT (NEW in Part 7)                                     │
│  ─────────────────────────────────────────                                     │
│  • Reader generates ephemeral key pair (EReaderKey.Priv, EReaderKey.Pub)       │
│  • Populates ReaderEngagement.Security with:                                   │
│    - Cipher suite identifier                                                   │
│    - Elliptic curve identifier                                                 │
│    - EReaderKey.Pub                                                            │
│                                                                                 │
│  Step 1: DEVICE ENGAGEMENT (Modified)                                          │
│  ────────────────────────────────────                                          │
│  • mDL generates ephemeral key pair (EDeviceKey.Priv, EDeviceKey.Pub)         │
│  • SHOULD use same curve as received EReaderKey if supported                   │
│  • MAY use different curve if EReaderKey curve not supported                   │
│  • Populates DeviceEngagement.Security with:                                   │
│    - Cipher suite identifier                                                   │
│    - Elliptic curve identifier                                                 │
│    - EDeviceKey.Pub                                                            │
│  • If curves match: derive session keys per Part 5                             │
│  • Sends DeviceEngagement in DeviceEngagementMessage                           │
│                                                                                 │
│  Step 2: SESSION ESTABLISHMENT (Modified)                                      │
│  ────────────────────────────────────────                                      │
│  • Reader derives session keys using received DeviceEngagement                 │
│                                                                                 │
│  IF curves match (EDeviceKey curve == EReaderKey curve from Step 0):           │
│    ─► Use existing EReaderKey.Priv for key derivation                          │
│    ─► Send encrypted request in SessionData (no new key needed)                │
│                                                                                 │
│  IF curves DON'T match:                                                        │
│    ─► Generate NEW EReaderKey pair matching mDL's curve                        │
│    ─► Send encrypted request in SessionEstablishment with new EReaderKey.Pub   │
│                                                                                 │
│  mDL Processing:                                                               │
│  • If didn't derive keys in Step 1, derive now using new EReaderKey            │
│  • If derived in Step 1 but received new EReaderKey: TERMINATE SESSION         │
│  • Decrypt request and continue per Part 5                                     │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Key Decision Flow:**

| Scenario | Reader Action | Message Type |
|----------|---------------|-------------|
| Curves match | Use existing EReaderKey | `SessionData` |
| Curves don't match | Generate new EReaderKey | `SessionEstablishment` (includes new key) |

---

### A.8 Session Transcript

The session transcript from Part 5 is used with **modified Handover element**:

```cddl
Handover = EngagementToApp / any

EngagementToApp = ReaderEngagementBytesHash

ReaderEngagementBytesHash = bstr    ; SHA-256 hash of ReaderEngagementBytes

ReaderEngagementBytes = #6.24(bstr .cbor ReaderEngagement)
```

**Key Points:**

| Element | Part 5 | Part 7 (Remote Flow) |
|---------|--------|---------------------|
| Handover | Device engagement transfer method | **SHA-256 hash of ReaderEngagementBytes** |
| DeviceEngagementBytes | Always present | `null` if not used |
| EReaderKeyBytes | Always present | `null` if not used |

**Special Cases:**

| Scenario | Value |
|----------|-------|
| Remote engagement flow | `Handover = SHA-256(ReaderEngagementBytes)` |
| DeviceEngagement not used | `DeviceEngagementBytes = null` |
| EReaderKey not used | `EReaderKeyBytes = null` |
| Out-of-band mechanism | Handover content is out of scope |

> **Important:** The `eReaderKey` used in the session transcript shall be the one used to derive session encryption keys (which may differ from the one in ReaderEngagement if curves didn't match).

---

## Annex B: OID4VP Flow

> **Informative Annex:** This section defines the OID4VP (OpenID for Verifiable Presentations) protocol flow for mDL presentation over the internet.

### Overview

OID4VP enables mDL presentation using **OAuth 2.0** constructs:

| OAuth 2.0 Role | mDL Role | Description |
|----------------|----------|-------------|
| Authorization Server | mdoc app (Wallet) | Holds the mDL, authorizes data release |
| Client | mdoc reader (Verifier) | Requests mDL data |
| Resource Owner | User | Consents to data sharing |

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           OID4VP Protocol Mapping                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌─────────────────┐              ┌─────────────────┐                         │
│   │     User        │              │   mdoc reader   │                         │
│   │   (Browser)     │              │   (Verifier)    │                         │
│   └────────┬────────┘              └────────┬────────┘                         │
│            │                                │                                   │
│            │  1. Visit website              │                                   │
│            ├───────────────────────────────►│                                   │
│            │                                │                                   │
│            │  2. Page with Authorization    │                                   │
│            │     Request (request_uri)      │                                   │
│            │◄───────────────────────────────┤                                   │
│            │                                │                                   │
│   ┌────────▼────────┐                       │                                   │
│   │   mdoc app      │  3. Invoke wallet     │                                   │
│   │   (Wallet)      │     (mdoc-openid4vp://)                                   │
│   └────────┬────────┘                       │                                   │
│            │                                │                                   │
│            │  4. Fetch Request Object (GET) │                                   │
│            ├───────────────────────────────►│                                   │
│            │                                │                                   │
│            │  5. Signed JWT (JAR)           │                                   │
│            │◄───────────────────────────────┤                                   │
│            │                                │                                   │
│            │  [User consent + auth]         │                                   │
│            │                                │                                   │
│            │  6. Authorization Response     │                                   │
│            │     (encrypted JWE)            │                                   │
│            ├───────────────────────────────►│                                   │
│            │                                │                                   │
│            │  7. Redirect URI               │                                   │
│            │◄───────────────────────────────┤                                   │
│            │                                │                                   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

### B.1 Sequence Diagrams

#### Engagement Phase (Steps 1-6)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          Engagement Phase Sequence                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   User       Browser        mdoc app         Verifier         Verifier          │
│              (Mobile)       (Wallet)         Frontend         Backend           │
│    │            │              │                │                │              │
│    │  1. User   │              │                │                │              │
│    │  interaction              │                │                │              │
│    ├───────────►│              │                │                │              │
│    │            │              │                │                │              │
│    │            │  2. [TLS] Request verifier   │                │              │
│    │            │     web page                  │                │              │
│    │            ├──────────────────────────────►│                │              │
│    │            │                               │                │              │
│    │            │                               │  3. Prepare    │              │
│    │            │                               │  auth request  │              │
│    │            │                               │  with request  │              │
│    │            │                               │  URI           │              │
│    │            │                               │◄───────────────┤              │
│    │            │                               │                │              │
│    │            │  4. [TLS] Web page with       │                │              │
│    │            │     embedded auth request     │                │              │
│    │            │     (e.g., deep link)         │                │              │
│    │            │◄──────────────────────────────┤                │              │
│    │            │                               │                │              │
│    │  5. User   │                               │                │              │
│    │  interaction              │                │                │              │
│    ├───────────►│              │                │                │              │
│    │            │              │                │                │              │
│    │            │  6. Invoke mdoc app with      │                │              │
│    │            │     auth request              │                │              │
│    │            │     (mdoc-openid4vp://)       │                │              │
│    │            ├─────────────►│                │                │              │
│    │            │              │                │                │              │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Key Points:**
- Step 4 establishes a session between user agent and mdoc reader
- Step 6 uses `mdoc-openid4vp://` URL scheme with `request_uri` parameter
- OID4VP doesn't define when/how the Request URI is generated

#### Device Retrieval Phase (Steps 7-21)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                       Device Retrieval Phase Sequence                           │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   User       Browser        mdoc app         Verifier         Verifier          │
│              (Mobile)       (Wallet)         Frontend         Backend           │
│    │            │              │                │                │              │
│    │            │              │  7. [TLS] GET request_uri      │              │
│    │            │              ├────────────────────────────────►│              │
│    │            │              │                │                │              │
│    │            │              │                │  8. Prepare &  │              │
│    │            │              │                │  sign auth     │              │
│    │            │              │                │  request obj   │              │
│    │            │              │                │◄───────────────┤              │
│    │            │              │                │                │              │
│    │            │              │  9. [TLS] Auth Request Object  │              │
│    │            │              │     (signed JWT)                │              │
│    │            │              │◄────────────────────────────────┤              │
│    │            │              │                │                │              │
│    │            │              │  10. Verify JWT signature &    │              │
│    │            │              │      validate request object   │              │
│    │            │              │                │                │              │
│    │  11. Ask user to authenticate & consent   │                │              │
│    │◄─────────────────────────┤                │                │              │
│    │                          │                │                │              │
│    │  12. User authenticates  │                │                │              │
│    │      and gives consent   │                │                │              │
│    ├─────────────────────────►│                │                │              │
│    │            │              │                │                │              │
│    │            │              │  13. Generate mdoc auth,       │              │
│    │            │              │      DeviceResponse, VP Token  │              │
│    │            │              │                │                │              │
│    │            │              │  14. Encrypt auth response     │              │
│    │            │              │      as JWE                    │              │
│    │            │              │                │                │              │
│    │            │              │  15. [TLS] POST encrypted      │              │
│    │            │              │      response to response_uri  │              │
│    │            │              ├────────────────────────────────►│              │
│    │            │              │                │                │              │
│    │            │              │                │  16. Process   │              │
│    │            │              │                │  response:     │              │
│    │            │              │                │  - Decrypt JWE │              │
│    │            │              │                │  - Validate VP │              │
│    │            │              │                │  - Verify mdoc │              │
│    │            │              │                │    auth        │              │
│    │            │              │                │  - Check issuer│              │
│    │            │              │                │◄───────────────┤              │
│    │            │              │                │                │              │
│    │            │              │  17. [TLS] 200 OK with         │              │
│    │            │              │      redirect_uri              │              │
│    │            │              │◄────────────────────────────────┤              │
│    │            │              │                │                │              │
│    │            │  18. Direct browser to redirect_uri           │              │
│    │            │◄─────────────┤                │                │              │
│    │            │              │                │                │              │
│    │            │  19. [TLS] Open redirect_uri with params      │              │
│    │            ├──────────────────────────────►│                │              │
│    │            │                               │                │              │
│    │            │                               │  20. Confirm   │              │
│    │            │                               │  session       │              │
│    │            │                               │  binding       │              │
│    │            │                               │◄───────────────┤              │
│    │            │                               │                │              │
│    │            │  21. [TLS] Display status     │                │              │
│    │            │      and returned data        │                │              │
│    │            │◄──────────────────────────────┤                │              │
│    │            │              │                │                │              │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Step 16 Processing Details:**

| Order | Action |
|-------|--------|
| a | Decrypt the JWE |
| b | Identify the associated Authorization Request |
| c | Parse and validate VP Token (DeviceResponse) |
| d | Compute SessionTranscript to verify mdoc authentication |
| e | Perform issuer data authentication |
| f | Prepare Redirect URI with response code |

> **Note:** The Authorization Request uses TLS for transport encryption, so DeviceRequest doesn't need application-layer encryption.

---

### B.2 Wallet Invocation

The mdoc reader invokes the wallet using:

| Mechanism | URI Scheme | Description |
|-----------|------------|-------------|
| Custom URL scheme | `mdoc-openid4vp://` | Primary method defined in this spec |
| Other mechanisms | varies | Out of scope |

**mdoc-openid4vp URI Scheme:**

```
mdoc-openid4vp://?client_id=example.com&request_uri=https%3A%2F%2Fexample.com%2F567545564
```

| Registration | Value |
|-------------|-------|
| URI scheme name | `mdoc-openid4vp` |
| Status | permanent |
| Change controller | ISO/IEC JTC 1/SC 17 |
| Reference | ISO/IEC TS 18013-7 |

---

### B.3 Metadata Exchange

#### B.3.1 Overview

OID4VP uses two types of metadata:

| Metadata Type | Used By | Purpose |
|---------------|---------|--------|
| **Wallet Metadata** | mdoc reader | Learn wallet capabilities before sending request |
| **Verifier Metadata** | mdoc | Learn verifier capabilities for response |

#### B.3.2 Wallet Metadata Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `issuer` | Wallet identifier | e.g., `"https://self-issued.me/v2"` |
| `authorization_endpoint` | `mdoc-openid4vp://` | Where to send Authorization Request |
| `response_types_supported` | `["vp_token"]` | Must contain `vp_token` |
| `vp_formats_supported` | `{"mso_mdoc": {}}` | Must contain `mso_mdoc` |
| `client_id_schemes_supported` | `["x509_san_dns"]` | Must contain `x509_san_dns` |
| `request_object_signing_alg_values_supported` | varies | Supported signing algorithms |
| `authorization_encryption_alg_values_supported` | `["ECDH-ES"]` | Must support ECDH-ES |
| `authorization_encryption_enc_values_supported` | `["A256GCM"]` | Must contain A256GCM |

**Static Wallet Metadata (Default):**

```json
{
  "issuer": "https://self-issued.me/v2",
  "authorization_endpoint": "mdoc-openid4vp://",
  "response_types_supported": ["vp_token"],
  "vp_formats_supported": {
    "mso_mdoc": {}
  },
  "client_id_schemes_supported": ["x509_san_dns"],
  "authorization_encryption_alg_values_supported": ["ECDH-ES"],
  "authorization_encryption_enc_values_supported": ["A256GCM"]
}
```

> **Note:** `https://self-issued.me/v2` is a symbolic string. The empty `mso_mdoc` object means the mdoc supports all cryptographic algorithms from Part 5.

#### B.3.3 Verifier Metadata Parameters

| Parameter | Description |
|-----------|-------------|
| `jwks` | Public keys of mdoc reader (JWKS format). Keys for MAC auth use `"use": "enc"` |
| `authorization_encrypted_response_alg` | Algorithm for JWE `alg` header (e.g., `"ECDH-ES"`) |
| `authorization_encrypted_response_enc` | Algorithm for JWE `enc` header (e.g., `"A256GCM"`) |
| `vp_formats` | Must include `{"mso_mdoc": {...}}` |

---

### B.4 Data Exchange

#### B.4.1 Authorization Request

##### Engagement Phase

The mdoc receives the Authorization Request at `authorization_endpoint` with a `request_uri` parameter:

```
mdoc-openid4vp://?client_id=example.com&request_uri=https%3A%2F%2Fexample.com%2F567545564
```

##### Device Retrieval Phase

The mdoc fetches the signed Authorization Request Object:

**HTTP Request:**
```http
GET /567545564 HTTP/1.1
Host: example.com
```

**HTTP Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/oauth-authz-req+jwt

eyJ4NW...
```

##### Authorization Request Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `response_type` | `vp_token` | Request VP Token response |
| `presentation_definition` | Object | Specifies requested mDL data |
| `client_metadata` | Object | Verifier Metadata |
| `nonce` | String | Cryptographic nonce (min 16 bytes entropy) |
| `client_id` | String | Client Identifier (e.g., domain name) |
| `client_id_scheme` | `x509_san_dns` | Client Identifier scheme |
| `response_mode` | `direct_post.jwt` | Response delivery mode |
| `response_uri` | HTTPS URL | Where to POST the response |
| `aud` | `https://self-issued.me/v2` | Audience (issuer from Wallet Metadata) |
| `state` | String | Optional session binding |

##### Presentation Definition

The `presentation_definition` specifies what mDL data to request:

```json
{
  "id": "mDL-sample-req",
  "input_descriptors": [
    {
      "id": "org.iso.18013.5.1.mDL",
      "format": {
        "mso_mdoc": {
          "alg": ["ES256", "ES384", "ES512", "EdDSA", "ESB256", "ESB320", "ESB384", "ESB512"]
        }
      },
      "constraints": {
        "limit_disclosure": "required",
        "fields": [
          {
            "path": ["$['org.iso.18013.5.1']['family_name']"],
            "intent_to_retain": false
          },
          {
            "path": ["$['org.iso.18013.5.1']['birth_date']"],
            "intent_to_retain": false
          }
        ]
      }
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `id` | Unique identifier for the Presentation Definition |
| `input_descriptors[].id` | Document type (e.g., `org.iso.18013.5.1.mDL`) |
| `input_descriptors[].format.mso_mdoc.alg` | Supported algorithms |
| `constraints.limit_disclosure` | Must be `"required"` |
| `constraints.fields[].path` | JSONPath to data element: `$['namespace']['element']` |
| `constraints.fields[].intent_to_retain` | `true` or `false` |

##### Authorization Request Signing

The Authorization Request Object is signed as a JWT (JAR):

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    Authorization Request Object (JWT/JAR)                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   JWT Header:                                                                   │
│   ───────────                                                                   │
│   {                                                                             │
│     "x5c": ["<base64-encoded certificate chain>"],                             │
│     "typ": "JWT",                                                               │
│     "alg": "ES256"                                                              │
│   }                                                                             │
│                                                                                 │
│   JWT Payload:                                                                  │
│   ────────────                                                                  │
│   {                                                                             │
│     "aud": "https://self-issued.me/v2",                                         │
│     "response_type": "vp_token",                                                │
│     "presentation_definition": {...},                                           │
│     "client_metadata": {...},                                                   │
│     "nonce": "abcdefgh1234567890",                                              │
│     "client_id": "example.com",                                                 │
│     "client_id_scheme": "x509_san_dns",                                         │
│     "response_mode": "direct_post.jwt",                                         │
│     "response_uri": "https://example.com/12345/response",                       │
│     "require_signed_request_object": true                                       │
│   }                                                                             │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**x509_san_dns Client Identifier Scheme:**

| Requirement | Description |
|-------------|-------------|
| `client_id` | Must be a DNS name matching a dNSName SAN in the leaf certificate |
| `x5c` header | Contains the X.509 certificate chain (base64-encoded, not base64url) |
| Signature | Signed with private key of leaf certificate |
| `response_uri` | FQDN must match `client_id` (unless trusted) |

#### B.4.2 Authorization Response

The mdoc sends the Authorization Response to `response_uri` using `direct_post.jwt`:

**HTTP Request:**
```http
POST /post HTTP/1.1
Host: example.org
Content-Type: application/x-www-form-urlencoded

response=eyJra...9t2LQ
```

##### Authorization Response Parameters

| Parameter | Value |
|-----------|-------|
| `vp_token` | base64url-encoded DeviceResponse (no padding) |
| `presentation_submission` | Presentation Submission object |
| `state` | Copied from request (if present) |

##### Presentation Submission

```json
{
  "id": "mDL-sample-res",
  "definition_id": "mDL-sample-req",
  "descriptor_map": [
    {
      "id": "org.iso.18013.5.1.mDL",
      "format": "mso_mdoc",
      "path": "$"
    }
  ]
}
```

##### Authorization Response Encryption

The Authorization Response is **encrypted as a JWE** (not nested JWS+JWE):

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    Authorization Response Object (JWE)                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   JWE Header:                                                                   │
│   ───────────                                                                   │
│   {                                                                             │
│     "alg": "ECDH-ES",                                                           │
│     "enc": "A256GCM",                                                           │
│     "apu": "<base64url mdocGeneratedNonce>",                                    │
│     "apv": "<base64url nonce from request>",                                    │
│     "kid": "<key ID from jwks>",                                                │
│     "epk": {                                                                    │
│       "kty": "EC",                                                              │
│       "crv": "P-256",                                                           │
│       "x": "...",                                                               │
│       "y": "..."                                                                │
│     }                                                                           │
│   }                                                                             │
│                                                                                 │
│   JWE Payload (encrypted):                                                      │
│   ─────────────────────────                                                     │
│   {                                                                             │
│     "vp_token": "<base64url DeviceResponse>",                                   │
│     "presentation_submission": {...}                                            │
│   }                                                                             │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**JWE Header Parameters:**

| Parameter | Value | Description |
|-----------|-------|-------------|
| `alg` | `ECDH-ES` | Key agreement algorithm |
| `enc` | `A256GCM` | Content encryption algorithm |
| `apu` | base64url | `mdocGeneratedNonce` (used in SessionTranscript) |
| `apv` | base64url | `nonce` from Authorization Request |
| `kid` | String | Key ID of verifier's public key used |
| `epk` | JWK | mdoc's ephemeral public key (must match curve of verifier key) |

#### B.4.3 Session Transcript

The SessionTranscript for OID4VP differs from Part 5 and Annex A:

```cddl
SessionTranscript = [
  DeviceEngagementBytes,  ; null for OID4VP
  EReaderKeyBytes,        ; null for OID4VP
  Handover                ; OID4VPHandover
]

OID4VPHandover = [
  clientIdHash,           ; SHA-256 hash of clientIdToHash
  responseUriHash,        ; SHA-256 hash of responseUriToHash  
  nonce                   ; nonce from Authorization Request
]

clientIdToHash = [
  clientId,               ; client_id from request
  mdocGeneratedNonce      ; random nonce generated by mdoc
]

responseUriToHash = [
  responseUri,            ; response_uri from request
  mdocGeneratedNonce      ; same nonce
]
```

**Comparison with Other Methods:**

| Element | Part 5 | Annex A (Website) | Annex B (OID4VP) |
|---------|--------|-------------------|------------------|
| DeviceEngagementBytes | Present | Present | `null` |
| EReaderKeyBytes | Present | Present | `null` |
| Handover | Device engagement method | SHA-256(ReaderEngagementBytes) | OID4VPHandover |

#### B.4.4 mdoc MAC Authentication

For MAC authentication, the mdoc uses ephemeral public keys from `jwks` in Verifier Metadata:

- Use keys with `"use": "enc"` 
- The key acts as `EReaderKey.Pub` for ECKA-DH to derive MAC key

---

### B.5 Security Mechanisms

#### B.5.1 Security Goals Mapping

| Security Goal | OID4VP Implementation |
|---------------|----------------------|
| a) Session encryption | TLS for transport |
| b) Issuer data authentication | Same as Part 5 |
| c) mdoc authentication | Same as Part 5 |
| d) Response encryption | JWE encryption to verifier |
| e) Relay protection | Nonce binding to session |

**Relay Protection in OID4VP:**

The verifier maintains binding between user session and `nonce`. When user is redirected back with same nonce (in SessionTranscript), verifier can detect MITM attacks.

#### B.5.2 Cryptographic Curves

| Curve | kty | crv | Signature alg | Purpose |
|-------|-----|-----|---------------|--------|
| **NIST P-256** | EC | P-256 | ES256 | ECDSA/ECDH |
| **NIST P-384** | EC | P-384 | ES384 | ECDSA/ECDH |
| **NIST P-521** | EC | P-521 | ES512 | ECDSA/ECDH |
| **BrainpoolP256r1** | EC | BP-256 | ESB256 | ECDSA/ECDH |
| **BrainpoolP320r1** | EC | BP-320 | ESB320 | ECDSA/ECDH |
| **BrainpoolP384r1** | EC | BP-384 | ESB384 | ECDSA/ECDH |
| **BrainpoolP512r1** | EC | BP-512 | ESB512 | ECDSA/ECDH |
| **Curve25519** | OKP | Ed25519/X25519 | EdDSA | EdDSA/ECDH |
| **Curve448** | OKP | Ed448/X448 | EdDSA | EdDSA/ECDH |

**Requirements:**
- mdoc: Support at least one curve
- mdoc reader: Support ALL curves for response decryption

#### B.5.3 Nonce Entropy

| Requirement | Value |
|-------------|-------|
| Minimum entropy | 16 bytes |
| Randomness | Unpredictable random or pseudorandom |
| Uniqueness | New value for each transaction |
| Applies to | `nonce` and `mdocGeneratedNonce` |

---

### B.6 Examples

#### Example: Authorization Request URL

```
mdoc-openid4vp://
  ?client_id=example.com
  &request_uri=https%3A%2F%2Fexample.com%2F567545564
```

#### Example: Presentation Definition

```json
{
  "id": "mDL-sample-req",
  "input_descriptors": [{
    "id": "org.iso.18013.5.1.mDL",
    "format": {
      "mso_mdoc": {
        "alg": ["ES256", "ES384", "ES512", "EdDSA"]
      }
    },
    "constraints": {
      "limit_disclosure": "required",
      "fields": [
        {"path": ["$['org.iso.18013.5.1']['family_name']"], "intent_to_retain": false},
        {"path": ["$['org.iso.18013.5.1']['given_name']"], "intent_to_retain": false},
        {"path": ["$['org.iso.18013.5.1']['birth_date']"], "intent_to_retain": false},
        {"path": ["$['org.iso.18013.5.1']['portrait']"], "intent_to_retain": false}
      ]
    }
  }]
}
```

#### Example: Verifier Metadata (client_metadata)

```json
{
  "jwks": {
    "keys": [{
      "kty": "EC",
      "use": "enc",
      "crv": "P-256",
      "x": "xVLtZaPPK-xvruh1fEClNVTR6RCZBsQai2-DrnyKkxg",
      "y": "-5-QtFqJqGwOjEL3Ut89nrE0MeaUp5RozksKHpBiyw0",
      "alg": "ECDH-ES",
      "kid": "P8p0virRlh6fAkh5-YSeHt4EIv-hFGneYk14d8DF51w"
    }]
  },
  "authorization_encrypted_response_alg": "ECDH-ES",
  "authorization_encrypted_response_enc": "A256GCM",
  "vp_formats": {
    "mso_mdoc": {
      "alg": ["ES256", "ES384", "ES512", "EdDSA"]
    }
  }
}
```

#### Example: Presentation Submission

```json
{
  "id": "mDL-sample-res",
  "definition_id": "mDL-sample-req",
  "descriptor_map": [{
    "id": "org.iso.18013.5.1.mDL",
    "format": "mso_mdoc",
    "path": "$"
  }]
}
```

#### Example: JWE Header (Authorization Response)

```json
{
  "alg": "ECDH-ES",
  "enc": "A256GCM",
  "apu": "MTIzNDU2Nzg5MGFiY2RlZmdo",
  "apv": "YWJjZGVmZ2gxMjM0NTY3ODkw",
  "kid": "P8p0virRlh6fAkh5-YSeHt4EIv-hFGneYk14d8DF51w",
  "epk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "laKMaRZltDtdJV0fmSivSI2dhGyOJilIZcXjdsheEfM",
    "y": "jwiLJu_o4PlxGg0RS3zjjT7g3mNcydj5Vc0n5Neby0Y"
  }
}
```

#### Example: SessionTranscript (OID4VP)

```
SessionTranscript = [
  null,                           // DeviceEngagementBytes
  null,                           // EReaderKeyBytes  
  [                               // OID4VPHandover
    h'DA25C527...',               // clientIdHash (SHA-256)
    h'F6ED8E32...',               // responseUriHash (SHA-256)
    "abcdefgh1234567890"          // nonce
  ]
]
```

**CBOR Hex (OID4VPHandover):**
```
835820DA25C527E5FB75BC2DD31267C02237C4462BA0C1BF37071F692E7DD93B10AD0B
5820F6ED8E3220D3C59A5F17EB45F48AB70AEECF9EE21744B1014982350BD96AC0C5
72616263646566676831323334353637383930
```

---

## Annex C: Digital Credentials API

> **Normative Annex:** This section defines a mechanism to use the W3C Digital Credentials API for mDL presentation, transmitting DeviceRequest and DeviceResponse through a browser API.

### C.1 General

#### Overview

The Digital Credentials API provides a **browser-native** mechanism for credential presentation:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      Digital Credentials API Flow                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌──────────────┐        ┌──────────────┐        ┌──────────────┐             │
│   │   Website    │        │   Browser    │        │  mdoc app    │             │
│   │  (Verifier)  │        │    (API)     │        │  (Wallet)    │             │
│   └──────┬───────┘        └──────┬───────┘        └──────┬───────┘             │
│          │                       │                       │                     │
│          │ 1. navigator.credentials.get()                │                     │
│          │    (DeviceRequest + EncryptionInfo)          │                     │
│          ├──────────────────────►│                       │                     │
│          │                       │                       │                     │
│          │                       │ 2. Invoke wallet      │                     │
│          │                       │    with request       │                     │
│          │                       ├──────────────────────►│                     │
│          │                       │                       │                     │
│          │                       │                       │ [User consent]      │
│          │                       │                       │                     │
│          │                       │ 3. Encrypted response │                     │
│          │                       │    (HPKE)             │                     │
│          │                       │◄──────────────────────┤                     │
│          │                       │                       │                     │
│          │ 4. Return encrypted   │                       │                     │
│          │    DeviceResponse     │                       │                     │
│          │◄──────────────────────┤                       │                     │
│          │                       │                       │                     │
│          │ 5. Decrypt with       │                       │                     │
│          │    private key        │                       │                     │
│          │                       │                       │                     │
└──────────────────────────────────────────────────────────────────────────────────┘
```

**Key Characteristics:**

| Aspect | Digital Credentials API |
|--------|------------------------|
| Protocol identifier | `"org-iso-mdoc"` |
| Request format | JavaScript object with base64url CBOR |
| Response format | JavaScript object with HPKE-encrypted CBOR |
| Encryption | HPKE (RFC 9180) |
| Origin binding | Browser-provided SerializedOrigin |

**Comparison with Other Methods:**

| Feature | Annex A (Website) | Annex B (OID4VP) | Annex C (DC API) |
|---------|-------------------|------------------|------------------|
| Transport | HTTPS REST | OAuth 2.0 | Browser API |
| Request encryption | Session encryption | TLS only | N/A (request not encrypted) |
| Response encryption | Session encryption | JWE (ECDH-ES) | HPKE |
| Relay protection | OriginInfo | Nonce binding | Browser origin |

---

### C.2 Request Structure

The request is a JavaScript object passed to the Digital Credentials API:

```javascript
{
  "deviceRequest": Base64DeviceRequest,    // base64url-no-padding
  "encryptionInfo": Base64EncryptionInfo   // base64url-no-padding
}
```

#### DeviceRequest

`Base64DeviceRequest` is the **base64url-without-padding** encoding of the CBOR-encoded `DeviceRequest` structure from ISO/IEC 18013-5.

#### EncryptionInfo

`Base64EncryptionInfo` is the **base64url-without-padding** encoding of the CBOR-encoded `EncryptionInfo`:

```cddl
EncryptionInfo = [
  "dcapi",                  ; Protocol identifier
  EncryptionParameters
]

EncryptionParameters = {
  "nonce": bstr,            ; Random nonce (min 16 bytes entropy)
  "recipientPublicKey": COSE_Key   ; mdoc reader's public key
}
```

**EncryptionParameters Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `nonce` | bstr | Unpredictable random value, min 16 bytes entropy, unique per transaction |
| `recipientPublicKey` | COSE_Key | mdoc reader's public key for HPKE encryption |

**Example Request Object:**

```javascript
// JavaScript object passed to navigator.credentials.get()
{
  "deviceRequest": "omdkb2NUeXBlc...",  // base64url DeviceRequest
  "encryptionInfo": "gmVkY2FwaaNl..."   // base64url EncryptionInfo
}
```

---

### C.3 Response Structure

The response is a JavaScript object returned from the wallet:

```javascript
{
  "response": Base64EncryptedResponse   // base64url-no-padding
}
```

#### EncryptedResponse

`Base64EncryptedResponse` is the **base64url-without-padding** encoding of the CBOR-encoded `EncryptedResponse`:

```cddl
EncryptedResponse = [
  "dcapi",                  ; Protocol identifier
  EncryptedResponseData
]

EncryptedResponseData = {
  "enc": bstr,              ; HPKE ephemeral public key (serialized)
  "cipherText": bstr        ; Encrypted DeviceResponse
}
```

**EncryptedResponseData Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `enc` | bstr | Serialized ephemeral public key from HPKE |
| `cipherText` | bstr | HPKE-encrypted CBOR-encoded DeviceResponse |

---

### C.4 HPKE Encryption

The response is encrypted using **HPKE** (Hybrid Public Key Encryption) as defined in RFC 9180.

#### HPKE Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| **Mode** | Base | Single-shot encryption |
| **KEM** | DHKEM_P256 | Diffie-Hellman Key Encapsulation (P-256) |
| **KDF** | HKDF_SHA256 | Key Derivation Function |
| **AEAD** | AES_128_GCM | Authenticated Encryption |

#### mdoc Encryption (Wallet Side)

The mdoc performs HPKE single-shot encryption with these parameters:

| Parameter | Value |
|-----------|-------|
| `pkR` | Recipient public key from `EncryptionParameters` |
| `aad` | Empty |
| `info` | CBOR-encoded `SessionTranscript` |
| `pt` | CBOR-encoded `DeviceResponse` (plaintext) |

**Output:**
- `enc` → Serialized ephemeral public key
- `ct` → Ciphertext (encrypted DeviceResponse)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          HPKE Encryption (mdoc)                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Inputs:                                                                       │
│   ├── pkR (recipient public key from request)                                   │
│   ├── info (CBOR SessionTranscript)                                             │
│   ├── pt (CBOR DeviceResponse)                                                  │
│   └── aad (empty)                                                               │
│                                                                                 │
│                    ┌─────────────────────┐                                      │
│   DeviceResponse ──┤  HPKE.Seal()        ├──► enc (ephemeral public key)        │
│   (CBOR)           │  Mode: Base         │    cipherText (encrypted response)  │
│                    │  KEM: DHKEM_P256    │                                      │
│                    │  KDF: HKDF_SHA256   │                                      │
│                    │  AEAD: AES_128_GCM  │                                      │
│                    └─────────────────────┘                                      │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### mdoc Reader Decryption (Verifier Side)

The mdoc reader performs HPKE single-shot decryption:

| Parameter | Value |
|-----------|-------|
| `enc` | `enc` value from response |
| `info` | CBOR-encoded `SessionTranscript` |
| `ct` | `cipherText` from response |
| `skR` | Recipient (mdoc reader) private key |
| `aad` | Empty |

**Output:**
- Decrypted `DeviceResponse` (CBOR)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          HPKE Decryption (Reader)                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Inputs:                                                                       │
│   ├── enc (ephemeral public key from response)                                  │
│   ├── ct (cipherText from response)                                             │
│   ├── skR (reader's private key)                                                │
│   ├── info (CBOR SessionTranscript)                                             │
│   └── aad (empty)                                                               │
│                                                                                 │
│                    ┌─────────────────────┐                                      │
│   cipherText ──────┤  HPKE.Open()        ├──► DeviceResponse (CBOR)             │
│                    │  Mode: Base         │                                      │
│                    │  KEM: DHKEM_P256    │                                      │
│                    │  KDF: HKDF_SHA256   │                                      │
│                    │  AEAD: AES_128_GCM  │                                      │
│                    └─────────────────────┘                                      │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

### C.5 Session Transcript

The SessionTranscript for the Digital Credentials API is used for:
- HPKE encryption/decryption (`info` parameter)
- mdoc authentication
- mdoc reader authentication

```cddl
SessionTranscript = [
  null,                     ; DeviceEngagementBytes (not used)
  null,                     ; EReaderKeyBytes (not used)
  [                         ; DCAPIHandover
    "dcapi",                ; Protocol identifier
    dcapiInfoHash           ; SHA-256 hash of dcapiInfo
  ]
]

dcapiInfo = [
  Base64EncryptionInfo,     ; The encryptionInfo from the request
  SerializedOrigin          ; Browser-provided origin
]

SerializedOrigin = tstr     ; e.g., "https://gov.example.com"
dcapiInfoHash = bstr        ; SHA-256(CBOR(dcapiInfo))
```

**Comparison of Session Transcripts:**

| Element | Part 5 | Annex A | Annex B (OID4VP) | Annex C (DC API) |
|---------|--------|---------|------------------|------------------|
| DeviceEngagementBytes | Present | Present | `null` | `null` |
| EReaderKeyBytes | Present | Present | `null` | `null` |
| Handover | Device engagement | SHA-256(ReaderEngagementBytes) | OID4VPHandover | `["dcapi", dcapiInfoHash]` |

#### SerializedOrigin

The `SerializedOrigin` is the ASCII serialization of the request origin as defined by WHATWG HTML spec.

**Example:**
```
"https://gov.example.com"
```

**Critical Security Rules:**

| Rule | Description |
|------|-------------|
| Origin source | mdoc **MUST** use the origin received from the browser API |
| No origin | If the mdoc doesn't receive origin from API, it **SHALL abort** the transaction |
| No self-determination | mdoc shall NOT determine origin from request data |

This provides **relay attack protection** because:
1. Browser provides the actual origin of the requesting website
2. Origin is bound into the SessionTranscript (via hash)
3. Any relay attack would have mismatched origin in the transcript
4. mdoc authentication would fail verification

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    DC API Origin Protection                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   LEGITIMATE:                                                                   │
│   ┌──────────────┐        ┌──────────────┐        ┌──────────────┐             │
│   │  bank.com    │ ──────►│   Browser    │ ──────►│   Wallet     │             │
│   └──────────────┘        │              │        │              │             │
│                           │ origin =     │        │ Uses origin  │             │
│                           │ "bank.com"   │        │ in transcript│             │
│                           └──────────────┘        └──────────────┘             │
│                                                                                 │
│   Reader verifies: SessionTranscript contains "bank.com" ✅                     │
│                                                                                 │
│   ════════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   RELAY ATTACK (BLOCKED):                                                       │
│   ┌──────────────┐        ┌──────────────┐        ┌──────────────┐             │
│   │  evil.com    │ ──────►│   Browser    │ ──────►│   Wallet     │             │
│   │  (attacker)  │        │              │        │              │             │
│   └──────────────┘        │ origin =     │        │ Uses origin  │             │
│         ▲                 │ "evil.com"   │        │ "evil.com"   │             │
│         │ relays from     └──────────────┘        └──────────────┘             │
│   ┌─────┴────────┐                                                             │
│   │  bank.com    │                                                             │
│   └──────────────┘                                                             │
│                                                                                 │
│   bank.com reader verifies: SessionTranscript has "evil.com" ≠ "bank.com" ❌    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### Example SessionTranscript

```
SessionTranscript = [
  null,
  null,
  [
    "dcapi",
    h'A1B2C3D4...'    // SHA-256 hash of [Base64EncryptionInfo, "https://gov.example.com"]
  ]
]
```

---

## References

- ISO/IEC 18013-5:2021 - Mobile driving licence (mDL) application
- OID4VP (OpenID for Verifiable Presentations) - Draft specification
- ISO/IEC TS 18013-7:2025 - mDL add-on functions

---

*This document will be updated as more specification details are shared.*
