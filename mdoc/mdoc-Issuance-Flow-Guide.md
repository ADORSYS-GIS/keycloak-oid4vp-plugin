# mdoc Issuance Flow Guide

A comprehensive step-by-step guide explaining how an mdoc (mobile document) is built, encoded, and issued to a holder according to ISO/IEC 18013-5.

## Table of Contents
- [Introduction](#introduction)
- [What is Issuance?](#what-is-issuance)
- [The Players in Issuance](#the-players-in-issuance)
- [Issuance Flow Overview](#issuance-flow-overview)
- [Step 1: Identity Verification & Data Collection](#step-1-identity-verification--data-collection)
- [Step 2: Device Key Generation (Holder's Device)](#step-2-device-key-generation-holders-device)
- [Step 3: Create IssuerSignedItems](#step-3-create-issuersigneditems)
- [Step 4: CBOR Encode with Tag 24](#step-4-cbor-encode-with-tag-24)
- [Step 5: Hash Each Item for the MSO](#step-5-hash-each-item-for-the-mso)
- [Step 6: Build the Mobile Security Object (MSO)](#step-6-build-the-mobile-security-object-mso)
- [Step 7: Sign the MSO (Create IssuerAuth)](#step-7-sign-the-mso-create-issuerauth)
- [Step 8: Package the Final mdoc](#step-8-package-the-final-mdoc)
- [Step 9: Deliver to Holder's Device](#step-9-deliver-to-holders-device)
- [Complete Encoding Example](#complete-encoding-example)
- [Security Considerations](#security-considerations)
- [Data Type Reference](#data-type-reference)
- [Summary](#summary)

---

## Introduction

This guide explains **how an issuing authority (like a DMV) creates and issues an mdoc** to a holder's mobile device. The mdoc format is defined by ISO/IEC 18013-5 and enables secure, privacy-preserving digital credentials.

### What You'll Learn

- The complete issuance workflow from start to finish
- How each piece of the mdoc is constructed
- The CBOR encoding process
- How cryptographic security is built into the structure
- Why each design decision was made

### Prerequisites

This guide assumes basic familiarity with:
- What an mdoc is (a digital credential on a mobile device)
- Basic cryptography concepts (keys, signatures, hashes)
- What CBOR is (a binary data format)

---

## What is Issuance?

**Issuance** is the process where an authorized entity (the **issuer**) creates a digital credential and delivers it to a person (the **holder**).

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              ISSUANCE IN A NUTSHELL                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│                                                                                 │
│   ┌─────────────────┐                              ┌─────────────────┐         │
│   │    ISSUER       │                              │    HOLDER       │         │
│   │  (e.g., DMV)    │          mdoc                │  (You + Phone)  │         │
│   │                 │ ─────────────────────────►   │                 │         │
│   │  "I certify     │   Digitally signed           │  "I now have a  │         │
│   │   this data     │   credential                 │   verifiable    │         │
│   │   is correct"   │                              │   credential"   │         │
│   └─────────────────┘                              └─────────────────┘         │
│                                                                                 │
│   INPUT:                              OUTPUT:                                   │
│   • Identity verification             • Cryptographically signed mdoc          │
│   • Personal data                     • Stored on holder's device              │
│   • Holder's device public key        • Ready to present to verifiers          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Real-World Analogy

Think of issuance like getting a physical driver's licence:

| Physical Process | Digital (mdoc) Process |
|------------------|------------------------|
| Visit the DMV | Visit DMV or use online service |
| Show ID documents, take photo | Identity verification |
| DMV prints your licence card | Issuer builds the mdoc |
| You receive the plastic card | mdoc delivered to your phone |
| Card has security features (hologram, etc.) | mdoc has cryptographic signatures |

The big difference: With mdoc, **you can prove ownership** of the credential in a way that's impossible with plastic cards.

---

## The Players in Issuance

### 1. The Issuer

The **Issuing Authority** (e.g., DMV, government agency) who:
- Verifies the holder's identity
- Collects the credential data
- Signs the mdoc with their private key
- Delivers the mdoc to the holder

The issuer has a **PKI (Public Key Infrastructure)** hierarchy:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          ISSUER PKI HIERARCHY                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌─────────────────────────────────────────┐                                  │
│   │           IACA Root Certificate          │  ← Trust Anchor                 │
│   │    (Issuing Authority CA - Self-signed)  │    (Published to verifiers)     │
│   └────────────────────┬────────────────────┘                                  │
│                        │ signs                                                  │
│                        ▼                                                        │
│   ┌─────────────────────────────────────────┐                                  │
│   │       Document Signer Certificate        │  ← Signs mdocs                   │
│   │       (DS - Issued by IACA)              │    (Short-lived, rotatable)     │
│   └────────────────────┬────────────────────┘                                  │
│                        │ private key used to sign                               │
│                        ▼                                                        │
│   ┌─────────────────────────────────────────┐                                  │
│   │            Individual mdocs              │                                  │
│   │     (Signed by Document Signer)          │                                  │
│   └─────────────────────────────────────────┘                                  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 2. The Holder

The person receiving the credential. Critically, the **holder's device generates the device key pair**:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    HOLDER'S DEVICE KEY GENERATION                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   HOLDER'S DEVICE GENERATES:                                                    │
│                                                                                 │
│   ┌─────────────────────────────┐    ┌─────────────────────────────┐           │
│   │ SDeviceKey.Priv (PRIVATE)   │    │ SDeviceKey.Pub (PUBLIC)     │           │
│   │                             │    │                             │           │
│   │ • Stays on device FOREVER   │    │ • Sent to issuer            │           │
│   │ • Never leaves secure area  │    │ • Embedded in MSO           │           │
│   │ • Used for mdoc auth later  │    │ • Visible to verifiers      │           │
│   └─────────────────────────────┘    └─────────────────────────────┘           │
│              │                                     │                            │
│              │                                     │                            │
│              │ ───────────── X ──────────────────┐ │                            │
│              │                                   │ │                            │
│              │   ISSUER NEVER RECEIVES THIS ──────┘                            │
│              │                                                                  │
│              ▼                                                                  │
│   Used later to PROVE the mdoc is on the authorized device (prevents cloning)  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

> **Why this matters:** Even the issuer cannot clone your credential because they never have your private key!

---

## Issuance Flow Overview

Here's the complete flow at a glance:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        COMPLETE ISSUANCE FLOW                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   HOLDER                                  ISSUER                                │
│   ──────                                  ──────                                │
│                                                                                 │
│   ┌─────────────────┐                                                          │
│   │ 1. Apply for    │ ──────────────────► Identity verification                │
│   │    credential   │                     Data collection                       │
│   └─────────────────┘                                                          │
│                                                                                 │
│   ┌─────────────────┐                                                          │
│   │ 2. Generate     │                                                          │
│   │    device key   │ ──────────────────► Receive public key                   │
│   │    pair         │    (public only)                                         │
│   └─────────────────┘                                                          │
│                                                                                 │
│                                           ┌─────────────────────────┐          │
│                                           │ 3. Create IssuerSigned  │          │
│                                           │    Items (wrap data)    │          │
│                                           └──────────┬──────────────┘          │
│                                                      ▼                          │
│                                           ┌─────────────────────────┐          │
│                                           │ 4. CBOR encode with     │          │
│                                           │    Tag 24               │          │
│                                           └──────────┬──────────────┘          │
│                                                      ▼                          │
│                                           ┌─────────────────────────┐          │
│                                           │ 5. Hash each item       │          │
│                                           │    (SHA-256)            │          │
│                                           └──────────┬──────────────┘          │
│                                                      ▼                          │
│                                           ┌─────────────────────────┐          │
│                                           │ 6. Build MSO            │          │
│                                           │    (with all hashes)    │          │
│                                           └──────────┬──────────────┘          │
│                                                      ▼                          │
│                                           ┌─────────────────────────┐          │
│                                           │ 7. Sign MSO             │          │
│                                           │    (create issuerAuth)  │          │
│                                           └──────────┬──────────────┘          │
│                                                      ▼                          │
│                                           ┌─────────────────────────┐          │
│                                           │ 8. Package final mdoc   │          │
│                                           └──────────┬──────────────┘          │
│                                                      │                          │
│   ┌─────────────────┐                               │                          │
│   │ 9. Receive &    │ ◄──────────────────────────────                          │
│   │    store mdoc   │                                                          │
│   └─────────────────┘                                                          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Step 1: Identity Verification & Data Collection

### What Happens

Before issuing any credential, the issuer must:
1. **Verify the holder's identity** (in-person, online with ID verification, etc.)
2. **Collect the required data** (name, birth date, photo, etc.)

### The Data

For an mDL, typical data elements include:

| Category | Data Elements |
|----------|---------------|
| **Personal** | `family_name`, `given_name`, `birth_date`, `portrait` |
| **Document** | `document_number`, `issue_date`, `expiry_date` |
| **Issuer** | `issuing_country`, `issuing_authority`, `issuing_jurisdiction` |
| **Driving** | `driving_privileges`, `vehicle_category_code` |
| **Age Predicates** | `age_over_18`, `age_over_21`, etc. |

### Example Data (Before Processing)

```json
{
  "family_name": "Doe",
  "given_name": "Jane",
  "birth_date": "1990-01-15",
  "portrait": "<binary JPEG data>",
  "document_number": "D1234567",
  "issue_date": "2024-01-01",
  "expiry_date": "2029-01-01",
  "issuing_country": "US",
  "issuing_authority": "California DMV",
  "driving_privileges": [
    {"vehicle_category_code": "B", "issue_date": "2010-05-20", "expiry_date": "2029-01-01"}
  ],
  "age_over_21": true
}
```

---

## Step 2: Device Key Generation (Holder's Device)

### What Happens

The **holder's device** (not the issuer!) generates an asymmetric key pair:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     DEVICE KEY GENERATION                                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   HOLDER'S DEVICE                                                               │
│   ───────────────                                                               │
│                                                                                 │
│   1. Generate key pair (e.g., P-256 elliptic curve):                           │
│                                                                                 │
│      ┌─────────────────────────────────────────────────────────────────────┐   │
│      │ Private Key (SDeviceKey.Priv):                                      │   │
│      │   d = 0x9876...ABCD (32 bytes - kept secret!)                       │   │
│      └─────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
│      ┌─────────────────────────────────────────────────────────────────────┐   │
│      │ Public Key (SDeviceKey.Pub):                                        │   │
│      │   x = 0x96313D6C63E24E3372742BFDB1A33BA2C897DCD68AB8C753E4FBD48DCA   │   │
│      │   y = 0x1FB3269EDD418857DE1B39A4E4A44B92FA484CAA722C228288F01D0C03   │   │
│      └─────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
│   2. Store private key in secure area (Secure Enclave, TEE, etc.)              │
│                                                                                 │
│   3. Send ONLY the public key to the issuer                                    │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   ISSUER RECEIVES (public key in COSE_Key format):                             │
│                                                                                 │
│   {                                                                             │
│       1: 2,        // kty: EC (Elliptic Curve)                                 │
│      -1: 1,        // crv: P-256                                               │
│      -2: h'9631...', // x coordinate                                           │
│      -3: h'1FB3...'  // y coordinate                                           │
│   }                                                                             │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Why This Design?

| Security Property | How Device Key Achieves It |
|-------------------|----------------------------|
| **Anti-cloning** | Private key never leaves device; even issuer can't clone |
| **Holder authentication** | Device can prove it holds the credential |
| **Non-repudiation** | Device's signature proves possession |

---

## Step 3: Create IssuerSignedItems

### What Happens

Each data element is wrapped in an **IssuerSignedItem** structure:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    WRAPPING DATA IN IssuerSignedItem                             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   RAW DATA:                          IssuerSignedItem:                          │
│   family_name = "Doe"                                                           │
│                                      {                                          │
│         ─────────────────────►          "digestID": 0,                         │
│                                         "random": h'8798645B...FC20E9',        │
│                                         "elementIdentifier": "family_name",    │
│                                         "elementValue": "Doe"                  │
│                                      }                                          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### IssuerSignedItem Structure

```
IssuerSignedItem = {
    "digestID"          : uint,     // Unique ID linking to MSO hash
    "random"            : bstr,     // Random bytes (min 16 bytes)
    "elementIdentifier" : tstr,     // Field name
    "elementValue"      : any       // Actual value (properly typed)
}
```

### Field Purposes

| Field | Purpose | Example |
|-------|---------|---------|
| `digestID` | Unique number linking this item to its hash in the MSO | `0`, `1`, `2`, ... |
| `random` | Prevents brute-force guessing of values | 32 random bytes |
| `elementIdentifier` | The name of the data field | `"family_name"` |
| `elementValue` | The actual value (with proper CBOR type) | `"Doe"` |

### Why Random Bytes?

Without random bytes, an attacker could:
1. Know someone's name is probably common (e.g., "Smith", "Jones")
2. Hash all common names
3. Compare against the MSO digests
4. Learn the name even without seeing the data

With 16+ random bytes, there are 2^128 possibilities, making this attack infeasible.

### Example: Multiple Items

```
Item 0: family_name
────────────────────
{
    "digestID": 0,
    "random": h'8798645B20EA200E19FFABAC92624BEE6AEC63ACEEDECFB1B80077D22BFC20E9',
    "elementIdentifier": "family_name",
    "elementValue": "Doe"
}

Item 1: given_name
────────────────────
{
    "digestID": 1,
    "random": h'D26C5A5C0D6E5B14E8A3D12DC80E3F2A1B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E',
    "elementIdentifier": "given_name",
    "elementValue": "Jane"
}

Item 2: birth_date
────────────────────
{
    "digestID": 2,
    "random": h'A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90',
    "elementIdentifier": "birth_date",
    "elementValue": 1004("1990-01-15")     ← Note: Tag 1004 for dates!
}
```

---

## Step 4: CBOR Encode with Tag 24

### What Happens

Each IssuerSignedItem must be:
1. CBOR encoded
2. Wrapped in a byte string with **Tag 24**

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    TAG 24 ENCODING PROCESS                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   STEP A: CBOR encode the IssuerSignedItem                                      │
│                                                                                 │
│   {                                                                             │
│     "digestID": 0,                                                              │
│     "random": h'8798...',                                                       │
│     "elementIdentifier": "family_name",                                         │
│     "elementValue": "Doe"                                                       │
│   }                                                                             │
│              │                                                                  │
│              │ CBOR encode                                                      │
│              ▼                                                                  │
│   h'A4686469676573744944006672616E646F6D58208798...'  (binary bytes)           │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   STEP B: Wrap as Tag 24 (CBOR tag for "embedded CBOR")                        │
│                                                                                 │
│   Tag 24 says: "This byte string contains CBOR data"                           │
│                                                                                 │
│   24(<< {digestID: 0, random: ..., elementIdentifier: "family_name", ...} >>)  │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   STEP C: CBOR encode the tagged value → IssuerSignedItemBytes                 │
│                                                                                 │
│   h'D818584AA4686469676573744944...'                                           │
│    ↑                                                                            │
│    D8 18 = Tag 24 in CBOR encoding                                             │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Why Tag 24?

Tag 24 is critical for **selective disclosure**:

| Without Tag 24 | With Tag 24 |
|----------------|-------------|
| Items are part of one big structure | Each item is self-contained |
| Hash depends on position in structure | Hash is independent |
| Can't selectively reveal items | Can reveal individual items |
| Verification requires all data | Verification works with partial data |

### CDDL Definition

```
IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
```

Translation: "A CBOR Tag 24 containing a byte string that, when decoded, is an IssuerSignedItem"

---

## Step 5: Hash Each Item for the MSO

### What Happens

Each **IssuerSignedItemBytes** is hashed using SHA-256:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         HASHING FOR MSO                                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   IssuerSignedItemBytes #0                       Hash #0                        │
│   ┌──────────────────────────┐                   ┌────────────────────────┐    │
│   │ D818584AA46864696765...  │   ───SHA-256───►  │ h'75167333B47B6C2BFB   │    │
│   │ (family_name = "Doe")    │                   │   86ECCC1F438CF57AF0   │    │
│   └──────────────────────────┘                   │   55371AC55E1E359E20   │    │
│                                                  │   F254ADCEBF'          │    │
│                                                  └────────────────────────┘    │
│                                                                                 │
│   IssuerSignedItemBytes #1                       Hash #1                        │
│   ┌──────────────────────────┐                   ┌────────────────────────┐    │
│   │ D818584AA46864696765...  │   ───SHA-256───►  │ h'67E539D6139EBD131A   │    │
│   │ (given_name = "Jane")    │                   │   EF441B445645DD831B   │    │
│   └──────────────────────────┘                   │   2B375B390CA5EF6279   │    │
│                                                  │   B205ED4571'          │    │
│                                                  └────────────────────────┘    │
│                                                                                 │
│   ... repeat for all items ...                                                  │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   RESULT: A map of digestID → hash                                              │
│                                                                                 │
│   valueDigests = {                                                              │
│       "org.iso.18013.5.1": {                                                    │
│           0: h'75167333...',  // family_name                                    │
│           1: h'67E539D6...',  // given_name                                     │
│           2: h'3394372D...',  // birth_date                                     │
│           ...                                                                   │
│       }                                                                         │
│   }                                                                             │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### The Magic of Hashing

This is what enables **selective disclosure**:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    HOW SELECTIVE DISCLOSURE WORKS                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   AT ISSUANCE:                                                                  │
│   ────────────                                                                  │
│   • Issuer creates IssuerSignedItemBytes for every field                       │
│   • Issuer hashes each one and stores hashes in MSO                            │
│   • Issuer signs the MSO (containing ALL hashes)                               │
│   • Holder receives: all IssuerSignedItemBytes + signed MSO                    │
│                                                                                 │
│   AT PRESENTATION:                                                              │
│   ────────────────                                                              │
│   • Verifier requests specific fields (e.g., just "age_over_21")               │
│   • Holder sends: requested IssuerSignedItemBytes + signed MSO                 │
│   • Verifier:                                                                   │
│     1. Hashes the received IssuerSignedItemBytes                               │
│     2. Compares hash to the one in MSO                                         │
│     3. Verifies MSO signature                                                  │
│     4. If all match → data is authentic!                                       │
│                                                                                 │
│   KEY INSIGHT:                                                                  │
│   ────────────                                                                  │
│   • Verifier sees hashes for ALL fields in the MSO                             │
│   • But can only see VALUES for fields holder chose to share                   │
│   • Hash is one-way: can't reverse hash → value                                │
│   • Random bytes prevent guessing                                               │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Step 6: Build the Mobile Security Object (MSO)

### What Happens

The MSO is the "security backbone" of the mdoc. It contains:
- All the hashes (enabling selective disclosure)
- The holder's device public key (enabling authentication)
- Validity information (preventing expired credentials)

### MSO Structure

```
MobileSecurityObject = {
    "version"         : "1.0",
    "digestAlgorithm" : "SHA-256",
    "valueDigests"    : ValueDigests,
    "deviceKeyInfo"   : DeviceKeyInfo,
    "docType"         : DocType,
    "validityInfo"    : ValidityInfo
}
```

### Complete MSO Example

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    COMPLETE MSO STRUCTURE                                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   {                                                                             │
│       "version": "1.0",                                                         │
│                                                                                 │
│       "digestAlgorithm": "SHA-256",                                             │
│                                                                                 │
│       "valueDigests": {                                                         │
│           "org.iso.18013.5.1": {                                                │
│               0: h'75167333B47B6C2BFB86ECCC1F438CF57AF055371AC55E1E359E20F254AD│
│                   CEBF',  // family_name                                        │
│               1: h'67E539D6139EBD131AEF441B445645DD831B2B375B390CA5EF6279B205ED│
│                   4571',  // given_name                                         │
│               2: h'3394372DDB78053F36D5D869780E61EDA313D44A392092AD8E0527A2FBFE│
│                   55AE',  // birth_date                                         │
│               3: h'2E35AD3C4E514BB67B1A9DB51CE74E4CB9B7146E41AC52DAC9CE86B8613D│
│                   B555',  // portrait                                           │
│               // ... more hashes for each data element                          │
│           }                                                                     │
│       },                                                                        │
│                                                                                 │
│       "deviceKeyInfo": {                                                        │
│           "deviceKey": {                                                        │
│               1: 2,       // kty: EC                                            │
│              -1: 1,       // crv: P-256                                         │
│              -2: h'96313D6C63E24E3372742BFDB1A33BA2C897DCD68AB8C753E4FBD48DCA   │
│                   6B7F9A',  // x coordinate                                     │
│              -3: h'1FB3269EDD418857DE1B39A4E4A44B92FA484CAA722C228288F01D0C03   │
│                   A2C3D6'   // y coordinate                                     │
│           }                                                                     │
│       },                                                                        │
│                                                                                 │
│       "docType": "org.iso.18013.5.1.mDL",                                       │
│                                                                                 │
│       "validityInfo": {                                                         │
│           "signed": 0("2024-01-15T10:30:00Z"),     // When MSO was signed       │
│           "validFrom": 0("2024-01-15T10:30:00Z"),  // Start of validity         │
│           "validUntil": 0("2025-01-15T10:30:00Z")  // End of validity           │
│       }                                                                         │
│   }                                                                             │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### MSO Components Explained

| Component | Purpose |
|-----------|---------|
| `version` | MSO format version (currently "1.0") |
| `digestAlgorithm` | Hash algorithm used ("SHA-256", "SHA-384", or "SHA-512") |
| `valueDigests` | Map of namespace → (digestID → hash) |
| `deviceKeyInfo` | Holder's device public key (for mdoc authentication) |
| `docType` | Document type identifier |
| `validityInfo` | When the credential is valid |

---

## Step 7: Sign the MSO (Create IssuerAuth)

### What Happens

The MSO is signed using **COSE_Sign1** to create the `issuerAuth`:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    CREATING issuerAuth (COSE_Sign1)                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   INPUT:                                                                        │
│   • MSO (the Mobile Security Object)                                            │
│   • Document Signer private key                                                 │
│   • Document Signer certificate (chains to IACA)                                │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   STEP A: Prepare the MSO as MobileSecurityObjectBytes                          │
│                                                                                 │
│   mso_bytes = Tag 24( CBOR_encode(MSO) )                                        │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   STEP B: Build the COSE_Sign1 structure                                        │
│                                                                                 │
│   issuerAuth = [                                                                │
│       protected,      // Algorithm info (wrapped as bstr)                       │
│       unprotected,    // Certificate chain                                      │
│       payload,        // MobileSecurityObjectBytes                              │
│       signature       // Digital signature                                      │
│   ]                                                                             │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   STEP C: Create the Sig_structure (what actually gets signed)                  │
│                                                                                 │
│   Sig_structure = [                                                             │
│       "Signature1",           // Context string                                 │
│       protected_bytes,        // Protected header                               │
│       h'',                    // External AAD (empty)                           │
│       mso_bytes               // The payload                                    │
│   ]                                                                             │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   STEP D: Sign                                                                  │
│                                                                                 │
│   signature = ECDSA_Sign(                                                       │
│       DS_private_key,                                                           │
│       SHA-256( CBOR_encode(Sig_structure) )                                    │
│   )                                                                             │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### IssuerAuth Structure

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         issuerAuth COSE_Sign1                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Index 0: protected                                                            │
│   ───────────────────                                                           │
│   << { 1: -7 } >>                                                               │
│        ↑   ↑                                                                    │
│        │   └── -7 = ES256 (ECDSA with P-256 and SHA-256)                       │
│        └────── 1 = "alg" (algorithm) header parameter                          │
│                                                                                 │
│   Index 1: unprotected                                                          │
│   ────────────────────                                                          │
│   { 33: <certificate chain> }                                                   │
│      ↑                                                                          │
│      └── 33 = "x5chain" (X.509 certificate chain)                              │
│                                                                                 │
│   Index 2: payload                                                              │
│   ─────────────────                                                             │
│   << MobileSecurityObjectBytes >>                                               │
│      (The MSO wrapped in Tag 24)                                                │
│                                                                                 │
│   Index 3: signature                                                            │
│   ─────────────────                                                             │
│   h'59E64205DF1E2F708DD6DB0847AED79FC7...' (64 bytes for ES256)                │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Certificate Chain (x5chain)

The certificate chain allows verifiers to validate the signature:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    CERTIFICATE CHAIN VALIDATION                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Verifier's Trust Anchor:                                                      │
│   ┌─────────────────────────────────┐                                          │
│   │ IACA Root Certificate (trusted) │                                          │
│   └────────────────┬────────────────┘                                          │
│                    │ must chain to                                              │
│                    ▼                                                            │
│   From x5chain:                                                                 │
│   ┌─────────────────────────────────┐                                          │
│   │ Document Signer Certificate     │ ← Public key matches signature           │
│   └────────────────┬────────────────┘                                          │
│                    │ signed with                                                │
│                    ▼                                                            │
│   ┌─────────────────────────────────┐                                          │
│   │ issuerAuth signature            │ ← Verifies against DS public key         │
│   └─────────────────────────────────┘                                          │
│                                                                                 │
│   VERIFICATION FLOW:                                                            │
│   1. Extract DS certificate from x5chain                                        │
│   2. Verify DS certificate chains to trusted IACA                               │
│   3. Extract public key from DS certificate                                     │
│   4. Verify issuerAuth signature using that public key                          │
│   5. If valid → MSO is authentic!                                               │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Step 8: Package the Final mdoc

### What Happens

All components are assembled into the final mdoc structure:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         FINAL mdoc STRUCTURE                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   mdoc = {                                                                      │
│       "docType": "org.iso.18013.5.1.mDL",                                       │
│                                                                                 │
│       "issuerSigned": {                                                         │
│           "nameSpaces": {                                                       │
│               "org.iso.18013.5.1": [                                            │
│                   24(<< {digestID:0, random:..., elementId:"family_name", ...}  │
│                       >>),                                                      │
│                   24(<< {digestID:1, random:..., elementId:"given_name", ...}   │
│                       >>),                                                      │
│                   24(<< {digestID:2, random:..., elementId:"birth_date", ...}   │
│                       >>),                                                      │
│                   // ... more IssuerSignedItemBytes                             │
│               ]                                                                 │
│           },                                                                    │
│           "issuerAuth": [                                                       │
│               << {1: -7} >>,                    // protected header             │
│               {33: [<DS cert>, <IACA cert>]},   // unprotected (x5chain)        │
│               << 24(<< MSO >>) >>,              // payload (MSO)                │
│               h'59E64205...'                    // signature                    │
│           ]                                                                     │
│       }                                                                         │
│   }                                                                             │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Visual Structure

```
mdoc
├── docType: "org.iso.18013.5.1.mDL"
│
└── issuerSigned
    ├── nameSpaces
    │   └── "org.iso.18013.5.1"
    │       ├── [0] IssuerSignedItemBytes (family_name)
    │       ├── [1] IssuerSignedItemBytes (given_name)
    │       ├── [2] IssuerSignedItemBytes (birth_date)
    │       ├── [3] IssuerSignedItemBytes (portrait)
    │       ├── [4] IssuerSignedItemBytes (document_number)
    │       └── ... more items
    │
    └── issuerAuth (COSE_Sign1)
        ├── protected: {alg: ES256}
        ├── unprotected: {x5chain: [DS cert, IACA cert]}
        ├── payload: MSO (with all hashes + device key)
        └── signature: <64 bytes>
```

---

## Step 9: Deliver to Holder's Device

### What Happens

The completed mdoc is delivered to the holder's device. **This process (Interface 1) is NOT specified by ISO 18013-5**, allowing flexibility in implementation.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         DELIVERY OPTIONS                                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ISSUER                                  HOLDER'S DEVICE                       │
│   ──────                                  ───────────────                       │
│                                                                                 │
│   ┌─────────────────┐                    ┌─────────────────┐                   │
│   │  Complete mdoc  │ ──────────────────►│  Wallet App     │                   │
│   │  (CBOR encoded) │                    │                 │                   │
│   └─────────────────┘                    └─────────────────┘                   │
│                                                                                 │
│   POSSIBLE DELIVERY METHODS:                                                    │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │ • OID4VCI (OpenID for Verifiable Credential Issuance)                   │  │
│   │   - Standard protocol for credential issuance                           │  │
│   │   - HTTPS-based                                                          │  │
│   │   - Supports various wallet apps                                         │  │
│   │                                                                          │  │
│   │ • Proprietary App Protocol                                               │  │
│   │   - Direct API from issuer's app to wallet                              │  │
│   │   - Custom implementation                                                │  │
│   │                                                                          │  │
│   │ • QR Code + Download                                                     │  │
│   │   - QR code contains URL                                                 │  │
│   │   - Device downloads mdoc from URL                                       │  │
│   │                                                                          │  │
│   │ • NFC Tap at Kiosk                                                       │  │
│   │   - Physical kiosk at DMV                                                │  │
│   │   - NFC transfer to device                                               │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│   UPON RECEIPT:                                                                 │
│                                                                                 │
│   1. Wallet validates the mdoc structure                                        │
│   2. Wallet verifies issuerAuth signature chains to known IACA                  │
│   3. Wallet confirms deviceKey in MSO matches device's key pair                │
│   4. Wallet stores mdoc securely                                                │
│   5. mdoc is ready for presentation!                                            │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Complete Encoding Example

Here's a simplified end-to-end example showing the encoding process:

### Input Data

```
family_name = "Doe"
```

### Step-by-Step Encoding

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    COMPLETE ENCODING WALKTHROUGH                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   1. CREATE IssuerSignedItem (CBOR Diagnostic):                                 │
│   ─────────────────────────────────────────────                                 │
│   {                                                                             │
│       "digestID": 0,                                                            │
│       "random": h'8798645B20EA200E19FFABAC92624BEE6AEC63ACEEDECFB1B80077D22BFC │
│                   20E9',                                                        │
│       "elementIdentifier": "family_name",                                       │
│       "elementValue": "Doe"                                                     │
│   }                                                                             │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   2. CBOR ENCODE the IssuerSignedItem:                                          │
│   ────────────────────────────────────                                          │
│                                                                                 │
│   A4                        // Map with 4 items                                 │
│     68 6469676573744944     // Key: "digestID" (text, 8 bytes)                 │
│     00                      // Value: 0 (unsigned int)                          │
│     66 72616E646F6D         // Key: "random" (text, 6 bytes)                   │
│     5820 8798645B20EA...    // Value: byte string, 32 bytes                    │
│     71 656C656D656E744964656E746966696572  // Key: "elementIdentifier"         │
│     6B 66616D696C795F6E616D65              // Value: "family_name"             │
│     6C 656C656D656E7456616C7565            // Key: "elementValue"              │
│     63 446F65               // Value: "Doe" (text, 3 bytes)                    │
│                                                                                 │
│   → item_bytes = h'A4686469676573744944006672616E646F6D58208798645B...'        │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   3. WRAP WITH TAG 24:                                                          │
│   ────────────────────                                                          │
│                                                                                 │
│   D8 18                     // Tag 24 (CBOR encoding)                          │
│   58 4A                     // Byte string, 74 bytes                           │
│   A4686469676573744944...   // The item_bytes from above                       │
│                                                                                 │
│   → IssuerSignedItemBytes = h'D818584AA4686469676573744944006672...'           │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   4. HASH FOR MSO:                                                              │
│   ────────────────                                                              │
│                                                                                 │
│   SHA-256(IssuerSignedItemBytes)                                                │
│     = h'75167333B47B6C2BFB86ECCC1F438CF57AF055371AC55E1E359E20F254ADCEBF'      │
│                                                                                 │
│   This hash goes into MSO.valueDigests["org.iso.18013.5.1"][0]                 │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Considerations

### 1. Key Protection

| Key | Location | Protection |
|-----|----------|------------|
| IACA Private Key | Issuer HSM | Highest security, air-gapped |
| DS Private Key | Issuer system | Hardware security module |
| Device Private Key | Holder's device | Secure Enclave / TEE |

### 2. Random Bytes

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    IMPORTANCE OF RANDOM BYTES                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   WITHOUT RANDOM:                     WITH RANDOM:                              │
│   ───────────────                     ────────────                              │
│                                                                                 │
│   Attacker knows hash algorithm       Attacker knows hash algorithm            │
│   Attacker guesses: "Doe"             Attacker guesses: "Doe"                  │
│   Attacker computes: SHA256("Doe")    Attacker computes: SHA256("Doe")         │
│   Result: h'ABC123...'                Result: h'ABC123...'                      │
│                                                                                 │
│   Compare to MSO:                     Compare to MSO:                           │
│   MSO has: h'ABC123...'               MSO has: h'75167333...'                   │
│   MATCH! 💥 Value exposed!            NO MATCH! ✅ Value safe!                  │
│                                                                                 │
│   WHY?                                WHY?                                      │
│   Hash(value) is predictable          Hash(random + value) is unpredictable   │
│                                                                                 │
│   REQUIREMENT: At least 16 bytes of random (128 bits)                          │
│   RECOMMENDATION: 32 bytes (256 bits) for extra security                       │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 3. Certificate Validity

- DS certificates should be short-lived (days to months)
- IACA certificates are long-lived (years)
- Verifiers must check certificate revocation

### 4. Device Key Binding

The device key in the MSO ensures:
- Only the original device can authenticate
- Even the issuer cannot clone the credential
- Presentation requires proof of device key possession

---

## Data Type Reference

### CBOR Types for mdoc Data

| Data Type | CBOR Type | Example |
|-----------|-----------|---------|
| Text | tstr | `"Doe"` |
| Number | uint/int | `42`, `-5` |
| Boolean | bool | `true`, `false` |
| Date (no time) | Tag 1004 | `1004("2024-01-15")` |
| Date-time | Tag 0 | `0("2024-01-15T10:30:00Z")` |
| Binary data | bstr | `h'FFD8FFE0...'` (JPEG) |
| Array | array | `[item1, item2, ...]` |
| Map | map | `{"key": value}` |

### Common mDL Data Elements

| Element | CBOR Type | Example |
|---------|-----------|---------|
| `family_name` | tstr | `"Doe"` |
| `given_name` | tstr | `"Jane"` |
| `birth_date` | Tag 1004 | `1004("1990-01-15")` |
| `portrait` | bstr | JPEG/JPEG2000 bytes |
| `issue_date` | Tag 1004 | `1004("2024-01-01")` |
| `expiry_date` | Tag 1004 | `1004("2029-01-01")` |
| `document_number` | tstr | `"D1234567"` |
| `issuing_country` | tstr | `"US"` |
| `age_over_21` | bool | `true` |
| `driving_privileges` | array | `[{vehicle_category_code: "B", ...}]` |

---

## Summary

### The Complete Issuance Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          ISSUANCE SUMMARY                                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   1. VERIFY IDENTITY           Confirm holder is who they claim                 │
│   2. COLLECT DATA              Gather all credential attributes                 │
│   3. GET DEVICE KEY            Holder's device provides public key              │
│   4. WRAP DATA                 Each value → IssuerSignedItem                    │
│   5. ENCODE                    Each item → Tag 24 CBOR bytes                   │
│   6. HASH                      Each encoded item → SHA-256 digest              │
│   7. BUILD MSO                 All hashes + device key + validity              │
│   8. SIGN                      MSO → COSE_Sign1 (issuerAuth)                   │
│   9. PACKAGE                   Everything → final mdoc                          │
│  10. DELIVER                   Send to holder's device                          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Key Takeaways

| Concept | Why It Matters |
|---------|----------------|
| **Hash-based selective disclosure** | Share only what's needed |
| **Device key generation by holder** | Prevents cloning, even by issuer |
| **Random bytes in each item** | Prevents hash-based guessing |
| **Tag 24 encoding** | Enables independent verification of each item |
| **COSE_Sign1 signature** | Proves authenticity and integrity |
| **Certificate chain** | Links to trusted issuing authority |

### What Happens Next?

After issuance, the holder can:
1. **Present** the mdoc to verifiers (see mdoc presentation documentation)
2. **Selectively disclose** only needed attributes
3. **Prove possession** using the device key
4. **Refresh** the credential when it expires

---

## References

- ISO/IEC 18013-5:2021 - Personal identification — ISO-compliant driving licence — Part 5: Mobile driving licence (mDL) application
- RFC 8152 - CBOR Object Signing and Encryption (COSE)
- RFC 8949 - Concise Binary Object Representation (CBOR)

---

*This guide is part of the mdoc documentation series. See also:*
- [mdoc-Data-Structure-Guide.md](mdoc-Data-Structure-Guide.md) - Complete data structure reference
- [ISO-MDOC-Specification.md](ISO-MDOC-Specification.md) - Full specification overview
