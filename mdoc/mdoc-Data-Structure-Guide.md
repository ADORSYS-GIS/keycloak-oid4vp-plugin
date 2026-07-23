# mdoc Data Structure Guide

A comprehensive guide to understanding how Mobile Documents (mdocs) are structured, encoded, and issued according to ISO/IEC 18013-5.

## Table of Contents
- [Introduction](#introduction)
- [The Big Picture](#the-big-picture)
- [How the Issuer Builds an mdoc (Step-by-Step)](#how-the-issuer-builds-an-mdoc-step-by-step)
- [Document Type (docType)](#document-type-doctype)
- [Namespaces](#namespaces)
- [Data Elements](#data-elements)
- [IssuerSigned Structure](#issuersigned-structure)
- [Mobile Security Object (MSO)](#mobile-security-object-mso)
  - [IssuerAuth (COSE_Sign1)](#issuerauth-cose_sign1)
- [DeviceSigned Structure](#devicesigned-structure)
- [CBOR Encoding](#cbor-encoding)
- [Understanding CBOR Diagnostic Notation](#understanding-cbor-diagnostic-notation)
- [Device Engagement](#device-engagement)
- [Request and Response](#request-and-response)
- [Complete mdoc Example](#complete-mdoc-example)
  - [Part 1: Full Issued mdoc Structure](#part-1-full-issued-mdoc-structure)
  - [Part 2: Presentation at the Bar](#part-2-presentation-at-the-bar)
  - [Issuance vs Presentation Comparison](#issuance-vs-presentation-comparison)
- [Putting It All Together](#putting-it-all-together)
- [Summary](#summary)

---

## Introduction

An **mdoc** (mobile document) is a digitally signed credential stored on a mobile device. The most common example is the **mDL** (mobile Driving Licence), but the same structure can be used for other documents like passports, health cards, or employee IDs.


This guide explains how an mdoc is built from the ground up, piece by piece.

### Why This Structure?

The mdoc structure is designed to achieve three critical goals:

1. **Selective Disclosure** - Share only what's needed (e.g., "I'm over 21" without revealing your birth date)
2. **Authenticity** - Prove the data came from a legitimate issuer
3. **Privacy** - Prevent tracking and minimize data exposure

---

## The Big Picture

Here's the complete structure of an mdoc at a glance:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              mdoc                                         │
├──────────────────────────────────────────────────────────────────────────┤
│  docType: "org.iso.18013.5.1.mDL"                                        │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                        issuerSigned                                 │  │
│  │  ┌──────────────────────────────────────────────────────────────┐  │  │
│  │  │  nameSpaces                                                   │  │  │
│  │  │    "org.iso.18013.5.1": [                                    │  │  │
│  │  │      IssuerSignedItem(family_name),                          │  │  │
│  │  │      IssuerSignedItem(given_name),                           │  │  │
│  │  │      IssuerSignedItem(birth_date),                           │  │  │
│  │  │      ...                                                      │  │  │
│  │  │    ]                                                          │  │  │
│  │  └──────────────────────────────────────────────────────────────┘  │  │
│  │  ┌──────────────────────────────────────────────────────────────┐  │  │
│  │  │  issuerAuth (COSE_Sign1)                                     │  │  │
│  │  │    - Protected Header (algorithm)                            │  │  │
│  │  │    - Unprotected Header (x5chain certificate)                │  │  │
│  │  │    - Payload: Mobile Security Object (MSO)                   │  │  │
│  │  │    - Signature                                               │  │  │
│  │  └──────────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                        deviceSigned                                 │  │
│  │    nameSpaces: {} (usually empty)                                  │  │
│  │    deviceAuth:                                                      │  │
│  │      - deviceMac (COSE_Mac0) OR                                    │  │
│  │      - deviceSignature (COSE_Sign1)                                │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## How the Issuer Builds an mdoc (Step-by-Step)

Before diving into details, here's the **complete building process** from start to finish. This is what the issuer (e.g., DMV) does to create an mdoc.

### Overview: 7 Steps to Build an mdoc

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    ISSUER'S mdoc BUILDING PROCESS                                │
│                                                                                 │
│  INPUT: Raw holder data (name, birthdate, photo, etc.)                         │
│  OUTPUT: Complete mdoc ready for holder's device                               │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ STEP 1: Collect holder data                                              │   │
│  │         { name: "Jane Doe", birth_date: "1990-01-15", photo: <bytes> }   │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                    │                                            │
│                                    ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ STEP 2: Get holder's device public key                                   │   │
│  │         (The holder generates a key pair; issuer gets the public key)    │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                    │                                            │
│                                    ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ STEP 3: Wrap each data element in IssuerSignedItem                       │   │
│  │                                                                          │   │
│  │   For EACH data element:                                                 │   │
│  │   ┌────────────────────────────────────────────┐                        │   │
│  │   │ item = {                                    │                        │   │
│  │   │   digestID: <unique number>,               │ ← Links to hash in MSO │   │
│  │   │   random: <32 random bytes>,               │ ← Prevents guessing    │   │
│  │   │   elementIdentifier: "family_name",        │ ← Field name           │   │
│  │   │   elementValue: "Doe"                      │ ← Actual value         │   │
│  │   │ }                                          │                        │   │
│  │   └────────────────────────────────────────────┘                        │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                    │                                            │
│                                    ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ STEP 4: Encode and wrap each item in Tag 24                              │   │
│  │                                                                          │   │
│  │   item_bytes = CBOR_encode(item)        → Binary CBOR                   │   │
│  │   tagged = Tag(24, item_bytes)          → IssuerSignedItemBytes         │   │
│  │   final_bytes = CBOR_encode(tagged)     → Ready for hashing             │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                    │                                            │
│                                    ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ STEP 5: Hash each item for the MSO                                       │   │
│  │                                                                          │   │
│  │   For EACH IssuerSignedItemBytes:                                        │   │
│  │   hash = SHA-256(final_bytes)           → 32-byte digest                │   │
│  │                                                                          │   │
│  │   Store in: valueDigests[namespace][digestID] = hash                    │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                    │                                            │
│                                    ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ STEP 6: Build and sign the MSO                                           │   │
│  │                                                                          │   │
│  │   MSO = {                                                                │   │
│  │     version: "1.0",                                                      │   │
│  │     digestAlgorithm: "SHA-256",                                          │   │
│  │     valueDigests: { <all the hashes from Step 5> },                     │   │
│  │     deviceKeyInfo: { deviceKey: <holder's public key from Step 2> },    │   │
│  │     docType: "org.iso.18013.5.1.mDL",                                    │   │
│  │     validityInfo: { signed: <now>, validFrom: <now>, validUntil: <+1yr> }│   │
│  │   }                                                                      │   │
│  │                                                                          │   │
│  │   Sign MSO with Document Signer private key → COSE_Sign1 (issuerAuth)   │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                    │                                            │
│                                    ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ STEP 7: Package everything into final mdoc                               │   │
│  │                                                                          │   │
│  │   mdoc = {                                                               │   │
│  │     docType: "org.iso.18013.5.1.mDL",                                    │   │
│  │     issuerSigned: {                                                      │   │
│  │       nameSpaces: {                                                      │   │
│  │         "org.iso.18013.5.1": [ <all IssuerSignedItemBytes> ]            │   │
│  │       },                                                                 │   │
│  │       issuerAuth: <COSE_Sign1 from Step 6>                              │   │
│  │     }                                                                    │   │
│  │   }                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                    │                                            │
│                                    ▼                                            │
│                          Send to holder's device                               │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Simplified Code Example

```python
# Complete mdoc issuance in pseudocode

# STEP 1: Holder's data (from identity verification)
holder_data = {
    "family_name": "Doe",
    "given_name": "Jane", 
    "birth_date": "1990-01-15",
    "portrait": photo_bytes,
    # ... more fields
}

# STEP 2: Get device public key from holder
device_public_key = holder.get_public_key()

# STEP 3 & 4: Create IssuerSignedItems with Tag 24
items = []
hashes = {}
digest_id = 0

for field_name, value in holder_data.items():
    # STEP 3: Build the item
    item = {
        "digestID": digest_id,
        "random": generate_random_bytes(32),
        "elementIdentifier": field_name,
        "elementValue": tag_if_date(value)  # Add Tag 1004 for dates
    }
    
    # STEP 4: Encode with Tag 24
    item_bytes = cbor_encode(item)
    tagged_item = cbor_encode(CBORTag(24, item_bytes))
    items.append(tagged_item)
    
    # STEP 5: Hash for MSO
    hashes[digest_id] = sha256(tagged_item)
    digest_id += 1

# STEP 6: Build MSO
mso = {
    "version": "1.0",
    "digestAlgorithm": "SHA-256",
    "valueDigests": {"org.iso.18013.5.1": hashes},
    "deviceKeyInfo": {"deviceKey": device_public_key},
    "docType": "org.iso.18013.5.1.mDL",
    "validityInfo": {
        "signed": now(),
        "validFrom": now(),
        "validUntil": now() + one_year
    }
}

# Sign MSO → issuerAuth (COSE_Sign1)
issuer_auth = cose_sign1(mso, document_signer_private_key, ds_certificate)

# STEP 7: Package final mdoc
mdoc = {
    "docType": "org.iso.18013.5.1.mDL",
    "issuerSigned": {
        "nameSpaces": {"org.iso.18013.5.1": items},
        "issuerAuth": issuer_auth
    }
}

# Send to holder
send_to_device(mdoc)
```

### Key Insight: The Hash is the Magic

The entire security model relies on this relationship:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                                                                  │
│   AT ISSUANCE:                         AT VERIFICATION:                          │
│                                                                                  │
│   IssuerSignedItemBytes                IssuerSignedItemBytes                     │
│   (sent to holder)                     (holder sends to verifier)                │
│          │                                      │                                │
│          │ SHA-256                              │ SHA-256                        │
│          ▼                                      ▼                                │
│   ┌──────────────┐                      ┌──────────────┐                        │
│   │    Hash      │──── stored in ────►  │    Hash      │                        │
│   └──────────────┘      MSO             └──────┬───────┘                        │
│                                                │                                │
│                                                │ compare                        │
│                                                ▼                                │
│                                         ┌──────────────┐                        │
│                                         │ Hash from MSO│                        │
│                                         └──────────────┘                        │
│                                                                                  │
│   If hashes match → data is authentic and hasn't been tampered with            │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## Document Type (docType)

Every mdoc has a **docType** that identifies what kind of document it is.

### Format

```
docType = tstr  (text string)
```

### For mDL

```
"org.iso.18013.5.1.mDL"
```

This follows a reverse-domain naming convention:
- `org.iso` - Organization (ISO)
- `18013.5.1` - Standard number and version
- `mDL` - Document type

### Why It Matters

The docType tells the reader:
1. What kind of document this is
2. What data elements to expect
3. Which namespaces are valid
4. How to interpret the data

---

## Namespaces

Namespaces organize data elements into logical groups. Think of them as "folders" for your data.

### Structure

```
nameSpaces = {
    + NameSpace => [ + IssuerSignedItemBytes ]
}

NameSpace = tstr  (text string)
```

### Standard mDL Namespace

```
"org.iso.18013.5.1"
```

This namespace contains all the standard mDL data elements like name, birth date, portrait, driving privileges, etc.

### Domestic/Regional Namespace

Countries can define their own namespaces for additional data:

```
"org.iso.18013.5.1.US"     // United States extensions
"org.iso.18013.5.1.DE"     // Germany extensions
"org.iso.18013.5.1.aamva"  // AAMVA (American Association of Motor Vehicle Administrators)
```

### Visual Example

```
┌─────────────────────────────────────────────────────────────────────┐
│                          nameSpaces                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  "org.iso.18013.5.1" ─────────────────────────────────────────────┐ │
│  │                                                                │ │
│  │  family_name: "Doe"                                           │ │
│  │  given_name: "Jane"                                           │ │
│  │  birth_date: "1990-01-15"                                     │ │
│  │  portrait: <binary image data>                                │ │
│  │  document_number: "D123456789"                                │ │
│  │  driving_privileges: [...]                                    │ │
│  │  issue_date: "2023-01-01"                                     │ │
│  │  expiry_date: "2028-01-01"                                    │ │
│  │  issuing_country: "US"                                        │ │
│  │  issuing_authority: "California DMV"                          │ │
│  │  age_over_21: true                                            │ │
│  │  ...                                                          │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  "org.iso.18013.5.1.US" ──────────────────────────────────────────┐ │
│  │                                                                │ │
│  │  domestic_driving_privileges: [...]                           │ │
│  │  domestic_vehicle_restrictions: "Corrective Lenses"           │ │
│  │  ...                                                          │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Data Elements

### IssuerSignedItem Structure

Each data element is wrapped in an **IssuerSignedItem** structure:

```
IssuerSignedItem = {
    "digestID"            : uint,           // Unique ID for this element
    "random"              : bstr,           // Random bytes (at least 16)
    "elementIdentifier"   : DataElementIdentifier,  // Field name
    "elementValue"        : DataElementValue        // Field value
}
```

### Why Each Field Exists

| Field | Purpose |
|-------|---------|
| `digestID` | Links this item to its hash in the MSO |
| `random` | Prevents brute-force guessing of values |
| `elementIdentifier` | The name of the data field |
| `elementValue` | The actual value |

### Example: Family Name

```
CBOR Diagnostic Notation:
{
    "digestID": 0,
    "random": h'8798645B20EA200E19FFABAC92624BEE6AEC63ACEEDECFB1B80077D22BFC20E9',
    "elementIdentifier": "family_name",
    "elementValue": "Doe"
}
```

### Why Random Bytes?

The random bytes prevent a "dictionary attack". Without them, an attacker could:
1. Guess common values (like common names)
2. Hash them
3. Compare against the MSO digests

With 16+ random bytes, this becomes computationally infeasible.

### Data Types

| Type | CBOR | Example |
|------|------|---------|
| Text | tstr | "Doe" |
| Number | uint/int | 42 |
| Boolean | bool | true |
| Date | tdate (tag 1004) | 1004("2023-01-15") |
| Full date-time | tdate (tag 0) | 0("2023-01-15T10:30:00Z") |
| Binary | bstr | h'FFD8FFE0...' (JPEG image) |
| Array | array | [item1, item2, ...] |
| Map | map | {key: value, ...} |

### Driving Privileges Example

Complex data elements like driving privileges are arrays of maps:

```
CBOR Diagnostic Notation:
[
    {
        "vehicle_category_code": "A",
        "issue_date": 1004("2018-08-09"),
        "expiry_date": 1004("2024-10-20")
    },
    {
        "vehicle_category_code": "B",
        "issue_date": 1004("2017-02-23"),
        "expiry_date": 1004("2024-10-20")
    }
]
```

This represents:
- Category A (motorcycles) - issued Aug 2018, expires Oct 2024
- Category B (cars) - issued Feb 2017, expires Oct 2024

---

## IssuerSigned Structure

The **issuerSigned** portion contains:
1. All the data elements (in nameSpaces)
2. The issuer's signature over a Mobile Security Object (in issuerAuth)

```
IssuerSigned = {
    "nameSpaces" : IssuerNameSpaces,    // The actual data
    "issuerAuth" : IssuerAuth           // Signature + MSO
}
```

### IssuerNameSpaces

```
IssuerNameSpaces = {
    + NameSpace => [ + IssuerSignedItemBytes ]
}
```

Each namespace contains an array of **tagged CBOR byte strings** (`IssuerSignedItemBytes`). The tagging is important - each item is encoded as CBOR, then wrapped in a byte string with tag 24.

```
IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
```

### Why Tag 24?

Tag 24 means "this byte string contains CBOR data". This:
1. Preserves the exact bytes for hash verification
2. Allows selective disclosure (send only the items you want)
3. Prevents malleability attacks

### Visual Representation

```
issuerSigned
├── nameSpaces
│   ├── "org.iso.18013.5.1"
│   │   ├── 24(<<{digestID: 0, random: ..., elementIdentifier: "family_name", elementValue: "Doe"}>>)
│   │   ├── 24(<<{digestID: 1, random: ..., elementIdentifier: "given_name", elementValue: "Jane"}>>)
│   │   ├── 24(<<{digestID: 2, random: ..., elementIdentifier: "birth_date", elementValue: 1004("1990-01-15")}>>)
│   │   └── ... more items
│   │
│   └── "org.iso.18013.5.1.US"
│       ├── 24(<<{digestID: 0, random: ..., elementIdentifier: "...", elementValue: ...}>>)
│       └── ... more items
│
└── issuerAuth (COSE_Sign1)
    ├── protected: {1: -7}           // Algorithm: ES256
    ├── unprotected: {33: <cert>}    // x5chain with DS certificate
    ├── payload: MSO
    └── signature: <bytes>
```

---

## Mobile Security Object (MSO)

The **MSO** is the heart of the security model. It contains hashes of all data elements, allowing selective disclosure while maintaining authenticity.

### Structure

```
MobileSecurityObject = {
    "version"           : tstr,              // "1.0"
    "digestAlgorithm"   : tstr,              // "SHA-256", "SHA-384", or "SHA-512"
    "valueDigests"      : ValueDigests,      // Hashes of all data elements
    "deviceKeyInfo"     : DeviceKeyInfo,     // Public key of the device
    "docType"           : DocType,           // "org.iso.18013.5.1.mDL"
    "validityInfo"      : ValidityInfo       // When this MSO is valid
}
```

### ValueDigests - The Hash Map

```
ValueDigests = {
    + NameSpace => DigestIDs
}

DigestIDs = {
    + DigestID => Digest
}

DigestID = uint
Digest = bstr    // Hash output (32 bytes for SHA-256)
```

### How Selective Disclosure Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      How Hashing Enables Selective Disclosure                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ISSUER SIDE (at issuance time):                                          │
│   ────────────────────────────────                                          │
│                                                                             │
│   IssuerSignedItem                    SHA-256                               │
│   ┌──────────────────────┐            ┌──────┐                             │
│   │ digestID: 0          │            │      │                             │
│   │ random: <32 bytes>   │ ─────────► │ HASH │ ─► 0x7516...CEBF            │
│   │ elementId: family_name│           │      │                             │
│   │ elementValue: "Doe"  │            └──────┘                             │
│   └──────────────────────┘                          │                      │
│                                                     │                      │
│   This hash goes into MSO.valueDigests["org.iso.18013.5.1"][0]             │
│                                                                             │
│   ═══════════════════════════════════════════════════════════════════      │
│                                                                             │
│   HOLDER SIDE (at presentation time):                                      │
│   ───────────────────────────────────                                      │
│                                                                             │
│   Option A: SHARE the data element                                         │
│   ┌──────────────────────┐                                                 │
│   │ Send IssuerSignedItem│  ──► Verifier hashes it, compares to MSO       │
│   └──────────────────────┘                                                 │
│                                                                             │
│   Option B: DON'T SHARE the data element                                   │
│   ┌──────────────────────┐                                                 │
│   │ Don't send item      │  ──► Verifier only sees the hash, can't reverse│
│   └──────────────────────┘                                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### MSO Example (Diagnostic Notation)

```
{
    "version": "1.0",
    "digestAlgorithm": "SHA-256",
    "valueDigests": {
        "org.iso.18013.5.1": {
            0: h'75167333B47B6C2BFB86ECCC1F438CF57AF055371AC55E1E359E20F254ADCEBF',
            1: h'67E539D6139EBD131AEF441B445645DD831B2B375B390CA5EF6279B205ED4571',
            2: h'3394372DDB78053F36D5D869780E61EDA313D44A392092AD8E0527A2FBFE55AE',
            3: h'2E35AD3C4E514BB67B1A9DB51CE74E4CB9B7146E41AC52DAC9CE86B8613DB555',
            // ... more digests
        },
        "org.iso.18013.5.1.US": {
            0: h'D80B83D25173C484C5640610FF1A31C949C1D934BF4CF7F18D5223B15DD4F21C',
            1: h'4D80E1E2E4FB246D97895427CE7000BB59BB24C8CD003ECF94BF35BBD2917E34',
            // ... more digests
        }
    },
    "deviceKeyInfo": {
        "deviceKey": {
            1: 2,       // kty: EC
            -1: 1,      // crv: P-256
            -2: h'96313D6C63E24E3372742BFDB1A33BA2C897DCD68AB8C753E4FBD48DCA6B7F9A',  // x
            -3: h'1FB3269EDD418857DE1B39A4E4A44B92FA484CAA722C228288F01D0C03A2C3D6'   // y
        }
    },
    "docType": "org.iso.18013.5.1.mDL",
    "validityInfo": {
        "signed": 0("2020-10-01T13:30:02Z"),
        "validFrom": 0("2020-10-01T13:30:02Z"),
        "validUntil": 0("2021-10-01T13:30:02Z")
    }
}
```

### DeviceKeyInfo

The device key binds the credential to a specific device. **The holder's device generates this key pair** - the issuer only receives the public key to embed in the MSO.

> **ISO 18013-5 Reference (Section 9.1.2.4):**  
> *"deviceKey contains the **public part** of the key pair used for mdoc authentication"*
>
> **Section 9.1.3.3:**  
> *"The **mdoc private key**, which belongs to the mdoc public key stored in the MSO, is used to authenticate the mdoc."*

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                WHO GENERATES THE DEVICE KEY?                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   HOLDER'S DEVICE (generates)              ISSUER (receives public only)        │
│   ───────────────────────────              ─────────────────────────────        │
│                                                                                 │
│   ┌─────────────────────────┐              ┌─────────────────────────┐         │
│   │ SDeviceKey.Priv         │              │                         │         │
│   │ (PRIVATE - never leaves │   ────X────  │  Issuer NEVER gets this │         │
│   │  the device!)           │              │                         │         │
│   └─────────────────────────┘              └─────────────────────────┘         │
│                                                                                 │
│   ┌─────────────────────────┐              ┌─────────────────────────┐         │
│   │ SDeviceKey.Pub          │              │                         │         │
│   │ (PUBLIC - sent to       │   ────────►  │  Embedded in MSO as     │         │
│   │  issuer during          │              │  deviceKeyInfo.deviceKey│         │
│   │  provisioning)          │              │                         │         │
│   └─────────────────────────┘              └─────────────────────────┘         │
│                                                                                 │
│   WHY THIS MATTERS:                                                            │
│   • Prevents cloning - even if someone copies the mdoc, they can't copy        │
│     the private key stored securely on the device                              │
│   • Enables holder authentication - at presentation, the device proves         │
│     it holds the private key by computing a MAC or signature                   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

```
DeviceKeyInfo = {
    "deviceKey" : DeviceKey,              // COSE_Key (PUBLIC key only!)
    ? "keyAuthorizations" : KeyAuthorizations,  // Optional: restrictions
    ? "keyInfo" : KeyInfo                 // Optional: additional info
}
```

### ValidityInfo

```
ValidityInfo = {
    "signed"       : tdate,     // When the MSO was signed
    "validFrom"    : tdate,     // Start of validity period
    "validUntil"   : tdate,     // End of validity period
    ? "expectedUpdate" : tdate  // When to check for updates
}
```

### IssuerAuth (COSE_Sign1)

The MSO doesn't travel alone—it's wrapped in a **COSE_Sign1** structure called `issuerAuth`. This is what actually contains the digital signature from the issuing authority.

#### COSE_Sign1 Structure

```
COSE_Sign1 = [
    protected,      // bstr-wrapped CBOR header (algorithm)
    unprotected,    // plain CBOR map (certificate chain)
    payload,        // bstr (contains the MSO)
    signature       // bstr (the digital signature)
]
```

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        issuerAuth (COSE_Sign1)                               │
├─────────────────────────────────────────────────────────────────────────────┤
│  Index 0: protected                                                          │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  << {1: -7} >>                                                          │ │
│  │  ↑                                                                      │ │
│  │  CBOR-encoded map wrapped as byte string                               │ │
│  │  {1: -7} means "algorithm: ES256" (ECDSA with P-256 and SHA-256)       │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  Index 1: unprotected                                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  {33: h'308201EF...'}                                                   │ │
│  │  ↑                                                                      │ │
│  │  Plain map (NOT byte-wrapped)                                          │ │
│  │  {33: ...} is the x5chain (X.509 certificate chain)                    │ │
│  │  Contains the Document Signer certificate that chains to IACA root     │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  Index 2: payload                                                            │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  << 24(<< {MSO} >>) >>                                                  │ │
│  │     ↑     ↑                                                             │ │
│  │     │     └── Inner: MSO is defined as Tag 24 wrapped (MSO spec)       │ │
│  │     └──────── Outer: COSE requires payload as bstr                     │ │
│  │                                                                         │ │
│  │  The MSO itself is "MobileSecurityObjectBytes" = Tag 24 encoded       │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  Index 3: signature                                                          │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  h'59E64205DF1E2F708DD6DB0847AED79FC7...'                               │ │
│  │  ↑                                                                      │ │
│  │  64-byte ECDSA signature (for ES256)                                   │ │
│  │  Signs the Sig_structure, NOT just the payload                         │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Understanding `<< >>` in Diagnostic Notation

The `<< >>` notation means "CBOR-encode this and wrap as a byte string":

```
<< {1: -7} >>

Step 1: {1: -7}           →  Map with one entry (alg = ES256)
Step 2: CBOR encode       →  A1 01 26 (3 bytes)  
Step 3: Wrap as bstr      →  43 A1 01 26 (length-prefixed byte string)
```

#### The Double Wrapping Explained

Why does the payload have `<< 24(<< ... >>) >>`? Two separate requirements:

| Layer | Notation | Reason |
|-------|----------|--------|
| Inner | `24(<< MSO >>)` | MSO spec defines `MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)` |
| Outer | `<< ... >>` | COSE_Sign1 requires the payload field to be a byte string |

#### What Gets Signed?

The signature is NOT computed over just the payload. COSE defines a **Sig_structure**:

```
Sig_structure = [
    context      : "Signature1",     // Fixed string for COSE_Sign1
    protected    : bstr,             // The protected header bytes
    external_aad : bstr,             // External additional data (usually empty)
    payload      : bstr              // The payload bytes (MSO)
]
```

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         What Gets Signed                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Sig_structure = [                                                          │
│       "Signature1",          ← Always this string for COSE_Sign1            │
│       h'A10126',             ← Protected header bytes: {1: -7}              │
│       h'',                   ← External AAD (empty)                         │
│       h'D818...MSO...'       ← MobileSecurityObjectBytes                    │
│   ]                                                                          │
│                                                                              │
│          │                                                                   │
│          ▼                                                                   │
│   ┌─────────────┐                                                           │
│   │ CBOR encode │                                                           │
│   └──────┬──────┘                                                           │
│          │                                                                   │
│          ▼                                                                   │
│   ┌─────────────┐                                                           │
│   │   SHA-256   │  (because ES256 = ECDSA with SHA-256)                     │
│   └──────┬──────┘                                                           │
│          │                                                                   │
│          ▼                                                                   │
│   ┌─────────────┐                                                           │
│   │ ECDSA Sign  │  with Document Signer's private key                       │
│   └──────┬──────┘                                                           │
│          │                                                                   │
│          ▼                                                                   │
│   signature = h'59E64205DF1E2F...' (64 bytes for P-256)                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### IssuerAuth in Code (Pseudocode)

```python
# Building issuerAuth (COSE_Sign1)

# 1. Create protected header
protected_header = {1: -7}  # alg: ES256
protected_bytes = cbor_encode(protected_header)

# 2. Create unprotected header with certificate chain
unprotected_header = {
    33: load_certificate("document_signer.crt")  # x5chain
}

# 3. Create MSO and wrap as MobileSecurityObjectBytes
mso = {
    "version": "1.0",
    "digestAlgorithm": "SHA-256",
    "valueDigests": { ... all hashes ... },
    "deviceKeyInfo": { ... },
    "docType": "org.iso.18013.5.1.mDL",
    "validityInfo": { ... }
}
mso_bytes = cbor_encode(mso)
mso_tagged = CBORTag(24, mso_bytes)    # Wrap in Tag 24
payload = cbor_encode(mso_tagged)       # This is the payload bstr

# 4. Build Sig_structure
sig_structure = [
    "Signature1",      # context
    protected_bytes,   # protected
    b'',               # external_aad (empty)
    payload            # payload
]
sig_structure_bytes = cbor_encode(sig_structure)

# 5. Sign
signature = ecdsa_sign(
    private_key=document_signer_private_key,
    data=sig_structure_bytes
)

# 6. Assemble COSE_Sign1
issuer_auth = [
    protected_bytes,     # Index 0
    unprotected_header,  # Index 1
    payload,             # Index 2
    signature            # Index 3
]
```

#### COSE Header Parameters

| Label | Name | Example Value | Meaning |
|-------|------|---------------|---------|
| 1 | alg | -7 | ES256 (ECDSA w/ SHA-256 on P-256) |
| 1 | alg | -35 | ES384 (ECDSA w/ SHA-384 on P-384) |
| 1 | alg | -36 | ES512 (ECDSA w/ SHA-512 on P-521) |
| 33 | x5chain | bstr | X.509 certificate chain |
| 4 | kid | bstr | Key identifier |

#### Tag 0 for DateTime in ValidityInfo

Notice the dates use **Tag 0**, not Tag 1004:

```
"validityInfo": {
    "signed": 0("2020-10-01T13:30:02Z"),      // Tag 0 = full datetime
    "validFrom": 0("2020-10-01T13:30:02Z"),
    "validUntil": 0("2021-10-01T13:30:02Z")
}
```

| Tag | Name | Format | Used For |
|-----|------|--------|----------|
| 0 | tdate (datetime) | Full RFC 3339 | ValidityInfo timestamps |
| 1004 | tdate (date-only) | YYYY-MM-DD | Data elements like birth_date |

---

## DeviceSigned Structure

The **deviceSigned** portion proves that the current device/user authorized this presentation.

```
DeviceSigned = {
    "nameSpaces"   : DeviceNameSpacesBytes,   // Usually empty
    "deviceAuth"   : DeviceAuth               // Device authentication
}
```

### DeviceAuth Options

The device can authenticate using either:

**Option 1: MAC (Message Authentication Code)**
```
DeviceAuth = {
    "deviceMac" : DeviceMac   // COSE_Mac0
}
```

**Option 2: Signature**
```
DeviceAuth = {
    "deviceSignature" : DeviceSignature   // COSE_Sign1
}
```

### DeviceMac Structure

```
DeviceMac = COSE_Mac0 (untagged)

COSE_Mac0 = [
    protected   : bstr,      // Algorithm header
    unprotected : map,       // Usually empty
    payload     : nil,       // Always null (external data)
    tag         : bstr       // The MAC value
]
```

### Example DeviceAuth (MAC)

```
{
    "deviceMac": [
        << {1: 5} >>,           // Algorithm: HMAC-256
        {},                      // Empty unprotected header
        null,                    // Payload is external
        h'E99521A85AD7891B806A07F8B5388A332D92C189A7BF293EE1F543405AE6824D'
    ]
}
```

### Why Device Authentication?

Device authentication proves:
1. **Freshness** - This presentation was created just now
2. **Holder binding** - The device holding the credential authorized this
3. **Session binding** - Ties to the specific reader/session

---

## CBOR Encoding

mdocs use **CBOR (Concise Binary Object Representation)** for encoding. Here's a quick primer.

### CBOR Basics

| Type | Encoding |
|------|----------|
| Unsigned int | 0x00-0x1B + value |
| Negative int | 0x20-0x3B + value |
| Byte string | 0x40-0x5B + length + bytes |
| Text string | 0x60-0x7B + length + UTF-8 |
| Array | 0x80-0x9B + count + items |
| Map | 0xA0-0xBB + count + key-value pairs |
| Tag | 0xC0-0xDB + tag number + item |
| Simple | 0xE0-0xF7 (false=0xF4, true=0xF5, null=0xF6) |

### Important Tags

| Tag | Meaning | Usage |
|-----|---------|-------|
| 0 | Date-time string | Timestamps |
| 1004 | Date (no time) | Birth dates, issue dates |
| 24 | Encoded CBOR | IssuerSignedItemBytes |
| 18 | COSE_Sign1 | Signatures |
| 17 | COSE_Mac0 | MACs |

### Encoding Example

```
Text: "Doe"

Step 1: UTF-8 bytes = 0x44 0x6F 0x65 (3 bytes)
Step 2: CBOR text string header for length 3 = 0x63
Step 3: Final CBOR = 0x63 0x44 0x6F 0x65

Hex: 6344 6f65
```

### IssuerSignedItem Encoding

```
Item in diagnostic notation:
{
    "digestID": 0,
    "random": h'8798645B...',
    "elementIdentifier": "family_name",
    "elementValue": "Doe"
}

CBOR hex:
a4                        // Map with 4 items
  68 64696765737449 44    // "digestID" (text, 8 chars)
  00                      // 0 (unsigned int)
  66 72616e646f6d        // "random" (text, 6 chars)
  5820 8798645b...       // Byte string, 32 bytes
  71 656c656d656e744964656e746966696572  // "elementIdentifier" (text, 17 chars)
  6b 66616d696c795f6e616d65             // "family_name" (text, 11 chars)
  6c 656c656d656e7456616c7565           // "elementValue" (text, 12 chars)
  63 446f65                              // "Doe" (text, 3 chars)
```

---

## Understanding CBOR Diagnostic Notation

Throughout this document, you'll see structures written like this:

```
24(<<{
    "digestID": 2,
    "random": h'B3C5D7E9...',
    "elementIdentifier": "birth_date",
    "elementValue": 1004("1990-01-15")
}>>)
```

**This is NOT code!** It's called **CBOR Diagnostic Notation** - a human-readable way to represent binary CBOR data in documentation.

### Notation Decoder Ring

| You See | It Means | In Code You Do |
|---------|----------|----------------|
| `24(...)` | CBOR Tag 24 (embedded CBOR) | Create a tag object: `CBORTag(24, data)` |
| `<<...>>` | Byte string containing CBOR | Encode inner content to bytes first |
| `{...}` | A CBOR map | Create a dictionary/map object |
| `1004("date")` | Tag 1004 wrapping a date string | `CBORTag(1004, "1990-01-15")` |
| `0("datetime")` | Tag 0 wrapping a datetime | `CBORTag(0, "2020-10-01T13:30:02Z")` |
| `h'ABCD...'` | Hexadecimal bytes | `bytes.fromhex("ABCD...")` |
| `"text"` | A text string | Just a string: `"text"` |

### How to ACTUALLY Build an IssuerSignedItem

Here's what you do in code (step by step):

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  DOCUMENTATION shows:                                                        │
│                                                                             │
│     24(<<{                                                                  │
│         "digestID": 2,                                                      │
│         "random": h'B3C5D7E9...',                                          │
│         "elementIdentifier": "birth_date",                                  │
│         "elementValue": 1004("1990-01-15")                                 │
│     }>>)                                                                    │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  In CODE you do:                                                            │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ STEP 1: Build the map (with Tag 1004 for the date)                 │    │
│  │                                                                     │    │
│  │   item = {                                                          │    │
│  │       "digestID": 2,                                                │    │
│  │       "random": <32 random bytes>,                                  │    │
│  │       "elementIdentifier": "birth_date",                            │    │
│  │       "elementValue": CBORTag(1004, "1990-01-15")  ◄── Tag for date│    │
│  │   }                                                                 │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                              │                                              │
│                              ▼                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ STEP 2: Encode the map to CBOR bytes                               │    │
│  │                                                                     │    │
│  │   item_bytes = cbor_encode(item)                                    │    │
│  │                                                                     │    │
│  │   Result: a4 68 64 69 67 65 73 74 49 44 02 ...  (binary bytes)     │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                              │                                              │
│                              ▼                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ STEP 3: Wrap those bytes in Tag 24                                 │    │
│  │                                                                     │    │
│  │   tagged = CBORTag(24, item_bytes)  ◄── This is IssuerSignedItemBytes   │
│  │   final_bytes = cbor_encode(tagged)                                 │    │
│  │                                                                     │    │
│  │   Result: d8 18 58 xx a4 68 64 69 ...                              │    │
│  │           ─────                                                     │    │
│  │             └── d8 18 = Tag 24 in CBOR encoding                    │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                              │                                              │
│                              ▼                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ STEP 4: Hash the final bytes (for the MSO)                         │    │
│  │                                                                     │    │
│  │   hash = SHA256(final_bytes)                                        │    │
│  │                                                                     │    │
│  │   This hash goes into MSO.valueDigests[namespace][digestID]        │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Code Example (Python-like Pseudocode)

```python
from cbor2 import dumps, CBORTag
import hashlib

# STEP 1: Build the map with tagged date
item = {
    "digestID": 2,
    "random": bytes.fromhex("B3C5D7E9F1A2345678901BCDEF2345678901BCDEF2345678901BCDEF234567"),
    "elementIdentifier": "birth_date",
    "elementValue": CBORTag(1004, "1990-01-15")  # Tag 1004 = date-only
}

# STEP 2: Encode map to CBOR bytes
item_bytes = dumps(item)

# STEP 3: Wrap in Tag 24 → IssuerSignedItemBytes
issuer_signed_item_bytes = dumps(CBORTag(24, item_bytes))

# STEP 4: Hash for MSO
digest = hashlib.sha256(issuer_signed_item_bytes).digest()
# This digest goes into MSO.valueDigests["org.iso.18013.5.1"][2]
```

### What Gets Hashed?

**The ENTIRE IssuerSignedItemBytes** (including Tag 24) is hashed - not just the value!

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         What Gets Hashed                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   IssuerSignedItemBytes (the complete tagged structure)                     │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  d8 18          ← Tag 24 header                                     │  │
│   │  58 xx          ← Byte string header (length)                       │  │
│   │  a4             ← Map with 4 items                                  │  │
│   │    "digestID": 2                                                    │  │
│   │    "random": <32 bytes>          ← Prevents brute-force guessing   │  │
│   │    "elementIdentifier": "birth_date"                                │  │
│   │    "elementValue": Tag(1004, "1990-01-15")                         │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                              │                                              │
│                              ▼                                              │
│                          SHA-256                                            │
│                              │                                              │
│                              ▼                                              │
│                    h'3394372DDB78053F...'  (32-byte hash)                  │
│                                                                             │
│   This hash is stored in: MSO.valueDigests["org.iso.18013.5.1"][2]         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why Hash Everything?

| Part of Item | Why It's Hashed |
|--------------|-----------------|
| **Tag 24** | Ensures byte-for-byte integrity |
| **digestID** | Links this item to its hash in MSO |
| **random** | Prevents guessing values (can't just hash "1990-01-15" and compare) |
| **elementIdentifier** | Prevents swapping values between fields |
| **elementValue** | The actual data being protected |

### Common Tag Encodings

| Tag Number | CBOR Bytes | Diagnostic Notation | Meaning |
|------------|------------|---------------------|---------|
| 0 | `c0` | `0("datetime")` | RFC 3339 datetime |
| 24 | `d8 18` | `24(<<...>>)` | Embedded CBOR |
| 1004 | `d9 03 ec` | `1004("date")` | Date only (no time) |

---

## Device Engagement

Before data exchange, the device and reader must establish a connection. This happens through **Device Engagement**.

### Device Engagement Structure

```
DeviceEngagement = {
    0 : tstr,                    // Version ("1.0")
    1 : Security,                // Device's ephemeral key
    2 : DeviceRetrievalMethods,  // How to get data (BLE, NFC, etc.)
    ? 3 : ServerRetrievalMethods,// Optional: server retrieval info
    ? 4 : ProtocolInfo           // Optional: protocol-specific data
}
```

### Security Element

Contains the device's ephemeral public key for session encryption:

```
Security = [
    1,                     // Cipher suite identifier
    EDeviceKeyBytes        // Device's ephemeral public key (COSE_Key)
]
```

### Device Retrieval Methods

Specifies how the reader should connect:

```
DeviceRetrievalMethods = [
    * DeviceRetrievalMethod
]

DeviceRetrievalMethod = [
    type : uint,           // 1=NFC, 2=BLE, 3=Wi-Fi Aware
    version : uint,        // Protocol version
    options : any          // Protocol-specific options
]
```

### Example Device Engagement

```
{
    0: "1.0",
    1: [
        1,
        24(<<
            {
                1: 2,        // kty: EC
                -1: 1,       // crv: P-256
                -2: h'5A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA444B624343167FE',
                -3: h'B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67'
            }
        >>)
    ],
    2: [
        [
            2,             // BLE
            1,             // Version 1
            {
                0: false,  // Peripheral server mode: false (central client mode)
                1: true,   // Central client mode: true
                11: h'45EFEF742B2C4837A9A3B0E1D05A6917'  // BLE UUID
            }
        ]
    ]
}
```

### QR Code Encoding

For QR-based engagement, the Device Engagement is encoded as:

```
"mdoc:" + base64url(CBOR(DeviceEngagement))
```

---

## Request and Response

### mdoc Request

When a reader wants data, it sends an **mdoc request**:

```
DeviceRequest = {
    "version"     : tstr,           // "1.0"
    "docRequests" : [ * DocRequest ]
}

DocRequest = {
    "itemsRequest" : ItemsRequestBytes,
    ? "readerAuth" : ReaderAuth     // Optional reader authentication
}
```

### ItemsRequest

```
ItemsRequest = {
    "docType"    : DocType,
    "nameSpaces" : NameSpaces,       // What data is requested
    ? "requestInfo" : RequestInfo    // Optional: why it's needed
}

NameSpaces = {
    + NameSpace => DataElements
}

DataElements = {
    + DataElementIdentifier => IntentToRetain
}
```

### Example Request

```
{
    "version": "1.0",
    "docRequests": [
        {
            "itemsRequest": 24(<<
                {
                    "docType": "org.iso.18013.5.1.mDL",
                    "nameSpaces": {
                        "org.iso.18013.5.1": {
                            "family_name": true,      // Want it, will retain
                            "document_number": true,
                            "driving_privileges": true,
                            "issue_date": true,
                            "expiry_date": true,
                            "portrait": false         // Want it, won't retain
                        }
                    }
                }
            >>)
        }
    ]
}
```

### mdoc Response

```
DeviceResponse = {
    "version"   : tstr,              // "1.0"
    "documents" : [ * Document ],    // The actual documents
    ? "documentErrors" : [ * DocumentError ],
    "status"    : uint               // 0 = OK
}

Document = {
    "docType"      : DocType,
    "issuerSigned" : IssuerSigned,
    "deviceSigned" : DeviceSigned,
    ? "errors"     : Errors
}
```

### Status Codes

| Code | Meaning |
|------|---------|
| 0 | OK |
| 10 | General error |
| 11 | CBOR decoding error |
| 12 | CBOR validation error |

---

## Complete mdoc Example

Let's trace through a complete example with real CBOR data.

### The Scenario

**Jane Doe** applies for a mobile driving licence at the California DMV. After identity verification, the DMV issues her a complete mDL. Later, she presents it at a bar to prove she's over 21.

We'll show both:
1. **The full issued mdoc** (what Jane receives from DMV)
2. **The presentation response** (what Jane shares at the bar)

---

### Part 1: Full Issued mdoc Structure

This is the complete mdoc as issued by the DMV and stored on Jane's device. It contains **ALL** her data elements.

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                    COMPLETE ISSUED mDL (stored on device)                       │
├────────────────────────────────────────────────────────────────────────────────┤
│  docType: "org.iso.18013.5.1.mDL"                                              │
│                                                                                │
│  issuerSigned:                                                                 │
│  ├── nameSpaces:                                                               │
│  │   ├── "org.iso.18013.5.1": [ALL 13+ standard data elements]                │
│  │   └── "org.iso.18013.5.1.US": [4 US-specific elements]                     │
│  │                                                                             │
│  └── issuerAuth: COSE_Sign1 (MSO + signature)                                 │
│                                                                                │
│  (deviceSigned is created at presentation time, not at issuance)              │
└────────────────────────────────────────────────────────────────────────────────┘
```

#### Complete IssuerSigned Structure (at issuance)

```
{
    "nameSpaces": {
        "org.iso.18013.5.1": [
            // ═══════════════════════════════════════════════════════════════
            // MANDATORY DATA ELEMENTS (must be present)
            // ═══════════════════════════════════════════════════════════════
            
            24(<<{
                "digestID": 0,
                "random": h'8798645B20EA200E19FFABAC92624BEE6AEC63ACEEDECFB1B80077D22BFC20E9',
                "elementIdentifier": "family_name",
                "elementValue": "Doe"
            }>>),
            
            24(<<{
                "digestID": 1,
                "random": h'A2B4C6D8E0F1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF12345',
                "elementIdentifier": "given_name",
                "elementValue": "Jane"
            }>>),
            
            24(<<{
                "digestID": 2,
                "random": h'B3C5D7E9F1A2345678901BCDEF2345678901BCDEF2345678901BCDEF234567',
                "elementIdentifier": "birth_date",
                "elementValue": 1004("1990-01-15")    // tdate tag 1004 for date-only
            }>>),
            
            24(<<{
                "digestID": 3,
                "random": h'B23F627E8999C706DF0C0A4ED98AD74AF988AF619B4BB078B89058553F44615D',
                "elementIdentifier": "issue_date",
                "elementValue": 1004("2019-10-20")
            }>>),
            
            24(<<{
                "digestID": 4,
                "random": h'C7FFA307E5DE921E67BA5878094787E8807AC8E7B5B3932D2CE80F00F3E9ABAF',
                "elementIdentifier": "expiry_date",
                "elementValue": 1004("2024-10-20")
            }>>),
            
            24(<<{
                "digestID": 5,
                "random": h'D4E6F8A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8',
                "elementIdentifier": "issuing_country",
                "elementValue": "US"
            }>>),
            
            24(<<{
                "digestID": 6,
                "random": h'E5F7A9B1C3D5E7F9A1B3C5D7E9F1A3B5C7D9E1F3A5B7C9D1E3F5A7B9C1D3E5F7',
                "elementIdentifier": "issuing_authority",
                "elementValue": "California DMV"
            }>>),
            
            24(<<{
                "digestID": 7,
                "random": h'26052A42E5880557A806C1459AF3FB7EB505D3781566329D0B604B845B5F9E68',
                "elementIdentifier": "document_number",
                "elementValue": "D1234567"
            }>>),
            
            24(<<{
                "digestID": 8,
                "random": h'D094DAD764A2EB9DEB5210E9D899643EFBD1D069CC311D3295516CA0B024412D',
                "elementIdentifier": "portrait",
                "elementValue": h'FFD8FFE000104A464946...'  // JPEG image bytes (truncated)
            }>>),
            
            24(<<{
                "digestID": 9,
                "random": h'4599F81BEAA2B20BD0FFCC9AA03A6F985BEFAB3F6BEAFFA41E6354CDB2AB2CE4',
                "elementIdentifier": "driving_privileges",
                "elementValue": [
                    {
                        "vehicle_category_code": "A",
                        "issue_date": 1004("2018-08-09"),
                        "expiry_date": 1004("2024-10-20")
                    },
                    {
                        "vehicle_category_code": "B",
                        "issue_date": 1004("2017-02-23"),
                        "expiry_date": 1004("2024-10-20")
                    }
                ]
            }>>),
            
            24(<<{
                "digestID": 10,
                "random": h'F6A8B0C2D4E6F8A0B2C4D6E8F0A2B4C6D8E0F2A4B6C8D0E2F4A6B8C0D2E4F6A8',
                "elementIdentifier": "un_distinguishing_sign",
                "elementValue": "USA"
            }>>),
            
            // ═══════════════════════════════════════════════════════════════
            // OPTIONAL DATA ELEMENTS (may be present)
            // ═══════════════════════════════════════════════════════════════
            
            24(<<{
                "digestID": 11,
                "random": h'A7B9C1D3E5F7A9B1C3D5E7F9A1B3C5D7E9F1A3B5C7D9E1F3A5B7C9D1E3F5A7B9',
                "elementIdentifier": "sex",
                "elementValue": 2    // 1=male, 2=female
            }>>),
            
            24(<<{
                "digestID": 12,
                "random": h'B8C0D2E4F6A8B0C2D4E6F8A0B2C4D6E8F0A2B4C6D8E0F2A4B6C8D0E2F4A6B8C0',
                "elementIdentifier": "height",
                "elementValue": 165    // in centimeters
            }>>),
            
            24(<<{
                "digestID": 13,
                "random": h'C9D1E3F5A7B9C1D3E5F7A9B1C3D5E7F9A1B3C5D7E9F1A3B5C7D9E1F3A5B7C9D1',
                "elementIdentifier": "weight",
                "elementValue": 60    // in kilograms
            }>>),
            
            24(<<{
                "digestID": 14,
                "random": h'D0E2F4A6B8C0D2E4F6A8B0C2D4E6F8A0B2C4D6E8F0A2B4C6D8E0F2A4B6C8D0E2',
                "elementIdentifier": "eye_colour",
                "elementValue": "brown"
            }>>),
            
            24(<<{
                "digestID": 15,
                "random": h'E1F3A5B7C9D1E3F5A7B9C1D3E5F7A9B1C3D5E7F9A1B3C5D7E9F1A3B5C7D9E1F3',
                "elementIdentifier": "resident_address",
                "elementValue": "123 Main Street, Los Angeles, CA 90001"
            }>>),
            
            24(<<{
                "digestID": 16,
                "random": h'F2A4B6C8D0E2F4A6B8C0D2E4F6A8B0C2D4E6F8A0B2C4D6E8F0A2B4C6D8E0F2A4',
                "elementIdentifier": "resident_city",
                "elementValue": "Los Angeles"
            }>>),
            
            24(<<{
                "digestID": 17,
                "random": h'A3B5C7D9E1F3A5B7C9D1E3F5A7B9C1D3E5F7A9B1C3D5E7F9A1B3C5D7E9F1A3B5',
                "elementIdentifier": "resident_state",
                "elementValue": "California"
            }>>),
            
            24(<<{
                "digestID": 18,
                "random": h'B4C6D8E0F2A4B6C8D0E2F4A6B8C0D2E4F6A8B0C2D4E6F8A0B2C4D6E8F0A2B4C6',
                "elementIdentifier": "resident_postal_code",
                "elementValue": "90001"
            }>>),
            
            24(<<{
                "digestID": 19,
                "random": h'C5D7E9F1A3B5C7D9E1F3A5B7C9D1E3F5A7B9C1D3E5F7A9B1C3D5E7F9A1B3C5D7',
                "elementIdentifier": "resident_country",
                "elementValue": "US"
            }>>),
            
            // ═══════════════════════════════════════════════════════════════
            // AGE ATTESTATION ELEMENTS (pre-computed by issuer)
            // ═══════════════════════════════════════════════════════════════
            
            24(<<{
                "digestID": 20,
                "random": h'D6E8F0A2B4C6D8E0F2A4B6C8D0E2F4A6B8C0D2E4F6A8B0C2D4E6F8A0B2C4D6E8',
                "elementIdentifier": "age_over_18",
                "elementValue": true
            }>>),
            
            24(<<{
                "digestID": 21,
                "random": h'E7F9A1B3C5D7E9F1A3B5C7D9E1F3A5B7C9D1E3F5A7B9C1D3E5F7A9B1C3D5E7F9',
                "elementIdentifier": "age_over_21",
                "elementValue": true
            }>>),
            
            24(<<{
                "digestID": 22,
                "random": h'F8A0B2C4D6E8F0A2B4C6D8E0F2A4B6C8D0E2F4A6B8C0D2E4F6A8B0C2D4E6F8A0',
                "elementIdentifier": "age_in_years",
                "elementValue": 34
            }>>),
            
            24(<<{
                "digestID": 23,
                "random": h'A9B1C3D5E7F9A1B3C5D7E9F1A3B5C7D9E1F3A5B7C9D1E3F5A7B9C1D3E5F7A9B1',
                "elementIdentifier": "age_birth_year",
                "elementValue": 1990
            }>>)
        ],
        
        // ═══════════════════════════════════════════════════════════════════
        // DOMESTIC NAMESPACE (US-specific data)
        // ═══════════════════════════════════════════════════════════════════
        
        "org.iso.18013.5.1.US": [
            24(<<{
                "digestID": 0,
                "random": h'B0C2D4E6F8A0B2C4D6E8F0A2B4C6D8E0F2A4B6C8D0E2F4A6B8C0D2E4F6A8B0C2',
                "elementIdentifier": "domestic_driving_privileges",
                "elementValue": [
                    {
                        "domestic_vehicle_class": {
                            "domestic_vehicle_class_code": "C",
                            "domestic_vehicle_class_description": "Passenger Car"
                        },
                        "domestic_vehicle_restrictions": {
                            "domestic_vehicle_restriction_code": "B",
                            "domestic_vehicle_restriction_description": "Corrective Lenses"
                        },
                        "issue_date": 1004("2017-02-23"),
                        "expiry_date": 1004("2024-10-20")
                    }
                ]
            }>>),
            
            24(<<{
                "digestID": 1,
                "random": h'C1D3E5F7A9B1C3D5E7F9A1B3C5D7E9F1A3B5C7D9E1F3A5B7C9D1E3F5A7B9C1D3',
                "elementIdentifier": "name_suffix",
                "elementValue": "Jr."
            }>>),
            
            24(<<{
                "digestID": 2,
                "random": h'D2E4F6A8B0C2D4E6F8A0B2C4D6E8F0A2B4C6D8E0F2A4B6C8D0E2F4A6B8C0D2E4',
                "elementIdentifier": "organ_donor",
                "elementValue": true
            }>>),
            
            24(<<{
                "digestID": 3,
                "random": h'E3F5A7B9C1D3E5F7A9B1C3D5E7F9A1B3C5D7E9F1A3B5C7D9E1F3A5B7C9D1E3F5',
                "elementIdentifier": "veteran",
                "elementValue": false
            }>>)
        ]
    },
    
    // ═══════════════════════════════════════════════════════════════════════════
    // ISSUER AUTH - Contains MSO + Signature
    // ═══════════════════════════════════════════════════════════════════════════
    
    "issuerAuth": [
        // Protected header (algorithm)
        << {1: -7} >>,   // ES256 (ECDSA with P-256 and SHA-256)
        
        // Unprotected header (certificate chain)
        {
            33: h'308201EF30820195A003020102021...'  // Document Signer X.509 certificate
            // The certificate chain (x5chain) links to the IACA root
        },
        
        // Payload: Mobile Security Object (MSO)
        <<
            24(<<
                {
                    "version": "1.0",
                    "digestAlgorithm": "SHA-256",
                    
                    // Hashes of ALL IssuerSignedItems
                    "valueDigests": {
                        "org.iso.18013.5.1": {
                            0:  h'75167333B47B6C2BFB86ECCC1F438CF57AF055371AC55E1E359E20F254ADCEBF', // family_name
                            1:  h'67E539D6139EBD131AEF441B445645DD831B2B375B390CA5EF6279B205ED4571', // given_name
                            2:  h'3394372DDB78053F36D5D869780E61EDA313D44A392092AD8E0527A2FBFE55AE', // birth_date
                            3:  h'2E35AD3C4E514BB67B1A9DB51CE74E4CB9B7146E41AC52DAC9CE86B8613DB555', // issue_date
                            4:  h'EA5C3304BB7C4A8DCB51C4C13B65264F845541341342093CCA786E058FAC2D59', // expiry_date
                            5:  h'FAE487F68B7A0E87A749774E56E9E1DC3A8EC7B77E490D21F0E1D3475661AA1D', // issuing_country
                            6:  h'7D83E507AE77DB815DE4D803B88555D0511D894C897439F5774056416A1C7533', // issuing_authority
                            7:  h'F0549A145F1CF75CBEEFFA881D4857DD438D627CF32174B1731C4C38E12CA936', // document_number
                            8:  h'B68C8AFCB2AAF7C581411D2877DEF155BE2EB121A42BC9BA5B7312377E068F66', // portrait
                            9:  h'0B3587D1DD0C2A07A35BFB120D99A0ABFB5DF56865BB7FA15CC8B56A66DF6E0C', // driving_privileges
                            10: h'C98A170CF36E11ABB724E98A75A5343DFA2B6ED3DF2ECFBB8EF2EE55DD41C881', // un_distinguishing_sign
                            11: h'B57DD036782F7B14C6A30FAAAAE6CCD5054CE88BDFA51A016BA75EDA1EDEA948', // sex
                            12: h'651F8736B18480FE252A03224EA087B5D10CA5485146C67C74AC4EC3112D4C3A', // height
                            13: h'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2', // weight
                            14: h'B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3', // eye_colour
                            15: h'C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4', // resident_address
                            16: h'D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5', // resident_city
                            17: h'E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6', // resident_state
                            18: h'F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7', // resident_postal_code
                            19: h'A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8', // resident_country
                            20: h'B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9', // age_over_18
                            21: h'C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0', // age_over_21
                            22: h'D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1', // age_in_years
                            23: h'E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2'  // age_birth_year
                        },
                        "org.iso.18013.5.1.US": {
                            0: h'D80B83D25173C484C5640610FF1A31C949C1D934BF4CF7F18D5223B15DD4F21C', // domestic_driving_privileges
                            1: h'4D80E1E2E4FB246D97895427CE7000BB59BB24C8CD003ECF94BF35BBD2917E34', // name_suffix
                            2: h'8B331F3B685BCA372E85351A25C9484AB7AFCDF0D2233105511F778D98C2F544', // organ_donor
                            3: h'C343AF1BD1690715439161ABA73702C474ABF992B20C9FB55C36A336EBE01A87'  // veteran
                        }
                    },
                    
                    // Device's public key (bound to this credential)
                    "deviceKeyInfo": {
                        "deviceKey": {
                            1: 2,        // kty: EC (Elliptic Curve)
                            -1: 1,       // crv: P-256
                            -2: h'96313D6C63E24E3372742BFDB1A33BA2C897DCD68AB8C753E4FBD48DCA6B7F9A', // x coordinate
                            -3: h'1FB3269EDD418857DE1B39A4E4A44B92FA484CAA722C228288F01D0C03A2C3D6'  // y coordinate
                        }
                    },
                    
                    "docType": "org.iso.18013.5.1.mDL",
                    
                    "validityInfo": {
                        "signed": 0("2020-10-01T13:30:02Z"),      // When MSO was created
                        "validFrom": 0("2020-10-01T13:30:02Z"),   // Start of validity
                        "validUntil": 0("2021-10-01T13:30:02Z")   // End of validity
                    }
                }
            >>)
        >>,
        
        // Digital signature over the MSO
        h'59E64205DF1E2F708DD6DB0847AED79FC7C0201D80FA55BADCAF2E1BCF5902E1E5A62E4832044B890AD85AA53F129134775D733754D7CB7A413766AEFF13CB2E'
    ]
}
```

#### Key Points About Issued Structure

| Aspect | Description |
|--------|-------------|
| **All Elements Present** | Every data element the holder might ever need to share is included |
| **Each Has Unique digestID** | Links to corresponding hash in MSO |
| **Random Bytes** | 32 bytes per element prevents brute-force attacks |
| **MSO Has All Hashes** | Every element's hash is in valueDigests |
| **Device Key Bound** | Holder's device public key is embedded in MSO |
| **No deviceSigned** | This part is created at presentation time |

#### Issuance Process Visualization

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         mDL ISSUANCE PROCESS                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  DMV (Issuer) Side:                                                            │
│  ─────────────────                                                             │
│                                                                                 │
│  1. Collect holder data           2. Generate random bytes                     │
│     ┌─────────────────┐              for each element                          │
│     │ family_name:Doe │              ┌─────────────────┐                       │
│     │ given_name:Jane │   ────────►  │ random: 32 bytes│ × 24 elements        │
│     │ birth_date:...  │              └─────────────────┘                       │
│     │ ... (24 elements)│                                                        │
│     └─────────────────┘                                                        │
│                                                                                 │
│  3. Create IssuerSignedItem for each element                                   │
│     ┌────────────────────────────────────────────────┐                         │
│     │ { digestID: 0, random: ...,                    │                         │
│     │   elementIdentifier: "family_name",            │                         │
│     │   elementValue: "Doe" }                        │                         │
│     └────────────────────────────────────────────────┘                         │
│                                                                                 │
│  4. Hash each IssuerSignedItem                                                 │
│     ┌──────────────────┐    SHA-256    ┌────────────────────────┐             │
│     │ IssuerSignedItem │ ────────────► │ h'75167333B47B6C2B...' │             │
│     │ (CBOR bytes)     │               │ (32 byte digest)       │             │
│     └──────────────────┘               └────────────────────────┘             │
│                                                                                 │
│  5. Build MSO with all hashes + device public key                              │
│     ┌────────────────────────────────────────────────────────────┐            │
│     │ MSO = {                                                     │            │
│     │   version: "1.0",                                          │            │
│     │   digestAlgorithm: "SHA-256",                              │            │
│     │   valueDigests: { 0: hash0, 1: hash1, 2: hash2, ... },    │            │
│     │   deviceKeyInfo: { deviceKey: <holder's public key> },     │            │
│     │   docType: "org.iso.18013.5.1.mDL",                        │            │
│     │   validityInfo: { signed: ..., validFrom: ..., validUntil }│            │
│     │ }                                                          │            │
│     └────────────────────────────────────────────────────────────┘            │
│                                                                                 │
│  6. Sign MSO with Document Signer private key                                  │
│     ┌─────────┐                        ┌─────────────────────────┐            │
│     │   MSO   │ + DS Private Key ────► │ COSE_Sign1 (issuerAuth) │            │
│     └─────────┘                        └─────────────────────────┘            │
│                                                                                 │
│  7. Package everything                                                         │
│     ┌────────────────────────────────────────────────────────────────┐        │
│     │ IssuerSigned = {                                                │        │
│     │   nameSpaces: { "org.iso...": [item0, item1, ...],             │        │
│     │                 "org.iso...US": [item0, item1, ...] },         │        │
│     │   issuerAuth: COSE_Sign1                                        │        │
│     │ }                                                               │        │
│     └────────────────────────────────────────────────────────────────┘        │
│                                                                                 │
│  8. Send to holder's device for secure storage                                 │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

### Part 2: Presentation at the Bar

Now Jane goes to a bar. The bouncer needs to verify she's over 21.

**The bar only requests:**
- Family name (for the receipt)
- age_over_21 (proof of legal drinking age)
- driving_privileges (to verify license validity)

### Response Structure (Selective Disclosure)

Notice how this response contains **only 3 data elements** instead of the 24+ from the issued credential:

```
{
    "version": "1.0",
    "documents": [
        {
            "docType": "org.iso.18013.5.1.mDL",
            "issuerSigned": {
                "nameSpaces": {
                    "org.iso.18013.5.1": [
                        // ═══════════════════════════════════════════════════════
                        // ONLY 3 ELEMENTS SHARED (out of 24+ available)
                        // ═══════════════════════════════════════════════════════
                        
                        24(<<{
                            "digestID": 0,
                            "random": h'8798645B20EA200E19FFABAC92624BEE6AEC63ACEEDECFB1B80077D22BFC20E9',
                            "elementIdentifier": "family_name",
                            "elementValue": "Doe"
                        }>>),
                        
                        24(<<{
                            "digestID": 9,
                            "random": h'4599F81BEAA2B20BD0FFCC9AA03A6F985BEFAB3F6BEAFFA41E6354CDB2AB2CE4',
                            "elementIdentifier": "driving_privileges",
                            "elementValue": [
                                {
                                    "vehicle_category_code": "A",
                                    "issue_date": 1004("2018-08-09"),
                                    "expiry_date": 1004("2024-10-20")
                                },
                                {
                                    "vehicle_category_code": "B",
                                    "issue_date": 1004("2017-02-23"),
                                    "expiry_date": 1004("2024-10-20")
                                }
                            ]
                        }>>),
                        
                        24(<<{
                            "digestID": 21,
                            "random": h'E7F9A1B3C5D7E9F1A3B5C7D9E1F3A5B7C9D1E3F5A7B9C1D3E5F7A9B1C3D5E7F9',
                            "elementIdentifier": "age_over_21",
                            "elementValue": true      // Just a boolean - no birth date revealed!
                        }>>)
                        
                        // ═══════════════════════════════════════════════════════
                        // NOT INCLUDED (but bar cannot see these values):
                        // - given_name (Jane)
                        // - birth_date (1990-01-15)
                        // - portrait (photo)
                        // - document_number (D1234567)
                        // - resident_address (123 Main Street...)
                        // - and 18+ other elements
                        // ═══════════════════════════════════════════════════════
                    ]
                },
                
                // The MSO still contains ALL hashes (same as at issuance)
                "issuerAuth": [
                    << {1: -7} >>,  // ES256 algorithm
                    {
                        33: h'308201EF30820195A003020102...'  // Document Signer certificate
                    },
                    <<
                        24(<<
                            {
                                "version": "1.0",
                                "digestAlgorithm": "SHA-256",
                                "valueDigests": {
                                    "org.iso.18013.5.1": {
                                        // ALL 24 hashes are present (unchanged from issuance)
                                        0:  h'75167333...',  // family_name - SHARED ✓
                                        1:  h'67E539D6...',  // given_name - hash only, no value
                                        2:  h'3394372D...',  // birth_date - hash only, no value
                                        3:  h'2E35AD3C...',  // issue_date - hash only, no value
                                        4:  h'EA5C3304...',  // expiry_date - hash only, no value
                                        5:  h'FAE487F6...',  // issuing_country - hash only
                                        6:  h'7D83E507...',  // issuing_authority - hash only
                                        7:  h'F0549A14...',  // document_number - hash only
                                        8:  h'B68C8AFC...',  // portrait - hash only
                                        9:  h'0B3587D1...',  // driving_privileges - SHARED ✓
                                        10: h'C98A170C...',  // un_distinguishing_sign - hash only
                                        // ... (hashes 11-20 omitted for brevity)
                                        21: h'C9D0E1F2...',  // age_over_21 - SHARED ✓
                                        22: h'D0E1F2A3...',  // age_in_years - hash only
                                        23: h'E1F2A3B4...'   // age_birth_year - hash only
                                    },
                                    "org.iso.18013.5.1.US": {
                                        // All US namespace hashes (none shared)
                                        0: h'D80B83D2...',
                                        1: h'4D80E1E2...',
                                        2: h'8B331F3B...',
                                        3: h'C343AF1B...'
                                    }
                                },
                                "deviceKeyInfo": {
                                    "deviceKey": {
                                        1: 2, -1: 1,
                                        -2: h'96313D6C...',
                                        -3: h'1FB3269E...'
                                    }
                                },
                                "docType": "org.iso.18013.5.1.mDL",
                                "validityInfo": {
                                    "signed": 0("2020-10-01T13:30:02Z"),
                                    "validFrom": 0("2020-10-01T13:30:02Z"),
                                    "validUntil": 0("2021-10-01T13:30:02Z")
                                }
                            }
                        >>)
                    >>,
                    h'59E64205DF1E2F708DD6DB0847AED79FC7C0201D80FA55BADCAF2E1BCF5902E1...'  // Signature
                ]
            },
            
            // ═══════════════════════════════════════════════════════════════════
            // DEVICE SIGNED - Created at presentation time (not at issuance!)
            // ═══════════════════════════════════════════════════════════════════
            "deviceSigned": {
                "nameSpaces": 24(<< {} >>),   // Empty - holder added no extra claims
                "deviceAuth": {
                    "deviceMac": [
                        << {1: 5} >>,         // HMAC-256 algorithm
                        {},                    // Empty unprotected header
                        null,                  // Payload is external (DeviceAuthentication)
                        h'E99521A85AD7891B806A07F8B5388A332D92C189A7BF293EE1F543405AE6824D'
                    ]
                }
            }
        }
    ],
    "status": 0
}
```

### Issuance vs Presentation Comparison

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                    ISSUANCE vs PRESENTATION COMPARISON                             │
├───────────────────────────────────────────────────────────────────────────────────┤
│                                                                                   │
│  ISSUANCE (from DMV)                      PRESENTATION (at bar)                   │
│  ═══════════════════                      ═════════════════════                   │
│                                                                                   │
│  nameSpaces:                              nameSpaces:                             │
│  ┌─────────────────────────────┐          ┌─────────────────────────────┐        │
│  │ 24 data elements            │          │ 3 data elements only        │        │
│  │ • family_name: "Doe"        │   ───►   │ • family_name: "Doe"        │        │
│  │ • given_name: "Jane"        │          │ • driving_privileges: [...]  │        │
│  │ • birth_date: "1990-01-15"  │          │ • age_over_21: true         │        │
│  │ • portrait: <photo>         │          └─────────────────────────────┘        │
│  │ • document_number: "D123.." │                                                  │
│  │ • age_over_21: true         │          Bar does NOT see:                      │
│  │ • driving_privileges: [...] │          • given_name                           │
│  │ • resident_address: "123.." │          • birth_date                           │
│  │ • ... 16 more elements      │          • portrait                             │
│  └─────────────────────────────┘          • document_number                      │
│                                           • resident_address                      │
│                                           • ... 21 more elements                  │
│                                                                                   │
│  MSO valueDigests:                        MSO valueDigests:                       │
│  ┌─────────────────────────────┐          ┌─────────────────────────────┐        │
│  │ 24 hashes (one per element) │   ═══►   │ Same 24 hashes (unchanged)  │        │
│  └─────────────────────────────┘          └─────────────────────────────┘        │
│                                                                                   │
│  deviceSigned:                            deviceSigned:                           │
│  ┌─────────────────────────────┐          ┌─────────────────────────────┐        │
│  │ NOT present at issuance     │   ───►   │ Created fresh for this      │        │
│  │                             │          │ presentation session        │        │
│  │                             │          │ • deviceMac with session key │        │
│  └─────────────────────────────┘          └─────────────────────────────┘        │
│                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────┘
```

| Aspect | At Issuance | At Presentation |
|--------|-------------|-----------------|
| **Data Elements** | All 24+ elements with values | Only requested elements (3 in this case) |
| **MSO Hashes** | All hashes computed and included | Same hashes (unchanged) |
| **issuerAuth Signature** | Created by DMV | Same signature (unchanged) |
| **deviceSigned** | Not present | Created fresh for each presentation |
| **Session Binding** | N/A | Tied to this specific reader session |

### What the Bar Learns

✅ **What they CAN verify:**
- Family name is "Doe" (for receipt)
- Jane is over 21 years old (age_over_21 = true)
- Her license includes Class A and B privileges
- The credential was issued by California DMV
- The credential hasn't been tampered with
- Jane's device authorized this presentation

❌ **What they CANNOT learn:**
- Jane's exact birth date
- Her given name
- Her photo
- Her address
- Her document number
- Her height, weight, eye color
- Any other data not requested

### Verification Steps

```
┌────────────────────────────────────────────────────────────────────────┐
│                    Reader Verification Process                          │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  Step 1: Verify Issuer Signature                                       │
│  ─────────────────────────────────                                     │
│  • Extract certificate from x5chain                                    │
│  • Verify certificate against trusted IACA root                        │
│  • Verify COSE_Sign1 signature over MSO                               │
│                                                                        │
│  Step 2: Verify Data Element Hashes                                    │
│  ───────────────────────────────────                                   │
│  For each IssuerSignedItem received:                                   │
│  • Compute SHA-256(IssuerSignedItemBytes)                             │
│  • Compare with valueDigests[namespace][digestID] in MSO              │
│  • If they match → data is authentic                                  │
│                                                                        │
│  Step 3: Verify Device Authentication                                  │
│  ─────────────────────────────────────                                 │
│  • Get deviceKey from MSO.deviceKeyInfo                               │
│  • Derive session key using ECDH with ephemeral keys                  │
│  • Verify deviceMac (or deviceSignature)                              │
│  • This proves the holder authorized this presentation                │
│                                                                        │
│  Step 4: Check Validity                                                │
│  ───────────────────────                                               │
│  • Check validityInfo.validFrom ≤ now ≤ validityInfo.validUntil      │
│  • Check certificate validity and revocation status                   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Putting It All Together

### The Issuance Flow

```
┌──────────────┐                                    ┌──────────────────┐
│    Holder    │                                    │  Issuing Authority│
│   (Device)   │                                    │       (DMV)      │
└──────┬───────┘                                    └────────┬─────────┘
       │                                                     │
       │  1. Apply for mDL (verify identity)                │
       │ ──────────────────────────────────────────────────►│
       │                                                     │
       │  2. Device generates key pair (on device!)          │
       │     SDeviceKey.Priv (stays secret on device)        │
       │     SDeviceKey.Pub  (will be sent to issuer)        │
       │                                                     │
       │  3. Send device PUBLIC key only                     │
       │ ──────────────────────────────────────────────────►│
       │                                                     │
       │                    ┌────────────────────────────────┤
       │                    │ 4. Create IssuerSignedItems    │
       │                    │    for all data elements       │
       │                    │                                │
       │                    │ 5. Compute hashes of all items │
       │                    │                                │
       │                    │ 6. Build MSO with:             │
       │                    │    - All hashes                │
       │                    │    - Device PUBLIC key         │
       │                    │    - Validity dates            │
       │                    │                                │
       │                    │ 7. Sign MSO with DS private key│
       │                    └────────────────────────────────┤
       │                                                     │
       │  8. Return complete mdoc                            │
       │◄───────────────────────────────────────────────────│
       │                                                     │
       │  9. Store mdoc securely                             │
       │                                                     │
```

### The Presentation Flow

```
┌──────────────┐                                    ┌──────────────────┐
│    Holder    │                                    │     Verifier     │
│   (Device)   │                                    │    (Bar/Police)  │
└──────┬───────┘                                    └────────┬─────────┘
       │                                                     │
       │  1. Device Engagement (QR code or NFC tap)          │
       │◄───────────────────────────────────────────────────│
       │                                                     │
       │  2. Exchange ephemeral keys                         │
       │◄───────────────────────────────────────────────────►
       │                                                     │
       │  3. Receive request (encrypted)                     │
       │◄───────────────────────────────────────────────────│
       │                                                     │
       │  ┌────────────────────────────────────────────────┐ │
       │  │ 4. User reviews request                        │ │
       │  │    "Bar wants: family_name, age_over_21"      │ │
       │  │                                                │ │
       │  │ 5. User approves (biometric/PIN)              │ │
       │  │                                                │ │
       │  │ 6. Build response with ONLY requested items    │ │
       │  │                                                │ │
       │  │ 7. Sign with device key (deviceAuth)          │ │
       │  └────────────────────────────────────────────────┘ │
       │                                                     │
       │  8. Send response (encrypted)                       │
       │ ──────────────────────────────────────────────────►│
       │                                                     │
       │                    ┌────────────────────────────────┤
       │                    │ 9. Decrypt response            │
       │                    │                                │
       │                    │10. Verify issuer signature     │
       │                    │                                │
       │                    │11. Verify data hashes          │
       │                    │                                │
       │                    │12. Verify device authentication│
       │                    │                                │
       │                    │13. Access granted/denied       │
       │                    └────────────────────────────────┤
       │                                                     │
```

### Security Properties Achieved

| Property | How It's Achieved |
|----------|-------------------|
| **Authenticity** | Issuer signature over MSO |
| **Integrity** | Hashes in MSO match data elements |
| **Selective Disclosure** | Only send items you choose; others stay hidden |
| **Holder Binding** | Device key in MSO + deviceAuth |
| **Freshness** | Session-specific ephemeral keys + deviceAuth |
| **Confidentiality** | Session encryption with ECDH-derived keys |
| **Non-correlation** | Random bytes in items + ephemeral keys each session |

---

## Summary

The mdoc structure is elegantly designed to balance **security**, **privacy**, and **usability**:

1. **DocType** identifies the credential type
2. **Namespaces** organize data logically
3. **IssuerSignedItems** wrap each data element with random bytes
4. **MSO** contains hashes enabling selective disclosure
5. **IssuerAuth** (COSE_Sign1) signs the MSO
6. **DeviceAuth** proves holder authorization
7. **CBOR** provides efficient binary encoding
8. **Session encryption** protects data in transit

This creates a robust system where you can prove specific facts about yourself while revealing nothing more than necessary.

---

## References

- ISO/IEC 18013-5:2021 - Personal identification — ISO-compliant driving licence — Part 5: Mobile driving licence (mDL) application
- RFC 8152 - CBOR Object Signing and Encryption (COSE)
- RFC 8949 - Concise Binary Object Representation (CBOR)
