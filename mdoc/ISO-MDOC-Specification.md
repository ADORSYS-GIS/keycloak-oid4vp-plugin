# ISO MDOC Specification - A Simple Guide

> **What is this?** This document explains the ISO/IEC 18013-5 standard (Mobile Driving Licence) in plain language, making it easy for anyone to understand without deep technical knowledge.

---

## Table of Contents
- [What is mDL?](#what-is-mdl)
- [Scope - What This Standard Covers](#scope---what-this-standard-covers)
- [System Overview - How It All Connects](#system-overview---how-it-all-connects)
- [Technical Requirements](#technical-requirements)
- [Security - Goals and Mechanisms](#security---goals-and-mechanisms)
- [mDL Data Model](#mdl-data-model)
- [Device Engagement](#device-engagement)
- [Data Retrieval](#data-retrieval)
- [Security Mechanisms - Deep Dive](#security-mechanisms---deep-dive)
- [Certificate Profiles](#certificate-profiles)
- [VICAL - The Trust List](#vical---the-trust-list)
- [Key Terms Explained](#key-terms-explained)
- [Common Abbreviations](#common-abbreviations)

---

## What is mDL?

**mDL** stands for **Mobile Driving Licence** - it's essentially your driving licence stored on your smartphone instead of a plastic card.

Think of it like how you can now use your phone to pay instead of a physical credit card. The mDL does the same thing for your driving licence.

---

## Scope - What This Standard Covers

### The Big Picture

This specification defines **how a digital driving licence works with mobile devices**. It's like a rulebook that ensures:

1. **Your phone can talk to verification devices** - When a police officer or a car rental company needs to check your licence, their reader device knows how to communicate with your phone.

2. **Verification devices can talk to the issuing authority** - The reader can check back with the DMV (or equivalent) to confirm your licence is real.

### What Can Others Do With Your mDL?

The standard allows authorized parties (like law enforcement in other states/countries) to:

| Capability | What It Means |
|------------|---------------|
| **Read mDL data by machine** | A device can automatically scan and read your licence info - no manual typing needed |
| **Link mDL to the holder** | Verify that YOU are the person the licence belongs to (not someone who stole your phone) |
| **Verify the source** | Confirm the licence was actually issued by a legitimate authority (like your state's DMV) |
| **Check data integrity** | Make sure nobody tampered with or modified your licence information |

### What This Standard Does NOT Cover

Some things are intentionally left out:

- ❌ **How you give consent** - The standard doesn't dictate how apps should ask for your permission to share data
- ❌ **How data is stored** - It doesn't specify where on your phone the licence data or security keys should be kept

> **Why leave these out?** These are implementation details that can vary by device, operating system, and local regulations. By not specifying them, the standard stays flexible across different platforms and countries.

---

## System Overview - How It All Connects

### The Three Main Players

The mDL ecosystem involves three parties that need to communicate with each other:

```
                    ┌─────────────────────────────────┐
                    │      ISSUING AUTHORITY          │
                    │   (e.g., DMV, Transport Dept)   │
                    │                                 │
                    │  ┌───────────────────────────┐  │
                    │  │  Issuing Authority        │  │
                    │  │  Infrastructure           │  │
                    │  │  (Servers & Databases)    │  │
                    │  └───────────┬───────────────┘  │
                    └──────────────┼──────────────────┘
                                   │
                 ┌─────────────────┼─────────────────┐
                 │                 │                 │
        Interface 1 ❌        Interface 3 ✅        │
        (Out of scope)        (Server Retrieval)    │
                 │                 │                 │
                 ▼                 ▼                 │
┌────────────────────────┐    ┌─────────────────────────────────┐
│     mDL HOLDER         │    │        mDL VERIFIER             │
│                        │    │   (Police, Rental Company...)   │
│  ┌──────────────────┐  │    │                                 │
│  │   📱 Phone       │  │    │  ┌───────────────────────────┐  │
│  │   with mDL       │◄─┼────┼─►│  📟 mDL Reader Device     │  │
│  └──────────────────┘  │    │  └───────────────────────────┘  │
│                        │    │                                 │
└────────────────────────┘    └─────────────────────────────────┘
                 ▲                 ▲
                 │                 │
                 └────────┬────────┘
                   Interface 2 ✅
                 (Device Retrieval)
```

### The Three Interfaces

| Interface | Connection | Covered by This Standard? | Purpose |
|-----------|------------|---------------------------|---------|
| **Interface 1** | Issuing Authority ↔ Your Phone | ❌ No | How the DMV puts your licence on your phone (provisioning) |
| **Interface 2** | Your Phone ↔ Reader Device | ✅ Yes | Direct communication to share your mDL data |
| **Interface 3** | Reader Device ↔ Issuing Authority | ✅ Yes | Reader fetching/verifying data from DMV servers |

#### Why is Interface 1 not covered?

The process of *getting* your mDL onto your phone is left to each issuing authority to decide. This could happen through:
- A dedicated government app
- A wallet app (like Apple Wallet or Google Wallet)
- A QR code scan at the DMV

This flexibility lets each country or state implement provisioning in their own way.

> **Important: Device Key Generation**  
> During provisioning, your **device generates the authentication key pair** (not the issuer!):
> - **Private key** → stays secret on your device, never shared
> - **Public key** → sent to the issuer, embedded in the MSO
> 
> This ensures even the issuing authority cannot impersonate you or clone your credential.

### Functional Requirements - What The System MUST Do

The specification requires that the mDL system must be capable of:

#### 1. 🔌 Work Offline
> The verifier and reader must be able to request, receive, and verify an mDL **even without internet connectivity** on either device.

**Why this matters:** A police officer checking your licence on a remote highway shouldn't need cell service to verify it's real.

#### 2. 🌍 Work for Third Parties
> Verifiers who are NOT the issuing authority must still be able to verify the mDL's integrity and authenticity.

**Why this matters:** If you have a California licence, a police officer in Texas (or even Germany) should be able to verify it without direct access to California's DMV systems.

#### 3. 👤 Confirm Identity
> The system must enable the verifier to confirm that the person presenting the mDL is actually the mDL holder.

**Why this matters:** This prevents someone from using a stolen phone with your mDL. The system needs ways to prove YOU are the legitimate owner (e.g., matching your face to the photo on the licence).

#### 4. 🔒 Support Selective Disclosure
> The interface must allow releasing only specific pieces of data to the reader.

**Why this matters:** If a bouncer just needs to know you're over 21, they don't need to see your home address, licence number, or exact birthdate. You should be able to share only "Yes, I'm over 21" without revealing everything else.

| Scenario | What You Share | What Stays Private |
|----------|----------------|-------------------|
| Age verification at a bar | "Over 21: Yes" | Address, licence number, exact DOB |
| Car rental | Name, DOB, licence validity | Address, organ donor status |
| Police traffic stop | Full mDL data | (Officer may need everything) |

---

## Technical Requirements

### The Data Model - How Information is Organized

Think of an mdoc like a well-organized filing cabinet. Here's how your mDL data is structured:

```
┌─────────────────────────────────────────────────────────────────┐
│                         📄 mdoc                                 │
├─────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  DOCTYPE                                                   │  │
│  │  (What type of document is this? e.g., "mDL")             │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  NAMESPACE                                                 │  │
│  │  (Category grouping, e.g., "org.iso.18013.5.1")           │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │  DATA ITEMS (each with a unique identifier)         │  │  │
│  │  │  ┌─────────────────┐  ┌─────────────────┐          │  │  │
│  │  │  │ family_name     │  │ given_name      │          │  │  │
│  │  │  │ "Smith"         │  │ "John"          │          │  │  │
│  │  │  └─────────────────┘  └─────────────────┘          │  │  │
│  │  │  ┌─────────────────┐  ┌─────────────────┐          │  │  │
│  │  │  │ birth_date      │  │ portrait        │          │  │  │
│  │  │  │ "1990-05-15"    │  │ [photo data]    │          │  │  │
│  │  │  └─────────────────┘  └─────────────────┘          │  │  │
│  │  │  ... more items ...                                 │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  (Can have additional namespaces...)                      │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─────────────────────────┐  ┌────────────────────────────┐   │
│  │  MSO                     │  │  mdoc Public Key           │   │
│  │  (Mobile Security Object)│  │  (Proves you hold the doc) │   │
│  │  - Issuer's signature    │  │                            │   │
│  │  - Integrity proof       │  │                            │   │
│  └─────────────────────────┘  └────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

#### Key Components Explained

| Component | What It Is | Analogy |
|-----------|-----------|---------|
| **DOCTYPE** | Identifies what kind of document this is | Like the title on a folder ("Driver's Licence") |
| **Namespace** | Groups related data items together | Like sections in the folder (personal info, driving privileges, etc.) |
| **Data Items** | Individual pieces of information with unique IDs | Like individual forms inside each section |
| **MSO** | Mobile Security Object - contains the issuer's digital signature and proof the data hasn't been tampered with | Like a notary stamp proving authenticity |
| **mdoc Public Key** | Cryptographic key generated BY YOUR DEVICE (not the issuer!). The public part is embedded in the MSO; the private part stays secret on your device | Like a fingerprint lock - only YOU can unlock it |

#### Why This Design is Clever

✅ **Generic & Reusable** - This same structure can be used for ANY type of digital document (ID cards, passports, professional licences, etc.) - not just driving licences

✅ **Selective Disclosure** - Each data item can be requested and returned independently, so you only share what's needed

✅ **Flexible** - The number of items can vary, and different document types can define their own data elements

---

### Data Exchange - How Information Flows

When you share your mDL, the process happens in **three phases**:

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────────┐
│    PHASE 1   │     │     PHASE 2      │     │     PHASE 3      │
│              │     │                  │     │                  │
│ Initialization│ ──▶│ Device Engagement│ ──▶ │  Data Retrieval  │
│              │     │                  │     │                  │
│  "Get ready" │     │ "Let's connect"  │     │  "Here's my data"│
└──────────────┘     └──────────────────┘     └──────────────────┘
```

| Phase | What Happens | Real-World Analogy |
|-------|--------------|-------------------|
| **Initialization** | Both devices prepare for communication | Like both people taking out their phones |
| **Device Engagement** | The mDL and reader establish a connection | Like exchanging phone numbers or scanning a QR code |
| **Data Retrieval** | The actual mDL data is requested and sent | Like actually sharing the information |

### Three Ways to Exchange Data

After initialization and device engagement, there are **three different paths** to retrieve the mDL data:

#### Flow 1: Pure Device Retrieval
```
┌──────────┐                      ┌──────────────┐
│  📱 mDL  │ ◄──── direct ─────▶ │ 📟 Reader    │
└──────────┘    (NFC/BLE/WiFi)   └──────────────┘
```
**How it works:** Your phone sends the mDL data directly to the reader.  
**When used:** Most common scenario - like showing your licence at a traffic stop.  
**Internet required?** ❌ No - works completely offline!

#### Flow 2: Device Engagement → Server Retrieval Info → Server Retrieval
```
┌──────────┐                      ┌──────────────┐
│  📱 mDL  │ ─── token + URL ──▶ │ 📟 Reader    │
└──────────┘                      └──────┬───────┘
                                         │
                                         ▼
                                 ┌──────────────────┐
                                 │  🏛️ DMV Server   │
                                 └──────────────────┘
```
**How it works:** Your phone gives the reader a "token" (like a claim ticket), then the reader fetches your data from the issuing authority's servers.  
**When used:** When the verifier wants to get the freshest data directly from the source.  
**Internet required?** ✅ Yes - the reader needs to contact the server.

#### Flow 3: Direct Server Retrieval
```
┌──────────┐                      ┌──────────────┐
│  📱 mDL  │ ── engagement ────▶ │ 📟 Reader    │
└──────────┘    info only         └──────┬───────┘
                                         │
                                         ▼
                                 ┌──────────────────┐
                                 │  🏛️ DMV Server   │
                                 └──────────────────┘
```
**How it works:** Minimal info exchange with your phone, then the reader goes straight to the server.  
**When used:** When the system is set up to always verify against the central database.  
**Internet required?** ✅ Yes.

### Connection Technologies

For **Device Retrieval**, the phone and reader can communicate via:
- **NFC** - Tap your phone against the reader
- **BLE** (Bluetooth Low Energy) - Wireless within a few meters
- **Wi-Fi Aware** - Wireless with higher bandwidth

For **Server Retrieval**, the reader contacts the issuing authority via:
- **OIDC** (OpenID Connect) - Standard identity protocol
- **WebAPI** - REST-based web services

### Important Design Principles

> 📱 **You keep your phone!**  
> The system is specifically designed so you **never need to hand your phone to the verifier**. Your mDL can be shared wirelessly while your device stays in your hands.

> 🔒 **Works offline**  
> Device retrieval requires **no internet connection** on either device. This is critical for locations with poor connectivity.

> 📦 **Wallet-friendly**  
> The protocol supports requesting items from **multiple documents** at once and receiving responses with **multiple documents** - perfect for digital wallet apps that hold various credentials.

---

### Deep Dive: The Three Phases

#### Phase 1: Initialization

This is the "wake up" phase where both devices get ready to communicate.

**How the mDL gets activated:**
- **By you** - Opening your wallet app or tapping a "share" button
- **By the reader** - Using NFC to "wake up" your mDL (like tapping a payment terminal)

> ⚠️ **Security Note:** If NFC is used to trigger activation, the system must prevent unauthorized readers from accessing your data without your knowledge.

**No specific requirements** are mandated for this phase - it's left flexible for different implementations.

---

#### Phase 2: Device Engagement

This is the "handshake" phase where your phone and the reader exchange the information needed to set up a secure connection.

**Available technologies for device engagement:**

| Technology | How It Works | mDL Support | Reader Support |
|------------|--------------|-------------|----------------|
| **NFC** | Tap your phone to the reader | Conditional* | Mandatory |
| **QR Code** | Reader scans QR from your screen (or vice versa) | Conditional* | Mandatory |

*\* The mDL must support **at least one** of these methods. The reader must support **both**.*

**Why this design?**
- **mDL flexibility** - Your phone only needs to support one method, reducing implementation burden
- **Reader compatibility** - Readers support everything, ensuring they can work with any mDL

**NFC Handover Methods:**

If NFC is used, there are two ways to do the handover:

| Method | Description |
|--------|-------------|
| **Static Handover** | Pre-defined connection information |
| **Negotiated Handover** | Devices negotiate the best connection method |

The mDL can support either or both. The reader must support both.

---

#### Phase 3: Data Retrieval Architecture

Here's how the data actually flows between devices:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              DATA RETRIEVAL ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌─ ─ ─ ─ ─ ─ ─┐          ┌────────────────────────────────┐                  │
│   │ Secure Area │◄─ ─ ─ ─ ─│  Issuing Authority Infrastructure│◄──WebAPI/OIDC──┐│
│   └─ ─ ─ ─ ─ ─ ─┘          └────────────────────────────────┘                 ││
│         │                                                                      ││
│         ▼                                                                      ││
│   ┌─────────────────────────┐                 ┌─────────────────────────┐      ││
│   │         📱 mDL          │                 │      📟 mDL Reader      │      ││
│   │  ┌───────────────────┐  │                 │  ┌───────────────────┐  │      ││
│   │  │  Request/Response │  │                 │  │  Request/Response │  │◄─────┘│
│   │  │     (CBOR)        │  │                 │  │     (CBOR)        │  │       │
│   │  └─────────┬─────────┘  │                 │  └─────────┬─────────┘  │       │
│   │            │            │                 │            │            │       │
│   │  ┌─────────▼─────────┐  │                 │  ┌─────────▼─────────┐  │       │
│   │  │     Session       │  │                 │  │     Session       │  │       │
│   │  │    Encryption     │  │                 │  │    Encryption     │  │       │
│   │  └─────────┬─────────┘  │                 │  └─────────┬─────────┘  │       │
│   └────────────┼────────────┘                 └────────────┼────────────┘       │
│                │                                           │                    │
│                │       Encrypted Message (CBOR)            │                    │
│                └──────────────────┬────────────────────────┘                    │
│                                   │                                             │
│                                   ▼                                             │
│              ┌────────────────────────────────────────────┐                     │
│              │         Transmission Technologies          │                     │
│              │  ┌─────┐  ┌─────┐  ┌────────┐  ┌───────┐  │                     │
│              │  │ NFC │  │ BLE │  │Wi-Fi   │  │ Other │  │                     │
│              │  │     │  │     │  │Aware   │  │ (RFU) │  │                     │
│              │  └─────┘  └─────┘  └────────┘  └───────┘  │                     │
│              └────────────────────────────────────────────┘                     │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**The Layered Approach:**

| Layer | What It Does |
|-------|--------------|
| **Request/Response (CBOR)** | The actual mDL data, encoded in CBOR format |
| **Session Encryption** | Encrypts everything so no one can eavesdrop |
| **Transmission** | The physical method of sending (NFC, BLE, Wi-Fi) |

**Key points:**
- Messages are **always encrypted** before transmission
- The transmission layer is **agnostic** - it just moves encrypted blobs, regardless of content
- This separation allows the same security to work over any transport technology

**About the "Secure Area":**

The dotted "Secure Area" in the architecture represents protected storage for sensitive data like:
- Your mDL private key
- Reader authentication keys

> 🔐 **Note:** The specification doesn't dictate HOW to implement secure storage - that's up to each device/OS. Examples include hardware security modules, secure enclaves (like Apple's Secure Enclave), or trusted execution environments.

---

### Data Retrieval Methods - Complete Reference

Here's a comprehensive table of all supported methods:

#### Device Retrieval (Phone ↔ Reader)

| Technology | mDL Support | Reader Support | Notes |
|------------|-------------|----------------|-------|
| **BLE** (Bluetooth Low Energy) | Conditional* | **Mandatory** | Most common method |
| **NFC** | Conditional* | **Mandatory** | Tap-to-share |
| **Wi-Fi Aware** | Optional | Recommended | Higher bandwidth for large data |

*\* Must support at least BLE or NFC (or both)*

#### Server Retrieval (Reader ↔ Issuing Authority)

| Technology | mDL Support | Reader Support | Issuer Support |
|------------|-------------|----------------|----------------|
| **WebAPI** | Optional | Recommended | Optional |
| **OIDC** | Optional | Recommended | Optional |

#### BLE Connection Modes

For Bluetooth, the reader must support two modes:

| Mode | Description |
|------|-------------|
| **mdoc Central Client Mode** | Reader acts as the "central" device that initiates |
| **mdoc Peripheral Server Mode** | Reader acts as a "peripheral" waiting for connections |

This dual-mode support ensures compatibility regardless of which device initiates.

---

### Important Practical Considerations

#### ⚠️ The QR + NFC Problem

If you use a **QR code** for device engagement but the reader wants to use **NFC** for data transfer, there's no way for the reader to tell your phone "switch to NFC." The user might not realize they need to tap their phone.

**Solution:** If NFC will be used for data transfer, use NFC for device engagement too.

#### ⚠️ NFC Range Limitations

NFC has a very short range (a few centimeters). For transactions that transfer large amounts of data:
- Holding your phone in range for extended periods can be inconvenient
- If your phone leaves the NFC field (even briefly), the transaction fails and must restart
- Any user interaction that moves the phone (like confirming consent on screen) can break the connection

**Best practice:** Complete any user interactions (consent dialogs, etc.) BEFORE starting the NFC data transfer.

#### The "Either/Or" Rule for Server Retrieval

If the reader requests **both** regular mDL data AND server retrieval information:
> The mDL must return **one or the other**, never both in the same response.

This prevents confusion about which data source should be trusted.

---

## Security - Goals and Mechanisms

Security is fundamental to the mDL system. Here's how the specification protects against various threats:

### The Four Security Goals

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SECURITY GOALS                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   🛡️ PROTECTION AGAINST FORGERY                                            │
│   "Is this licence real, and is the data unchanged?"                        │
│                                                                             │
│   🔄 PROTECTION AGAINST CLONING                                             │
│   "Is this the original licence, not a copy on another device?"             │
│                                                                             │
│   👁️ PROTECTION AGAINST EAVESDROPPING                                       │
│   "Can anyone else see the data being transmitted?"                         │
│                                                                             │
│   🚫 PROTECTION AGAINST UNAUTHORIZED ACCESS                                 │
│   "Can someone access my data without my permission?"                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### How Each Goal is Achieved

#### 🛡️ Protection Against Forgery

**The threat:** Someone creates a fake mDL or modifies legitimate mDL data.

| What We Need to Verify | Device Retrieval Method | Server Retrieval Method |
|------------------------|------------------------|------------------------|
| The mDL came from a real issuing authority | Issuer Data Authentication | JWS (JSON Web Signature) |
| The data hasn't been tampered with | Issuer Data Authentication | JWS |
| How fresh/current the data is | Issuer Data Authentication | JWS |

**In plain terms:**
- **Device Retrieval:** The issuing authority digitally signs all mDL data. This signature can be verified offline to prove authenticity.
- **Server Retrieval:** Uses JWS (a web standard for signed data) - the server's response is cryptographically signed.

---

#### 🔄 Protection Against Cloning

**The threat:** Someone copies your mDL data to their own device and pretends to be you.

| What We Need | Device Retrieval Method | Server Retrieval Method |
|--------------|------------------------|------------------------|
| Prove the mDL is on the authorized device | mdoc Authentication | mdoc Authentication* |
| Ensure communication hasn't been altered | Session Encryption | TLS |

*\* Only applicable if the server retrieval token is transferred via device retrieval*

**In plain terms:**
- **mdoc Authentication:** Your phone proves it holds a private key that's bound to your mDL. Even if someone copies all visible data, they can't copy the private key stored securely on your device.
- **Session Encryption / TLS:** All communication is encrypted, preventing anyone from capturing data mid-transmission to replay later.

---

#### 👁️ Protection Against Eavesdropping

**The threat:** Someone intercepts the wireless communication between your phone and the reader to steal your data.

| What We Need | Device Retrieval Method | Server Retrieval Method |
|--------------|------------------------|------------------------|
| Keep mDL data confidential | Session Encryption | TLS |

**In plain terms:**
- **Session Encryption:** A unique encryption key is created for each session. Even if someone captures the radio signals, they see only scrambled data.
- **TLS:** The same technology that secures websites (HTTPS). All server communication is encrypted.

---

#### 🚫 Protection Against Unauthorized Access

**The threat:** A malicious reader tries to access your mDL without your knowledge or consent.

| What We Need | Device Retrieval Method | Server Retrieval Method |
|--------------|------------------------|------------------------|
| Prevent sneaky data access | Close-range device engagement + Session Encryption | Close-range device engagement* + TLS |
| Verify the reader is legitimate | mdoc Reader Authentication** | TLS Client Authentication** |

*\* Only applicable if the server retrieval token is transferred via device retrieval*  
*\*\* These are optional methods*

**In plain terms:**
- **Close-range device engagement:** You must be physically close to the reader (NFC tap or QR scan). No one can secretly access your mDL from across the room.
- **Session Encryption:** Even if engagement happens, the data is encrypted for that specific session.
- **mdoc Reader Authentication (optional):** The reader proves its identity to your mDL - your phone can reject untrusted readers.
- **TLS Client Authentication (optional):** The reader proves its identity when connecting to the issuing authority's servers.

---

### Security Mechanisms Summary

| Mechanism | What It Does | Where It's Used |
|-----------|-------------|-----------------|
| **Issuer Data Authentication** | Proves data came from the real DMV and hasn't been modified | Device retrieval - verifying mDL authenticity |
| **JWS** (JSON Web Signature) | Cryptographic signature on server responses | Server retrieval - verifying data authenticity |
| **Session Encryption** | Scrambles all data for the current session | Device retrieval - all data transfer |
| **TLS** | Industry-standard encrypted connection | Server retrieval - all server communication |
| **mdoc Authentication** | Proves the mDL is on the original device | Preventing cloning |
| **mdoc Reader Authentication** | Reader proves it's legitimate (optional) | Blocking rogue readers |
| **TLS Client Authentication** | Reader proves identity to server (optional) | Server retrieval security |
| **Close-range Engagement** | Requires physical proximity to start | Preventing remote attacks |

---

### The Trust Chain

Here's how trust flows through the system:

```
┌────────────────────────────────────────────────────────────────────────┐
│                         TRUST CHAIN                                    │
└────────────────────────────────────────────────────────────────────────┘
                                    
   ┌─────────────────┐                                                    
   │  ROOT OF TRUST  │   The issuing authority (e.g., DMV) is trusted    
   │  Issuing        │   because it's a known government entity           
   │  Authority      │                                                    
   └────────┬────────┘                                                    
            │                                                             
            │ Signs the mDL data with their private key                   
            ▼                                                             
   ┌─────────────────┐                                                    
   │  mDL DATA +     │   The digital signature can be verified by anyone  
   │  SIGNATURE      │   who has the issuing authority's public key       
   │  (MSO)          │   (published in certificates)                      
   └────────┬────────┘                                                    
            │                                                             
            │ MSO includes holder's device PUBLIC key                    
            │ (generated BY the device, not the issuer!)                 
            ▼                                                             
   ┌─────────────────┐                                                    
   │  YOUR PHONE     │   Your phone proves it holds the mDL by using     
   │  (Device Key)   │   the PRIVATE key (which never left the device)   
   └────────┬────────┘                                                    
            │                                                             
            │ Encrypted session with verified reader                      
            ▼                                                             
   ┌─────────────────┐                                                    
   │  VERIFIER       │   Receives authentic, unmodified data from the     
   │  (Reader)       │   legitimate mDL holder                            
   └─────────────────┘                                                    
```

### Why All This Matters

| Without This Security... | What Could Happen |
|--------------------------|-------------------|
| No issuer authentication | Anyone could create fake licences |
| No anti-cloning | Thieves could copy your licence to their phones |
| No encryption | Nearby attackers could capture all your data |
| No close-range requirement | Attackers could scan your mDL from a distance |
| No reader authentication | Malicious readers could trick you into sharing data |

---

## mDL Data Model

This section describes what information is stored in an mDL and how it's organized.

### Document Type and Namespace

Every mDL has two key identifiers that tell systems what they're looking at:

| Identifier | Value | Purpose |
|------------|-------|---------|
| **DocType** | `org.iso.18013.5.1.mDL` | Identifies this as a mobile driving licence |
| **Namespace** | `org.iso.18013.5.1` | Groups all the standard mDL data elements |

**Why the weird format?**

The format uses "reverse domain notation" (like `org.iso.18013.5.1`) to avoid conflicts. It's similar to how apps are named (`com.google.maps`, `com.apple.music`). This ensures:
- No two document types accidentally have the same name
- Organizations can define their own document types without colliding

> 📝 The "1" at the end may increase in future versions of the standard.

---

### Data Elements - What's In Your mDL

Your mDL contains various pieces of information, each with a unique identifier. Here's what can be stored:

#### Mandatory Data Elements

These fields **must** be present on every mDL:

| Identifier | What It Is | Format | Example |
|------------|-----------|--------|---------|
| `family_name` | Last name / surname | Text (max 150 chars) | "Smith" |
| `given_name` | First name(s) | Text (max 150 chars) | "John William" |
| `birth_date` | Date of birth | Date | 1990-05-15 |
| `issue_date` | When the licence was issued | Date/time | 2023-01-15 |
| `expiry_date` | When the licence expires | Date/time | 2031-01-15 |
| `issuing_country` | Country that issued the licence | 2-letter code | "US" |
| `issuing_authority` | Organization that issued it | Text (max 150 chars) | "California DMV" |
| `document_number` | The licence number | Text (max 150 chars) | "D1234567" |
| `portrait` | Your photo | Image (JPEG/JPEG2000) | [photo data] |
| `driving_privileges` | What you can drive | Structured data | See below |
| `un_distinguishing_sign` | International sign | Text | "USA" |

#### Optional Data Elements

These fields **may** be included:

| Identifier | What It Is | Format |
|------------|-----------|--------|
| `administrative_number` | Audit/control number | Text (max 150 chars) |
| `sex` | Sex of the holder | Number (ISO 5218) |
| `height` | Height in centimetres | Number |
| `weight` | Weight in kilograms | Number |
| `eye_colour` | Eye colour | Text (see allowed values) |
| `hair_colour` | Hair colour | Text (see allowed values) |
| `birth_place` | Place of birth | Text (max 150 chars) |
| `resident_address` | Full residential address | Text (max 150 chars) |
| `resident_city` | City of residence | Text (max 150 chars) |
| `resident_state` | State/province of residence | Text (max 150 chars) |
| `resident_postal_code` | Postal/ZIP code | Text (max 150 chars) |
| `resident_country` | Country of residence | 2-letter code |
| `portrait_capture_date` | When the photo was taken | Date/time |
| `age_in_years` | Current age in years | Number |
| `age_birth_year` | Birth year | Number |
| `age_over_NN` | Age verification (see below) | True/False |
| `issuing_jurisdiction` | Sub-national jurisdiction | Code (ISO 3166-2) |
| `nationality` | Nationality | 2-letter code |
| `family_name_national_character` | Name in native script | Text (UTF-8) |
| `given_name_national_character` | Name in native script | Text (UTF-8) |
| `signature_usual_mark` | Signature image | Image (JPEG/JPEG2000) |
| `biometric_template_xx` | Biometric data | Binary |

**Allowed values for eye colour:**
`black`, `blue`, `brown`, `dichromatic`, `grey`, `green`, `hazel`, `maroon`, `pink`, `unknown`

**Allowed values for hair colour:**
`bald`, `black`, `blond`, `brown`, `grey`, `red`, `auburn`, `sandy`, `white`, `unknown`

---

### Important Rules About Data Release

#### Portrait is Required for Verification

> If ANY data is returned to a reader, the **portrait must also be returned** (if requested).

Why? The photo is the only way to verify the person presenting the mDL is actually the holder. Without it, someone could use a stolen phone.

#### Reader Authentication and Optional Data

| Data Type | Can require reader authentication? |
|-----------|-----------------------------------|
| Mandatory data elements | ❌ No - must be available without reader auth |
| Optional data elements | ✅ Yes - mDL can require the reader to prove its identity first |

This ensures you can always use your mDL as a basic driving licence, even if the reader doesn't support authentication.

---

### Driving Privileges Structure

The `driving_privileges` field describes what vehicles you're allowed to drive. It's structured like this:

```
┌─────────────────────────────────────────────────────────────┐
│                   Driving Privileges                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Driving Privilege #1                               │   │
│  │  ├── vehicle_category_code: "B"    (cars)          │   │
│  │  ├── issue_date: 2020-01-15                        │   │
│  │  ├── expiry_date: 2030-01-15                       │   │
│  │  └── codes: [restrictions/conditions]              │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Driving Privilege #2                               │   │
│  │  ├── vehicle_category_code: "A"    (motorcycles)   │   │
│  │  ├── issue_date: 2022-06-01                        │   │
│  │  └── expiry_date: 2030-01-15                       │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Common vehicle category codes:**

| Code | Vehicle Type |
|------|-------------|
| AM | Mopeds |
| A1 | Light motorcycles |
| A2 | Medium motorcycles |
| A | All motorcycles |
| B | Cars (up to 3,500 kg) |
| C | Trucks |
| D | Buses |
| BE, CE, DE | With trailers |

---

### Age Attestation - Privacy-Friendly Age Verification

This is one of the most **privacy-friendly** features of mDL!

#### The Problem
A bar needs to verify you're over 21. Do they really need your exact birth date?

#### The Solution: `age_over_NN`

Instead of revealing your birth date, the mDL can simply confirm: **"Yes, this person is over 21"** ✅

```
┌─────────────────────────────────────────────────────────────┐
│              TRADITIONAL WAY (Privacy-invasive)             │
├─────────────────────────────────────────────────────────────┤
│  Bouncer asks: "Are you over 21?"                           │
│  You show: birth_date = "1990-05-15"                        │
│  Bouncer now knows: Your exact birthday 😟                  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│              mDL WAY (Privacy-preserving)                   │
├─────────────────────────────────────────────────────────────┤
│  Bouncer asks: "age_over_21?"                               │
│  mDL responds: age_over_21 = TRUE ✅                        │
│  Bouncer knows: You're over 21 (nothing more!) 😊           │
└─────────────────────────────────────────────────────────────┘
```

#### How It Works

Your mDL stores several age attestations (e.g., `age_over_18`, `age_over_21`, `age_over_25`, `age_over_65`).

When a reader requests `age_over_NN`:

1. **First**, look for a TRUE attestation ≥ NN with the smallest gap
2. **If none**, look for a FALSE attestation ≤ NN with the smallest gap  
3. **If none**, return nothing

**Example:** You're 23 years old, and your mDL has `age_over_18=TRUE` and `age_over_21=TRUE`

| Reader Requests | mDL Returns | Reasoning |
|-----------------|-------------|-----------|
| `age_over_21` | `age_over_21=TRUE` | Exact match |
| `age_over_18` | `age_over_18=TRUE` | Exact match |
| `age_over_20` | `age_over_21=TRUE` | Closest TRUE attestation ≥ 20 |
| `age_over_25` | `age_over_21=TRUE` | Closest TRUE attestation (even though < 25) |

#### Privacy Considerations

> 📊 **More attestations = Better privacy**
> 
> Having many age attestations (18, 19, 20, 21, 25, 30, etc.) means the response will be closer to the question asked, revealing less about your actual age.

**Limitation:** Readers can only request **up to 2** age attestations per transaction (to prevent them from narrowing down your exact age through repeated queries).

---

### Biometric Templates

Optional biometric data can be included for enhanced identity verification:

| Template Type | Identifier |
|--------------|------------|
| Face | `biometric_template_face` |
| Fingerprint | `biometric_template_finger` |
| Iris | `biometric_template_iris` |
| Signature | `biometric_template_signature_sign` |

These follow ISO/IEC 19785-3 standards. The facial template must use JPEG or JPEG2000 format.

---

### Portrait and Signature Requirements

| Element | Format | Notes |
|---------|--------|-------|
| **Portrait** | JPEG or JPEG2000 | Must follow ISO/IEC 18013-2 face image requirements |
| **Signature** | JPEG or JPEG2000 | Image of the holder's signature or usual mark |

---

### Domestic (Country-Specific) Data

Countries can add their own custom data elements using their own namespace.

**Namespace format:** `org.iso.18013.5.1.[COUNTRY_CODE]`

| Country/Region | Namespace Example |
|----------------|-------------------|
| United States | `org.iso.18013.5.1.US` |
| Iowa (US state) | `org.iso.18013.5.1.US-IA` |
| Germany | `org.iso.18013.5.1.DE` |
| California | `org.iso.18013.5.1.US-CA` |

This allows each jurisdiction to include local requirements (like organ donor status, veteran indicator, etc.) without conflicting with the international standard.

---

### Data Encoding Quick Reference

| Format | Description | When Used |
|--------|-------------|-----------|
| `tstr` | Text string | Names, addresses, codes |
| `uint` | Unsigned integer | Age, height, weight |
| `bstr` | Binary string | Images, biometrics |
| `bool` | Boolean (true/false) | Age attestations |
| `tdate` | Date with time | Issue date, expiry date |
| `full-date` | Date only (no time) | Birth date |

**Date rules:**
- No fractional seconds
- Always use UTC (indicated by "Z" suffix)
- Example: `2024-01-15T00:00:00Z`

---

### Verification Requirements

When a reader receives mDL data, it must verify:

| Data Element | Must Match |
|--------------|-----------|
| `issuing_country` | Country name in the Document Signer certificate |
| `issuing_jurisdiction` | State/Province in the DS certificate (if present) |
| `issue_date` | Must not be after the MSO's validFrom timestamp |

---

## Device Engagement

Device engagement is the "handshake" phase where your phone and the reader establish a secure connection before exchanging any mDL data.

### What Happens During Device Engagement?

```
┌──────────────────────────────────────────────────────────────────────────┐
│                      DEVICE ENGAGEMENT FLOW                              │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   📱 Your Phone                              📟 Reader Device            │
│        │                                           │                     │
│        │  ┌─────────────────────────────────┐     │                     │
│        │  │ Device Engagement Info:         │     │                     │
│        │  │ • Version ("1.0")               │     │                     │
│        │  │ • Security (cipher + key)       │     │                     │
│        │  │ • How to connect (BLE/NFC/WiFi) │     │                     │
│        │  │ • Server retrieval options      │     │                     │
│        ├──┴─────────────────────────────────┴────►│                     │
│        │           via QR Code or NFC             │                     │
│        │                                          │                     │
│        │◄─────────── Secure Connection ──────────►│                     │
│        │                                          │                     │
└──────────────────────────────────────────────────────────────────────────┘
```

### The Device Engagement Structure

When your phone starts the engagement, it sends a structured message containing:

| Field | What It Contains | Required? |
|-------|------------------|-----------|
| **Version** | Protocol version (currently "1.0") | ✅ Yes |
| **Security** | Cipher suite ID + your device's ephemeral public key | ✅ Yes |
| **DeviceRetrievalMethods** | List of ways to connect (BLE, NFC, Wi-Fi) | Only for QR |
| **ServerRetrievalMethods** | Info for server-based retrieval (WebAPI/OIDC) | ❌ Optional |
| **ProtocolInfo** | Reserved for future use | ❌ Optional |

### Ways to Start Device Engagement

#### Option 1: QR Code 📷

Your phone displays a QR code that the reader scans.

```
┌───────────────────────────────────────┐
│         QR Code Contents              │
├───────────────────────────────────────┤
│  mdoc:[base64url-encoded-data]        │
│                                       │
│  Example:                             │
│  mdoc:owBjMS4woQECAQGhAQFYQC...       │
└───────────────────────────────────────┘
```

**The QR code contains:**
- `mdoc:` - The URL scheme (tells the reader "this is an mDL")
- Base64url-encoded Device Engagement structure

**What's included for QR engagement:**
- Supported connection methods (BLE, NFC, Wi-Fi Aware)
- Connection-specific options (UUIDs, channels, etc.)

#### Option 2: NFC Tap 📲

You tap your phone to the reader using NFC.

**Two handover methods:**

| Method | How It Works |
|--------|-------------|
| **Static Handover** | Your phone has pre-configured connection info ready to send |
| **Negotiated Handover** | Your phone and reader negotiate the best connection method |

> 💡 **Pro tip:** Negotiated Handover provides better user experience and security because both devices can agree on the best connection method.

**With NFC engagement:**
- The Device Engagement structure is sent as an auxiliary data record
- Connection options are in Alternative Carrier Records (not in the main structure)

### Server Retrieval Information

If server retrieval is supported, this info can be shared during engagement:

```
┌─────────────────────────────────────────────────────────┐
│              Server Retrieval Info                      │
├─────────────────────────────────────────────────────────┤
│  OIDC = [                                               │
│    version: 1,              // Protocol version         │
│    issuerURL: "https://dmv.example.gov",                │
│    token: "abc123..."       // Server retrieval token   │
│  ]                                                      │
│                                                         │
│  WebAPI = [                                             │
│    version: 1,                                          │
│    issuerURL: "https://api.dmv.example.gov",            │
│    token: "xyz789..."                                   │
│  ]                                                      │
└─────────────────────────────────────────────────────────┘
```

**Two ways to get server retrieval info:**

| Method | Security | When to Use |
|--------|----------|-------------|
| **During device engagement** | ⚠️ Not authenticated | Quick setup, but issuing authority must validate the token |
| **During device retrieval** | ✅ Authenticated (issuer or device signed) | More secure, data integrity protected |

### Connection Options by Technology

#### BLE Options

```javascript
BleOptions = {
  peripheralServerMode: true/false,  // Can phone act as server?
  centralClientMode: true/false,     // Can phone act as client?
  peripheralServerUUID: "...",       // UUID for server mode
  centralClientUUID: "...",          // UUID for client mode  
  deviceAddress: "..."               // BLE device address (optional)
}
```

#### NFC Options

```javascript
NfcOptions = {
  maxCommandDataLength: 255-65535,   // Max bytes phone can receive
  maxResponseDataLength: 256-65536   // Max bytes phone can send
}
```

#### Wi-Fi Aware Options

```javascript
WifiOptions = {
  passPhrase: "...",       // Connection password (optional)
  operatingClass: 81,      // WiFi operating class
  channelNumber: 6,        // WiFi channel
  supportedBands: [...]    // Supported frequency bands
}
```

### Time-outs

| Stage | Recommended Minimum Time-out |
|-------|------------------------------|
| Transaction initialization → Device engagement | 30 seconds |
| Device engagement → Session establishment | 30 seconds |

> ⏱️ Either party can terminate the session at any time.

---

## Data Retrieval

Once device engagement is complete, the actual data exchange begins. This section covers how requests are made and responses are returned.

### Overview of the Process

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        DATA RETRIEVAL FLOW                               │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   📟 Reader                                   📱 Phone                   │
│       │                                           │                      │
│       │  "I need: name, DOB, portrait,           │                      │
│       │   driving_privileges for doc type        │                      │
│       │   org.iso.18013.5.1.mDL"                 │                      │
│       ├──────────────────────────────────────────►│                      │
│       │            mdoc Request                   │                      │
│       │                                           │                      │
│       │                                           │  User approves       │
│       │                                           │  what to share       │
│       │                                           │                      │
│       │  "Here's the signed data you requested"  │                      │
│       │◄──────────────────────────────────────────┤                      │
│       │            mdoc Response                  │                      │
│       │                                           │                      │
└──────────────────────────────────────────────────────────────────────────┘
```

### DocType and Namespace

Every request and response specifies:

| Parameter | Purpose | Example |
|-----------|---------|---------|
| **DocType** | What type of document | `org.iso.18013.5.1.mDL` |
| **Namespace** | Which set of data elements | `org.iso.18013.5.1` |

---

### Device Retrieval (Phone ↔ Reader)

#### The Request Structure

When the reader wants mDL data, it sends a **DeviceRequest**:

```
DeviceRequest
├── version: "1.0"
└── docRequests: [
      └── DocRequest
            ├── itemsRequest: (CBOR-encoded)
            │     ├── docType: "org.iso.18013.5.1.mDL"
            │     ├── nameSpaces:
            │     │     └── "org.iso.18013.5.1":
            │     │           ├── "family_name": true    // intend to retain
            │     │           ├── "given_name": false   // won't retain
            │     │           ├── "portrait": false
            │     │           └── "age_over_21": false
            │     └── requestInfo: { ... }  // optional extra info
            └── readerAuth: (optional reader authentication)
    ]
```

**Key concepts:**

| Field | What It Means |
|-------|---------------|
| `docRequests` | Array of document requests (can request multiple docs) |
| `itemsRequest` | The actual request, CBOR-encoded |
| `IntentToRetain` | **Important!** Tells the user if the verifier will store the data |
| `readerAuth` | Optional proof of reader identity |

> 🔒 **Privacy Protection:** Verifiers MUST NOT retain any data (including derived data) unless `IntentToRetain` was set to `true` in the request. "Retain" means storing longer than needed for the real-time transaction.

#### The Response Structure

The phone responds with a **DeviceResponse**:

```
DeviceResponse
├── version: "1.0"
├── status: 0 (OK)
├── documents: [
│     └── Document
│           ├── docType: "org.iso.18013.5.1.mDL"
│           ├── issuerSigned:
│           │     ├── nameSpaces:
│           │     │     └── "org.iso.18013.5.1": [
│           │     │           IssuerSignedItem (family_name),
│           │     │           IssuerSignedItem (given_name),
│           │     │           IssuerSignedItem (portrait),
│           │     │           ...
│           │     │         ]
│           │     └── issuerAuth: (MSO + signature)
│           ├── deviceSigned:
│           │     ├── nameSpaces: { ... }
│           │     └── deviceAuth: (device signature or MAC)
│           └── errors: { ... }  // if any items couldn't be returned
│   ]
└── documentErrors: [ ... ]  // if any documents couldn't be returned
```

**Two types of signed data:**

| Type | What It Contains | Signed By |
|------|------------------|-----------|
| **IssuerSigned** | Official mDL data elements | Issuing authority (DMV) |
| **DeviceSigned** | Additional data (like server retrieval info) | Your device |

**IssuerSignedItem structure:**

```javascript
IssuerSignedItem = {
  digestID: 0,                    // Links to MSO for verification
  random: [random bytes],         // Salt for privacy (selective disclosure)
  elementIdentifier: "family_name",
  elementValue: "Smith"
}
```

#### Status Codes

| Code | Message | Meaning |
|------|---------|---------|
| 0 | OK | Everything worked |
| 10 | General error | Something went wrong |
| 11 | CBOR decoding error | Couldn't parse the request |
| 12 | CBOR validation error | Request structure was invalid |

#### Error Codes (for specific items)

| Code | Meaning |
|------|---------|
| 0 | Data not returned (no specific reason) |
| Positive integers | Application-specific errors |
| Negative integers | Reserved for future use |

---

### Server Retrieval (Reader ↔ Issuing Authority)

For server retrieval, the reader contacts the issuing authority's servers directly.

#### WebAPI Method

**Request (JSON):**

```json
{
  "version": "1.0",
  "token": "server-retrieval-token-from-mdoc",
  "docRequests": [
    {
      "docType": "org.iso.18013.5.1.mDL",
      "nameSpaces": {
        "org.iso.18013.5.1": {
          "family_name": false,
          "portrait": false,
          "age_over_21": false
        }
      }
    }
  ]
}
```

**Response (JSON with JWT):**

```json
{
  "version": "1.0",
  "documents": [
    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."  // JWT containing the data
  ]
}
```

The JWT contains:
- `doctype`: The document type
- `namespaces`: The requested data elements
- `exp`: Expiration time (required)
- `iat`: Issued at time (required)

**HTTP Endpoints:**

| Endpoint | Method | Content-Type |
|----------|--------|--------------|
| `{issuerURL}/identity` | POST | `application/json` |

**HTTP Status Codes:**

| Code | Meaning |
|------|---------|
| 200 OK | Success |
| 202 Accepted | Processing (use polling) |
| 400 Bad Request | Invalid request |
| 401 Unauthorized | Invalid token |
| 500 Internal Server Error | Server problem |

#### OIDC Method

Uses standard OpenID Connect flow:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         OIDC FLOW                                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Step 1: Configuration                                                  │
│  ─────────────────────                                                  │
│  Reader fetches: {issuerURL}/.well-known/openid-configuration           │
│                                                                         │
│  Step 2: Client Registration                                            │
│  ──────────────────────────                                             │
│  Reader gets a client_id (dynamic registration or pre-configured)       │
│                                                                         │
│  Step 3: Authorization                                                  │
│  ─────────────────────                                                  │
│  Reader sends auth request with:                                        │
│  • client_id                                                            │
│  • login_hint = server_retrieval_token (from mDL)                       │
│  User approves → Reader gets authorization code                         │
│                                                                         │
│  Step 4: Get ID Token                                                   │
│  ───────────────────                                                    │
│  Reader exchanges auth code for ID token at token endpoint              │
│  Token contains the mDL data as claims                                  │
│                                                                         │
│  Step 5: Validate ID Token                                              │
│  ────────────────────────                                               │
│  Reader verifies the JWT signature using issuer's public key (JWKS)     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**OIDC Claim naming convention:**

```
[Namespace]:[DataElementIdentifier]

Example:
org.iso.18013.5.1:portrait
org.iso.18013.5.1:family_name
```

---

### Transmission Technologies

#### Bluetooth Low Energy (BLE)

The most common method for device retrieval.

**BLE Roles:**

| Mode | Phone Role | Reader Role | When Used |
|------|------------|-------------|-----------|
| **mdoc peripheral server** | GATT Server (Peripheral) | GATT Client (Central) | Reader connects to phone |
| **mdoc central client** | GATT Client (Central) | GATT Server (Peripheral) | Phone connects to reader |

> 💡 If the phone supports both modes, the reader should select **mdoc central client mode**.

**Connection Flow:**

```
1. Device Engagement (QR or NFC)
         ↓
2. BLE Connection Setup
   • Peripheral broadcasts UUID from engagement
   • Central scans for UUID and connects
   • (Optional) Verify Ident characteristic
         ↓
3. GATT Client subscribes to notifications
         ↓
4. Client writes 0x01 to State characteristic ("Ready!")
         ↓
5. Data Exchange
   • Messages split into MTU-sized chunks
   • First byte: 0x01 (more coming) or 0x00 (last chunk)
         ↓
6. Client writes 0x02 to State ("Done!")
         ↓
7. Disconnect
```

**BLE Characteristics (when phone is server):**

| Characteristic | UUID | Purpose |
|----------------|------|---------|
| State | 00000001-A123-48CE-896B-4C76973373E6 | Connection state (Start/End) |
| Client2Server | 00000002-A123-48CE-896B-4C76973373E6 | Reader sends data to phone |
| Server2Client | 00000003-A123-48CE-896B-4C76973373E6 | Phone sends data to reader |

**State Values:**

| Value | Meaning |
|-------|---------|
| 0x01 | Start - transmission can begin |
| 0x02 | End - terminate transaction |

**Connection Lost?**
- Before transmission started → Reconnect
- After transmission started → Start completely new transaction

#### NFC

For close-range, tap-to-share transfers.

**Roles:**
- Phone: PICC mode (acts like a contactless card)
- Reader: PCD mode (acts like a card reader)

**Application ID (AID):** `A0 00 00 02 48 04 00`

**Commands:**
1. **SELECT** - Select the mDL application
2. **ENVELOPE** - Transfer data (with chaining for large messages)
3. **GET RESPONSE** - Get remaining data if response was too large

**Data Field Limits:**

| Field | Minimum | Maximum |
|-------|---------|---------|
| Command data | 255 bytes | 65,535 bytes |
| Response data | 256 bytes | 65,536 bytes |

> ⚠️ If NFC connection is lost during data retrieval, the entire transaction must restart from device engagement.

#### Wi-Fi Aware

For high-bandwidth transfers.

**How it works:**
1. Service name is derived from the device key (unique per transaction)
2. Phone is the Service Publisher, Reader is the Service Subscriber
3. After discovery, Reader initiates the data path (NDP Initiator)
4. Data transferred via HTTP POST over the Wi-Fi Aware connection

**HTTP Request Format:**
```http
POST /mdoc HTTP/1.1
Host: [IPv6 address of phone]
Content-Type: application/cbor

[SessionEstablishment or SessionData message]
```

**Cipher Suites:**

| Suite | Reader Support | Phone Support |
|-------|----------------|---------------|
| NCS-SK-128 | Required | Required |
| NCS-PK-2WDH-128 | Required | Recommended |

---

### Putting It All Together - Transaction Flow Summary

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    COMPLETE TRANSACTION FLOW                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 1. INITIALIZATION                                               │   │
│  │    Phone activates mDL app                                      │   │
│  │    Reader prepares to scan                                      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 2. DEVICE ENGAGEMENT                                            │   │
│  │    • Phone shows QR code OR NFC tap                             │   │
│  │    • Exchange: version, security info, connection methods       │   │
│  │    • Establish encrypted session                                │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 3. DATA RETRIEVAL                                               │   │
│  │                                                                 │   │
│  │    Option A: Device Retrieval                                   │   │
│  │    ────────────────────────                                     │   │
│  │    Reader ──[Request]──► Phone                                  │   │
│  │    Phone ──[Response]──► Reader (via BLE/NFC/WiFi)              │   │
│  │                                                                 │   │
│  │    Option B: Server Retrieval                                   │   │
│  │    ─────────────────────                                        │   │
│  │    Phone ──[Token]──► Reader                                    │   │
│  │    Reader ──[Request+Token]──► Issuing Authority Server         │   │
│  │    Server ──[Response]──► Reader (via WebAPI/OIDC)              │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 4. SESSION TERMINATION                                          │   │
│  │    • Data verified                                              │   │
│  │    • Connection closed                                          │   │
│  │    • Session info cleared                                       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Security Mechanisms - Deep Dive

This section provides detailed information about how the mDL system secures data and prevents attacks.

### Overview of Security Mechanisms

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SECURITY MECHANISMS OVERVIEW                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 1. SESSION ENCRYPTION                                           │   │
│  │    Protects data during transmission (eavesdropping/alteration) │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 2. ISSUER DATA AUTHENTICATION                                   │   │
│  │    Proves data came from real DMV and wasn't modified           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 3. mdoc AUTHENTICATION                                          │   │
│  │    Prevents cloning - proves this is the original device        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 4. mdoc READER AUTHENTICATION (Optional)                        │   │
│  │    Verifies the reader is legitimate                            │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### 1. Session Encryption

**Purpose:** Protect all data exchanged between your phone and the reader from eavesdropping and tampering.

#### How It Works

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SESSION ENCRYPTION FLOW                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  STEP 1: Device Engagement                                              │
│  ─────────────────────────                                              │
│  📱 Phone generates ephemeral key pair:                                 │
│     • EDeviceKey.Priv (kept secret)                                     │
│     • EDeviceKey.Pub  (shared in engagement)                            │
│                                                                         │
│  STEP 2: Session Establishment                                          │
│  ────────────────────────────                                           │
│  📟 Reader generates ephemeral key pair:                                │
│     • EReaderKey.Priv (kept secret)                                     │
│     • EReaderKey.Pub  (sent to phone)                                   │
│                                                                         │
│  Both devices independently derive session keys using ECDH:             │
│                                                                         │
│     Phone:  EDeviceKey.Priv + EReaderKey.Pub → Shared Secret            │
│     Reader: EReaderKey.Priv + EDeviceKey.Pub → Same Shared Secret!      │
│                                                                         │
│  From shared secret, derive two keys:                                   │
│     • SKReader - Reader encrypts with this                              │
│     • SKDevice - Phone encrypts with this                               │
│                                                                         │
│  STEP 3: Session Data Exchange                                          │
│  ─────────────────────────────                                          │
│  All messages are encrypted with AES-256-GCM                            │
│                                                                         │
│  STEP 4: Session Termination                                            │
│  ───────────────────────────                                            │
│  Keys destroyed, channel closed                                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Session Key Derivation

Using HKDF (HMAC-based Key Derivation Function):

| Key | Parameters |
|-----|------------|
| **SKReader** | Hash: SHA-256, IKM: shared secret, salt: SHA-256(SessionTranscript), info: "SKReader", length: 32 bytes |
| **SKDevice** | Hash: SHA-256, IKM: shared secret, salt: SHA-256(SessionTranscript), info: "SKDevice", length: 32 bytes |

#### Encryption Details

| Parameter | Value |
|-----------|-------|
| **Algorithm** | AES-256-GCM |
| **IV (Initialization Vector)** | 12 bytes = Identifier (8 bytes) + Message Counter (4 bytes) |
| **Phone Identifier** | `0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01` |
| **Reader Identifier** | `0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00` |
| **Message Counter** | Starts at 1, increments with each message |
| **AAD** | Empty string |

> ⚠️ **Critical:** The message counter must NEVER be reused with the same key. This is why it increments with each message.

#### Session Messages

**Session Establishment (Reader → Phone):**
```javascript
SessionEstablishment = {
  "eReaderKey": EReaderKeyBytes,  // Reader's public key
  "data": [encrypted mdoc request]
}
```

**Session Data (bidirectional):**
```javascript
SessionData = {
  "data": [encrypted mdoc request or response],  // Optional
  "status": [status code]                         // Optional
}
```

#### Session Termination

Sessions end when:
- **Time-out:** No activity for 300+ seconds
- **Completion:** Either party doesn't want more requests
- **Error:** Encryption or decoding errors

**Status Codes:**

| Code | Meaning | Action |
|------|---------|--------|
| 10 | Session encryption error | Terminate session |
| 11 | CBOR decoding error | Terminate session |
| 20 | Session termination | Terminate session |

**When terminating:**
1. Destroy all session keys and ephemeral key material
2. Close the communication channel

---

### 2. Issuer Data Authentication

**Purpose:** Prove that mDL data came from the real issuing authority and hasn't been modified.

#### The Mobile Security Object (MSO)

The MSO is the heart of issuer data authentication. It contains:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    MOBILE SECURITY OBJECT (MSO)                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  MobileSecurityObject = {                                               │
│    version: "1.0",                                                      │
│    digestAlgorithm: "SHA-256",                                          │
│                                                                         │
│    valueDigests: {                // Hash of each data element          │
│      "org.iso.18013.5.1": {                                             │
│        0: [hash of family_name],                                        │
│        1: [hash of given_name],                                         │
│        2: [hash of birth_date],                                         │
│        ...                                                              │
│      }                                                                  │
│    },                                                                   │
│                                                                         │
│    deviceKeyInfo: {               // For mdoc authentication            │
│      deviceKey: [public key],                                           │
│      keyAuthorizations: {...}                                           │
│    },                                                                   │
│                                                                         │
│    docType: "org.iso.18013.5.1.mDL",                                    │
│                                                                         │
│    validityInfo: {                                                      │
│      signed: "2024-01-15T00:00:00Z",     // When signed                 │
│      validFrom: "2024-01-15T00:00:00Z",  // Valid start                 │
│      validUntil: "2024-07-15T00:00:00Z", // Valid end                   │
│      expectedUpdate: "2024-06-01T00:00:00Z"  // Optional                │
│    }                                                                    │
│  }                                                                      │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  The entire MSO is wrapped in a COSE_Sign1 structure (IssuerAuth)       │
│  and signed by the issuing authority's Document Signer certificate      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### How Selective Disclosure Works with MSO

This is the clever part! The MSO contains a **hash** of each data element, not the actual data.

```
┌─────────────────────────────────────────────────────────────────────────┐
│              SELECTIVE DISCLOSURE WITH MSO                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  MSO contains:                    You share:                            │
│  ──────────────                   ──────────                            │
│  hash(family_name + random)  →    family_name + random ✅               │
│  hash(given_name + random)   →    (not shared)                          │
│  hash(birth_date + random)   →    birth_date + random ✅                │
│  hash(portrait + random)     →    portrait + random ✅                  │
│  hash(address + random)      →    (not shared)                          │
│                                                                         │
│  Verifier can:                                                          │
│  1. Verify the MSO signature (proves it's from real DMV)                │
│  2. Hash each received element                                          │
│  3. Check that hashes match what's in the MSO                           │
│  4. Cannot learn ANYTHING about elements not shared!                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Why the random value?**

Each data element includes a random "salt" (minimum 16 bytes). Without this:
- If someone just hashes "male" or "female" for the sex field
- They could pre-compute all possible hashes
- And figure out values from the MSO alone!

The random salt prevents this - you can't verify a hash without knowing the salt.

#### Signature Algorithms for MSO

| Algorithm | Curves |
|-----------|--------|
| **ES256** (ECDSA + SHA-256) | P-256, brainpoolP256r1 |
| **ES384** (ECDSA + SHA-384) | P-384, brainpoolP320r1, brainpoolP384r1 |
| **ES512** (ECDSA + SHA-512) | P-521, brainpoolP512r1 |
| **EdDSA** | Ed25519, Ed448 |

#### Digest Algorithms

| Algorithm | Identifier |
|-----------|------------|
| SHA-256 | "SHA-256" |
| SHA-384 | "SHA-384" |
| SHA-512 | "SHA-512" |

#### Validity Info Timestamps

| Field | Meaning |
|-------|---------|
| `signed` | When the MSO was created |
| `validFrom` | When the MSO becomes valid (can be future-dated!) |
| `validUntil` | When the MSO expires |
| `expectedUpdate` | When the issuer plans to refresh the MSO |

> 💡 **Future-dated validFrom:** Useful when data is expected to change. For example, if someone turns 21 next week, you can pre-issue an MSO with age_over_21=TRUE that becomes valid on their birthday.

---

### 3. mdoc Authentication (Anti-Cloning)

**Purpose:** Prove that the mDL is on the original device, not a copy.

#### The Problem

What if someone:
1. Copies all the mDL data from your phone
2. Pastes it onto their phone
3. Presents it as their own?

The issuer signature would still be valid! The data hasn't changed.

#### The Solution: Device Key

When the issuing authority creates your mDL, they also:
1. Generate a key pair (SDeviceKey.Priv, SDeviceKey.Pub)
2. Store the **private key** securely on your device
3. Include the **public key** in the MSO (signed by the issuer)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    mdoc AUTHENTICATION                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  During presentation, your phone must prove it has SDeviceKey.Priv      │
│                                                                         │
│  Two methods:                                                           │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ METHOD A: MAC (Recommended for Privacy)                          │  │
│  │                                                                  │  │
│  │ Phone:  SDeviceKey.Priv + EReaderKey.Pub → EMacKey               │  │
│  │ Reader: EReaderKey.Priv + SDeviceKey.Pub → Same EMacKey!         │  │
│  │                                                                  │  │
│  │ Phone computes: HMAC(EMacKey, DeviceAuthenticationData)          │  │
│  │ Reader verifies: Can compute same HMAC                           │  │
│  │                                                                  │  │
│  │ ✅ Privacy benefit: Reader could have computed the same MAC,     │  │
│  │    so the phone can deny producing it (non-repudiation)          │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ METHOD B: ECDSA/EdDSA Signature                                  │  │
│  │                                                                  │  │
│  │ Phone signs: Sign(SDeviceKey.Priv, DeviceAuthenticationData)     │  │
│  │ Reader verifies: Using SDeviceKey.Pub from MSO                   │  │
│  │                                                                  │  │
│  │ ⚠️ Creates non-repudiable proof that phone signed specific data  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### What Gets Authenticated

The **DeviceAuthentication** structure:

```javascript
DeviceAuthentication = [
  "DeviceAuthentication",   // Literal string
  SessionTranscript,        // Binds to this specific session
  DocType,                  // Document type
  DeviceNameSpacesBytes     // Any device-signed data elements
]
```

**Why include SessionTranscript?**

It binds the authentication to THIS specific session. Even if someone records the MAC/signature, they can't replay it in a different session.

#### Key Authorizations

The MSO specifies what data the device key can sign:

```javascript
KeyAuthorizations = {
  nameSpaces: ["org.iso.18013.5.1.US"],  // Can sign entire namespaces
  dataElements: {                         // Or specific elements
    "org.iso.18013.5.1": ["webapi_info", "oidc_info"]
  }
}
```

> 🔒 **Rule:** A device key can ONLY be used for MAC OR signatures during its lifetime, never both.

---

### 4. mdoc Reader Authentication (Optional)

**Purpose:** Allow the mDL to verify that the reader is legitimate before releasing data.

#### How It Works

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    READER AUTHENTICATION                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Reader has:                                                            │
│  • Private key (kept secret)                                            │
│  • Certificate (sent to phone with request)                             │
│                                                                         │
│  ReaderAuthentication = [                                               │
│    "ReaderAuthentication",                                              │
│    SessionTranscript,      // Binds to this session                     │
│    ItemsRequestBytes       // The actual request being authenticated    │
│  ]                                                                      │
│                                                                         │
│  Reader signs ReaderAuthentication → ReaderAuth (COSE_Sign1)            │
│  Includes certificate in x5chain header                                 │
│                                                                         │
│  Phone can:                                                             │
│  1. Validate the certificate chain                                      │
│  2. Check what the reader is authorized to access                       │
│  3. Decide whether to release optional data elements                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Why This Matters

Remember the data release rules?
- Mandatory data: Available without reader authentication
- Optional data: mDL can require reader authentication first

This means a random reader can verify your licence is valid, but only **trusted readers** can access sensitive optional data like your address.

---

### 5. Session Transcript

The SessionTranscript ties everything together and prevents replay attacks:

```javascript
SessionTranscript = [
  DeviceEngagementBytes,  // Original engagement data
  EReaderKeyBytes,        // Reader's ephemeral public key
  Handover                // How engagement happened
]

// Handover depends on engagement method:
QRHandover = null
NFCHandover = [
  HandoverSelectMessage,   // Binary data from phone
  HandoverRequestMessage   // Binary from reader (null if static handover)
]
```

**Used in:**
- Session key derivation (salt)
- mdoc authentication
- Reader authentication

---

### 6. Supported Elliptic Curves

For Cipher Suite 1 (the only currently defined suite):

| Curve | Purpose | Standard |
|-------|---------|----------|
| **P-256** | ECDH, ECDSA | FIPS 186-4 |
| **P-384** | ECDH, ECDSA | FIPS 186-4 |
| **P-521** | ECDH, ECDSA | FIPS 186-4 |
| **X25519** | ECDH only | RFC 7748 |
| **X448** | ECDH only | RFC 7748 |
| **Ed25519** | EdDSA only | RFC 8032 |
| **Ed448** | EdDSA only | RFC 8032 |
| **brainpoolP256r1** | ECDH, ECDSA | RFC 5639 |
| **brainpoolP320r1** | ECDH, ECDSA | RFC 5639 |
| **brainpoolP384r1** | ECDH, ECDSA | RFC 5639 |
| **brainpoolP512r1** | ECDH, ECDSA | RFC 5639 |

> 📝 **Readers must support ALL curves.** Phones can choose which to use.

---

### 7. Server Retrieval Security

For server retrieval (Reader ↔ Issuing Authority), different mechanisms apply:

#### TLS (Transport Layer Security)

All server communication must use TLS with server authentication.

**Supported Versions:**
- TLS 1.2 (required)
- TLS 1.3 (optional)

**TLS 1.2 Cipher Suites:**

| Cipher Suite | Support |
|--------------|---------|
| TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | Required |
| TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 | Required |
| TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | Recommended |

**TLS 1.3 Cipher Suites:**

| Cipher Suite | Support |
|--------------|---------|
| TLS_AES_128_GCM_SHA256 | Required |
| TLS_AES_256_GCM_SHA384 | Recommended |
| TLS_CHACHA20_POLY1305_SHA256 | Recommended |

**Optional:** TLS client authentication (reader proves identity to server)

#### JWS (JSON Web Signature)

Server responses are protected with JWS:

**Supported Algorithms:**

| Algorithm | Description |
|-----------|-------------|
| ES256 | ECDSA with P-256 and SHA-256 |
| ES384 | ECDSA with P-384 and SHA-384 |
| ES512 | ECDSA with P-521 and SHA-512 |

**Requirements:**
- Certificate included in `x5c` header parameter
- JWS Compact Serialization
- No critical header parameters

---

### 8. Validation Procedures

#### Validating Issuer Data Authentication

The reader must verify:

1. ✅ **Certificate validation** - Is the DS certificate valid and trusted?
2. ✅ **Signature verification** - Does the MSO signature check out?
3. ✅ **Digest verification** - Does each received data element's hash match the MSO?
4. ✅ **DocType match** - Does the MSO docType match the response?
5. ✅ **Validity check:**
   - `signed` date is within certificate validity
   - Current time ≥ `validFrom`
   - Current time ≤ `validUntil`

#### Validating JWS (Server Retrieval)

1. ✅ **Certificate validation** - Is the JWS signer certificate valid?
2. ✅ **Algorithm check** - Is the `alg` parameter an allowed algorithm?
3. ✅ **Signature verification** - Is the signature valid?
4. ✅ **Time validation:**
   - Current time ≥ `iat` (issued at)
   - Current time ≤ `exp` (expiration)

#### Certificate Path Validation

For certificates issued under an IACA (Issuing Authority CA):

1. Apply RFC 5280 basic path validation
2. Verify `countryName` matches between IACA and target certificate
3. Verify `stateOrProvinceName` matches (if present in both)

---

### Security Summary: What Protects What

| Threat | Mechanism | How It Works |
|--------|-----------|--------------|
| **Eavesdropping** | Session encryption | AES-256-GCM with ephemeral keys |
| **Data tampering** | Session encryption + Issuer signatures | GCM authentication tag + MSO hashes |
| **Fake mDL** | Issuer data authentication | MSO signed by issuing authority |
| **Modified data** | Issuer data authentication | Hash of each element in MSO |
| **Cloned mDL** | mdoc authentication | Device must prove it has private key |
| **Replay attacks** | Session transcript | Unique per session |
| **Unauthorized access** | Close-range engagement | Must be physically present |
| **Rogue reader** | Reader authentication (optional) | Reader proves identity with certificate |
| **Server impersonation** | TLS | Server certificate validation |

---

*📝 This document will be updated as more sections of the specification are reviewed.*

---

## Certificate Profiles

Digital certificates are the foundation of trust in the mDL ecosystem. Think of certificates like official ID badges - they prove that a particular entity (person, server, or organization) is who they claim to be.

### The Certificate Hierarchy

The mDL system uses a **hierarchy of certificates** where one trusted "parent" certificate vouches for "child" certificates:

```
                    ┌─────────────────────────┐
                    │   IACA Root Certificate │  ← The "trust anchor"
                    │   (Issuing Authority)   │     Self-signed, trusted
                    └───────────┬─────────────┘
                                │
           ┌────────────────────┼────────────────────┐
           │                    │                    │
           ▼                    ▼                    ▼
    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │ Document    │     │ JWS Signer  │     │ TLS Server  │
    │ Signer Cert │     │ Certificate │     │ Certificate │
    └─────────────┘     └─────────────┘     └─────────────┘
           │                    │                    │
           ▼                    ▼                    ▼
    Signs mDL data       Signs server        Protects server
    (device retrieval)   responses           connections
```

### Types of Certificates

| Certificate Type | Purpose | Max Validity |
|-----------------|---------|--------------|
| **IACA Root** | Trust anchor for all other certificates | 20 years |
| **IACA Link** | Bridges old root to new root during key rotation | Until old root expires |
| **Document Signer** | Signs mDL data in device retrieval | 457 days (~15 months) |
| **JWS Signer** | Signs server retrieval responses | 457 days (~15 months) |
| **TLS Server** | Protects server connections | 822 days (~27 months) |
| **mdoc Reader Auth** | Identifies the reader (recommended) | 1,187 days (~39 months) |
| **TLS Client Auth** | Authenticates reader for server retrieval | 1,187 days (~39 months) |
| **OCSP Signer** | Signs certificate status responses | 90-457 days |

### IACA Root Certificate - The Trust Anchor

**IACA** stands for **Issuing Authority Certificate Authority**. This is the "boss certificate" that everyone trusts.

**Key characteristics:**
- **Self-signed**: Signs itself (no higher authority)
- **Country-specific**: Contains the ISO country code (e.g., "US", "DE")
- **Long-lived**: Up to 20 years validity
- **Signs all other certificates**: Every other certificate traces back to this one

**Real-world analogy**: Think of the IACA root certificate like a country's official government seal. When you see a document stamped with that seal, you trust it because you trust the government.

**What's in an IACA Root Certificate:**

```
┌────────────────────────────────────────────────────────────┐
│  IACA Root Certificate                                      │
├────────────────────────────────────────────────────────────┤
│  Version: 3                                                 │
│  Serial Number: Random 63+ bit number                       │
│  Issuer: countryName=US, commonName="DMV Authority"         │
│  Subject: (same as Issuer - self-signed)                   │
│  Valid: From 2024-01-01 To 2044-01-01 (up to 20 years)     │
│  Public Key: Elliptic Curve (P-256, P-384, P-521, or BP)   │
│  Key Usage: Certificate Signing, CRL Signing               │
│  Basic Constraints: CA=TRUE, pathLen=0                     │
│  CRL Distribution: https://example.gov/crl                 │
└────────────────────────────────────────────────────────────┘
```

### IACA Link Certificate - Smooth Key Rotation

When an IACA needs to create a new root certificate (called "re-keying"), they create a **link certificate** to maintain trust:

```
OLD IACA Root ──signs──▶ Link Certificate ──contains──▶ NEW IACA Root Public Key
     │                                                           │
     │                                                           │
     ▼                                                           ▼
Still trusted                                              Now also trusted
by existing mDLs                                           by existing mDLs
```

This allows a smooth transition - mDLs that only know the old root can still verify documents signed under the new root.

### Document Signer Certificate

This certificate signs the actual mDL data during **device retrieval**:

```
┌─────────────┐        ┌──────────────────┐        ┌─────────────┐
│  IACA Root  │──signs─▶│ Document Signer │──signs─▶│  Your mDL   │
│             │        │   Certificate    │        │    Data     │
└─────────────┘        └──────────────────┘        └─────────────┘
```

**Key points:**
- Maximum validity: **457 days** (about 15 months)
- Extended Key Usage: `1.0.18013.5.1.2` (mdlDS)
- Included in the `x5chain` element of IssuerAuth
- Short lifespan improves security - if compromised, damage is limited

**Security tip from the spec**: Issuing authorities should use certificates with short lifespans (a few weeks) so that if compromised, they can quickly revoke and reissue.

### JWS Signer Certificate

Used for **server retrieval** to sign JSON Web Signatures:

- Maximum validity: **457 days**
- Extended Key Usage: `1.0.18013.5.1.3` (mdlJWS)
- Included in the `x5c` parameter of the JWS

### TLS Server Certificate

Protects the connection to issuing authority servers:

- Maximum validity: **822 days** (about 27 months)
- Must include the server's **DNS name**
- Extended Key Usage: Server Authentication

### Reader Authentication Certificates

For verifying who is asking for your data:

**mdoc Reader Authentication Certificate:**
- Extended Key Usage: `1.0.18013.5.1.6` (mdlReaderAuth)
- Maximum validity: **1,187 days** (about 39 months)
- Optional but **recommended**

**TLS Client Certificate:**
- Extended Key Usage: `1.0.18013.5.1.9` (mdlTLSClientAuth)
- Maximum validity: **1,187 days**
- Used with server retrieval methods

### Supported Cryptographic Curves

All certificates use **elliptic curve cryptography**. Here are the supported curves:

| Curve | OID | Notes |
|-------|-----|-------|
| **P-256** | 1.2.840.10045.3.1.7 | Most common |
| **P-384** | 1.3.132.0.34 | Higher security |
| **P-521** | 1.3.132.0.35 | Highest security |
| brainpoolP256r1 | 1.3.36.3.3.2.8.1.1.7 | European alternative |
| brainpoolP320r1 | 1.3.36.3.3.2.8.1.1.9 | |
| brainpoolP384r1 | 1.3.36.3.3.2.8.1.1.11 | |
| brainpoolP512r1 | 1.3.36.3.3.2.8.1.1.13 | |
| **Ed25519** | 1.3.101.112 | Document Signer & Reader Auth only |
| **Ed448** | 1.3.101.113 | Document Signer & Reader Auth only |

### Certificate Revocation Lists (CRLs)

When a certificate is compromised or should no longer be trusted, it gets added to a **Certificate Revocation List**:

```
┌───────────────────────────────────────────────────────────┐
│                    CRL (Revocation List)                   │
├───────────────────────────────────────────────────────────┤
│  Issuer: IACA Root Certificate                            │
│  This Update: 2024-06-01                                  │
│  Next Update: 2024-08-30 (within 90 days)                │
│                                                           │
│  Revoked Certificates:                                    │
│  ┌─────────────────┬──────────────────┐                  │
│  │ Serial Number   │ Revocation Date  │                  │
│  ├─────────────────┼──────────────────┤                  │
│  │ 12345...        │ 2024-05-15       │                  │
│  │ 67890...        │ 2024-05-20       │                  │
│  └─────────────────┴──────────────────┘                  │
└───────────────────────────────────────────────────────────┘
```

**CRL Rules:**
- Must be updated at least every **90 days** (even if no revocations)
- When a certificate is revoked, new CRL must be issued within **48 hours**
- Contains serial numbers and revocation dates
- Signed by the IACA root certificate

### OCSP - Real-Time Certificate Status

**OCSP** (Online Certificate Status Protocol) provides real-time certificate validity checking:

```
┌──────────┐      "Is cert #12345 valid?"     ┌─────────────┐
│  Reader  │ ─────────────────────────────────▶│ OCSP Server │
│          │ ◀─────────────────────────────────│             │
└──────────┘         "Yes/No/Unknown"          └─────────────┘
```

The OCSP Signer certificate signs these responses and can have:
- **Short validity (90 days)** with no revocation checking needed, OR
- **Longer validity (457 days)** with its own CRL

### Certificate Validation Flow

When an mDL reader receives a certificate chain, here's how validation works:

```
Step 1: Check Certificate Chain
┌─────────────────────────────────────────────────────────────┐
│  Start with trusted IACA root certificate                   │
│                        │                                    │
│                        ▼                                    │
│  Verify signature on Document Signer certificate            │
│  - Was it signed by the IACA root? ✓                       │
│  - Is it not expired? ✓                                    │
│  - Is it not revoked? ✓                                    │
│  - Does country code match? ✓                              │
│  - Is Extended Key Usage correct? ✓                        │
└─────────────────────────────────────────────────────────────┘

Step 2: Check CRL
┌─────────────────────────────────────────────────────────────┐
│  Get latest CRL (may be cached)                             │
│                        │                                    │
│                        ▼                                    │
│  Verify CRL signature (must match IACA root)                │
│                        │                                    │
│                        ▼                                    │
│  Search for certificate serial number in CRL                │
│  - Found? Certificate is REVOKED ✗                         │
│  - Not found? Certificate is VALID ✓                       │
└─────────────────────────────────────────────────────────────┘
```

### Extended Key Usage OIDs

The standard defines specific **Object Identifiers (OIDs)** for mDL certificates:

| OID | Meaning | Used By |
|-----|---------|---------|
| `1.0.18013.5.1.2` | mDL Document Signer | Signs device retrieval data |
| `1.0.18013.5.1.3` | mDL JWS Signer | Signs server retrieval responses |
| `1.0.18013.5.1.4` | mDL IACA Link | Links old root to new root |
| `1.0.18013.5.1.6` | mDL Reader Auth | Reader authentication |
| `1.0.18013.5.1.7` | mDL IACA | IACA root certificate |
| `1.0.18013.5.1.9` | mDL TLS Client Auth | Reader TLS authentication |

### Forbidden Certificate Extensions

The following extensions **shall NOT be used** in mDL certificates:
- PolicyMappings
- NameConstraints
- PolicyConstraints
- InhibitAnyPolicy
- FreshestCRL

### Key Certificate Rules Summary

| Rule | Requirement |
|------|-------------|
| **Encoding** | All certificates must be DER encoded |
| **Serial Numbers** | Random, at least 63 bits from CSPRNG |
| **Country Code** | Must match between IACA and end-entity certificates |
| **State/Province** | If in IACA, must be in end-entity certificates too |
| **Public Keys** | Uncompressed form (except Ed25519/Ed448) |
| **Subject Key ID** | SHA-1 hash of public key |

---

## VICAL - The Trust List

### The Problem: Who Do You Trust?

Imagine you're a bar in California and someone shows you a digital driver's license from Germany. How do you know the German DMV's certificate is legitimate? Unlike passports (where ICAO maintains a central list), there's no single global organization managing all mDL issuers.

**VICAL** (Verified Issuer Certificate Authority List) solves this problem.

### What is VICAL?

VICAL is like a **phonebook of trusted certificate authorities**. It's a signed list that says "these are the legitimate issuing authorities and their certificates."

```
┌─────────────────────────────────────────────────────────────┐
│                         VICAL                                │
│              "The Trust List for mDLs"                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │  🇺🇸 USA DMV     │  │  🇩🇪 Germany     │                  │
│  │  IACA Cert #1   │  │  IACA Cert #1   │                  │
│  └─────────────────┘  └─────────────────┘                  │
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │  🇫🇷 France      │  │  🇯🇵 Japan       │                  │
│  │  IACA Cert #1   │  │  IACA Cert #1   │                  │
│  └─────────────────┘  └─────────────────┘                  │
│                                                             │
│  ... and more countries/jurisdictions                       │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  Signed by: VICAL Provider                                  │
│  Date: 2024-06-01                                           │
│  Next Update: 2024-08-30                                    │
└─────────────────────────────────────────────────────────────┘
```

### How VICAL Works

```
┌──────────────────┐         ┌──────────────────┐
│ Issuing Authority│         │ Issuing Authority│
│    (Country A)   │         │    (Country B)   │
└────────┬─────────┘         └────────┬─────────┘
         │ Submit IACA cert           │
         │                            │
         ▼                            ▼
    ┌─────────────────────────────────────┐
    │         VICAL Provider              │
    │                                     │
    │  1. Verify identity of authority    │
    │  2. Validate certificates           │
    │  3. Compile into signed list        │
    │  4. Distribute to subscribers       │
    └──────────────────┬──────────────────┘
                       │
         ┌─────────────┼─────────────┐
         │             │             │
         ▼             ▼             ▼
    ┌─────────┐   ┌─────────┐   ┌─────────┐
    │Subscriber│   │Subscriber│   │Subscriber│
    │  (App)   │   │ (Reader)│   │(Service)│
    └─────────┘   └─────────┘   └─────────┘
         │             │             │
         └─────────────┼─────────────┘
                       │
                       ▼
              Relying Parties
           (Verify mDLs using
            the trust list)
```

### Key Participants

| Participant | Role | Example |
|-------------|------|--------|
| **VICAL Provider** | Creates, maintains, and distributes the trust list | A government agency or trusted organization |
| **Issuing Authority** | Submits their IACA certificates for inclusion | State DMV, national transport ministry |
| **Point of Contact** | Official representative who communicates with VICAL Provider | Designated official at the DMV |
| **Subscriber** | Receives the VICAL from the provider | App developers, verification services |
| **Relying Party** | Uses the VICAL to verify mDLs | Bar, airport security, police |

### VICAL Structure

The VICAL is encoded in CBOR and contains:

```
VICAL Contents:
┌─────────────────────────────────────────────────────────────┐
│  version: "1.0"           ← Structure version               │
│  vicalProvider: "Example Trust Service"                     │
│  date: 2024-06-01         ← When this VICAL was created    │
│  vicalIssueID: 42         ← Unique, always increasing      │
│  nextUpdate: 2024-08-30   ← Expect new version by this date│
│                                                             │
│  certificateInfos: [      ← List of trusted certificates   │
│    {                                                        │
│      certificate: <DER bytes>   ← The actual certificate   │
│      serialNumber: 12345                                    │
│      ski: <subject key ID>                                  │
│      docType: ["org.iso.18013.5.1.mDL"]  ← For mDLs        │
│      certificateProfile: ["1.0.18013.5.1.7"]  ← IACA type  │
│      issuingAuthority: "California DMV"                     │
│      issuingCountry: "US"                                   │
│      stateOrProvinceName: "California"  ← Optional         │
│      notBefore: 2024-01-01                                  │
│      notAfter: 2044-01-01                                   │
│    },                                                       │
│    { ... more certificates ... }                            │
│  ]                                                          │
└─────────────────────────────────────────────────────────────┘
│                                                             │
│  SIGNED with COSE_Sign1 by VICAL Provider                   │
└─────────────────────────────────────────────────────────────┘
```

### Identity Verification - The Critical First Step

Before adding an issuing authority to the VICAL, the provider must **verify their identity**. This is crucial - a fake authority in the list would compromise the entire system.

**How verification works:**

1. **Check legitimacy** through:
   - Official government sources
   - Regional associations of issuing authorities
   - International conventions
   - References from already-trusted authorities

2. **Establish secure communication:**
   - Contact the authority's official point of contact
   - Set up a trusted communication channel
   - Exchange sensitive material out-of-band (not over email!)

3. **Maintain the relationship:**
   - Regularly verify the point of contact is still valid
   - Update communication channels as needed

### VICAL Lifecycle Operations

| Operation | What Happens |
|-----------|-------------|
| **Application** | IA submits certificate for inclusion |
| **Processing** | VICAL Provider validates all information |
| **Acceptance** | Certificate added to VICAL |
| **Re-key** | New certificate with new key (treated as new application) |
| **Modification** | Changed certificate (treated as new application) |
| **Suspension** | Certificate temporarily removed |
| **Removal** | Certificate permanently removed |

**Important:** Certificate **renewal** (same key, extended validity) is **NOT allowed**.

### Security Requirements for VICAL Providers

VICAL Providers must meet strict security standards:

#### Physical Security
- Equipment in physically secured areas
- Access limited to authorized personnel
- Intrusion detection and alarms
- Entry/exit logging

#### Key Management
- Signing keys generated in secure cryptographic devices
- **Dual control** required (at least 2 people)
- Hardware must meet **EAL 4+** (ISO/IEC 15408) or **FIPS 140-2 Level 3**
- Keys destroyed when no longer needed

#### Personnel Controls
- Background checks for trusted roles
- Regular security training
- Separation of duties
- Named trusted roles:
  - Security Officers
  - System Administrators  
  - System Operators
  - System Auditors

#### Audit Requirements
- Log all significant events
- Retain records for **at least 7 years**
- Time synchronized to UTC (within 3 minutes)
- Regular vulnerability scans
- Penetration testing

### VICAL Updates

```
         ┌─────────────────────────────────────┐
         │        VICAL Update Rules           │
         ├─────────────────────────────────────┤
         │                                     │
         │  Regular updates:                   │
         │  • At least every 90 days           │
         │                                     │
         │  Emergency updates:                 │
         │  • Within 48 hours of compromise    │
         │                                     │
         │  Key changeover:                    │
         │  • Notify all subscribers           │
         │  • Provide new key securely         │
         │  • May use key rollover certs       │
         │                                     │
         └─────────────────────────────────────┘
```

### VICAL Signer Certificate

The VICAL is signed by the provider's certificate:

| Field | Value |
|-------|-------|
| **Max Validity** | 1,187 days (~39 months) |
| **Extended Key Usage** | `1.0.18013.5.1.8` (mdlVICAL) |
| **Key Usage** | Non-repudiation = 1 |
| **Curves** | P-256, P-384, P-521, or brainpool variants |
| **Signature** | ECDSA with SHA-256/384/512 |

### Disaster Recovery & Termination

**If the VICAL Provider's key is compromised:**
1. Notify all issuing authorities and subscribers
2. Indicate affected VICALs may no longer be valid
3. Generate new keys and distribute securely

**If the VICAL Provider terminates:**
1. Notify all participants
2. Transfer records to a reliable party
3. Destroy all private keys
4. If possible, arrange transfer to another provider
5. Maintain public key availability for relying parties

### Multiple VICAL Providers

The standard **does not require a single VICAL provider**. In reality:

```
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ VICAL Provider A│   │ VICAL Provider B│   │ VICAL Provider C│
│   (Regional)    │   │   (National)    │   │   (Private)     │
└────────┬────────┘   └────────┬────────┘   └────────┬────────┘
         │                     │                     │
         │                     │                     │
         └─────────────────────┼─────────────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Relying Party    │
                    │                     │
                    │ May combine multiple│
                    │ VICALs for broader  │
                    │ coverage            │
                    └─────────────────────┘
```

Relying parties may need to use **multiple VICALs** from different providers to get complete coverage of all issuing authorities.

### Compliance & Auditing

VICAL Providers should:

- Conduct **self-audits yearly** (minimum)
- Consider third-party audits based on:
  - **ISO/IEC 27001** (Information Security Management)
  - **ISO/IEC 27002** (Security Controls)
- Implement an **Information Security Management System (ISMS)**
- Make audit results available to stakeholders

### Why VICAL Matters

| Without VICAL | With VICAL |
|--------------|------------|
| Each reader must manually trust each country's certificate | Single trusted list covers many countries |
| No standardized way to distribute trust | Consistent, signed distribution mechanism |
| Difficult to verify foreign mDLs | Easy cross-border verification |
| No accountability for trust decisions | Audited, documented trust process |

---

## Key Terms Explained

Understanding the vocabulary is crucial. Here's a simple breakdown of the main terms:

### The Devices

| Term | Simple Explanation |
|------|-------------------|
| **Mobile Device** | Your smartphone or tablet - any portable device you can carry, that has a screen, battery, storage, and can communicate wirelessly |
| **mdoc** | Any document or app that lives on a mobile device (mDL is one type of mdoc) |
| **mDL** | A Mobile Driving Licence - your driving licence in digital form on your phone |

### The People

| Term | Who Are They? |
|------|---------------|
| **mdoc Holder** | You! The person who the digital document belongs to |
| **mDL Holder** | The person who owns the mobile driving licence (the legitimate driver) |
| **mdoc/mDL Verifier** | The person or organization checking your document (e.g., a police officer, bouncer, car rental clerk) |

### The Readers

| Term | What Is It? |
|------|-------------|
| **mdoc Reader** | A device that can scan and read digital documents from your phone |
| **mDL Reader** | Specifically, a reader designed to check mobile driving licences |

### The Authorities

| Term | What They Do |
|------|--------------|
| **Licensing Authority** | The organization that issues driving licences (like your local DMV, Ministry of Transport, or equivalent) |
| **Issuing Country** | The country where your licence was issued |
| **Issuing Authority** | Either the licensing authority OR the country itself (if there's no separate licensing body) |
| **Issuing Authority Infrastructure** | All the computer systems and networks controlled by the issuing authority |
| **Issuing Authority CA** | The "Certificate Authority" - a trusted system that creates digital certificates to prove licences are genuine |

### How Data is Retrieved

There are two ways to get mDL data:

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEVICE RETRIEVAL                             │
│  ┌──────────┐         direct          ┌──────────────┐         │
│  │  Your    │ ───────────────────────▶│   Reader     │         │
│  │  Phone   │    (NFC, Bluetooth)     │   Device     │         │
│  └──────────┘                         └──────────────┘         │
│                                                                 │
│  → Data goes directly from your phone to the reader            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    SERVER RETRIEVAL                             │
│  ┌──────────┐                         ┌──────────────┐         │
│  │  Your    │ ── gives token ───────▶ │   Reader     │         │
│  │  Phone   │                         │   Device     │         │
│  └──────────┘                         └──────┬───────┘         │
│                                              │                  │
│                                              ▼                  │
│                                    ┌──────────────────┐        │
│                                    │  DMV Server      │        │
│                                    │  (Issuing Auth)  │        │
│                                    └──────────────────┘        │
│                                                                 │
│  → Reader uses a token to fetch data from the DMV's servers    │
└─────────────────────────────────────────────────────────────────┘
```

| Term | What It Means |
|------|---------------|
| **Device Retrieval** | Data is pulled directly from your phone to the reader (phone-to-reader only) |
| **Server Retrieval** | The reader contacts the issuing authority's servers to get/verify data |
| **Server Retrieval Token** | A special code that identifies you and your mDL to the issuing authority |

### NFC Modes

When using NFC (tap-to-share), your phone can operate in two modes:

| Mode | What It Means |
|------|---------------|
| **PCD Mode** | Your phone acts as the "reader" (like a payment terminal) |
| **PICC Mode** | Your phone acts as the "card" being read (like a contactless credit card) |

---

## Common Abbreviations

Here's a quick reference for the acronyms you'll encounter:

### Communication & Connectivity
| Abbreviation | Full Term | What It Is |
|--------------|-----------|------------|
| **NFC** | Near Field Communication | Tap-to-share technology (like Apple Pay) |
| **BLE** | Bluetooth Low Energy | Low-power Bluetooth for short-range communication |
| **RF** | Radiofrequency | The wireless signals used for communication |
| **MTU** | Maximum Transmission Unit | The largest chunk of data that can be sent at once |

### Data Formats
| Abbreviation | Full Term | What It Is |
|--------------|-----------|------------|
| **CBOR** | Concise Binary Object Representation | A compact way to encode data (like JSON but smaller) |
| **JSON** | JavaScript Object Notation | A common text format for data |
| **CDDL** | Concise Data Definition Language | A language to describe data structures |

### Security & Encryption
| Abbreviation | Full Term | What It Is |
|--------------|-----------|------------|
| **AES** | Advanced Encryption Standard | A method to encrypt (scramble) data securely |
| **ECDSA** | Elliptic Curve Digital Signature Algorithm | A way to create digital signatures |
| **ECDH** | Elliptic Curve Diffie-Hellman | A method for two parties to create a shared secret key |
| **SHA** | Secure Hash Algorithm | Creates a unique "fingerprint" of data |
| **HMAC** | Hash-based Message Authentication Code | Verifies data hasn't been tampered with |
| **TLS** | Transport Layer Security | Encrypts data sent over the internet (the "S" in HTTPS) |

### Certificates & Trust
| Abbreviation | Full Term | What It Is |
|--------------|-----------|------------|
| **CA** | Certificate Authority | An organization that issues digital certificates |
| **PKI** | Public Key Infrastructure | The system of certificates and keys that enable secure communication |
| **IACA** | Issuing Authority Certificate Authority | The CA run by the licence issuer |
| **VICAL** | Verified Issuer Certificate Authority List | A list of trusted certificate authorities |
| **CRL** | Certificate Revocation List | A list of certificates that are no longer valid |
| **OCSP** | Online Certificate Status Protocol | A way to check if a certificate is still valid in real-time |

### Tokens & Web Standards
| Abbreviation | Full Term | What It Is |
|--------------|-----------|------------|
| **JWT** | JSON Web Token | A secure way to transmit information as a JSON object |
| **JWK** | JSON Web Key | A JSON format for cryptographic keys |
| **JWS** | JSON Web Signature | A signed JWT |
| **OIDC** | OpenID Connect | An identity layer on top of OAuth 2.0 |

### Other Key Terms
| Abbreviation | Full Term | What It Is |
|--------------|-----------|------------|
| **MSO** | Mobile Security Object | Contains security info and the issuer's signature |
| **DS** | Document Signer | The entity that digitally signs the document |
| **IDL** | ISO-compliant Driving Licence | The traditional physical driving licence |
| **MITM** | Man-in-the-Middle Attack | When someone secretly intercepts communication between two parties |
| **UUID** | Universally Unique Identifier | A unique ID that won't clash with any other |
| **URI/URL** | Uniform Resource Identifier/Locator | A web address |
| **UTC** | Coordinated Universal Time | The world's time standard |
| **RFU** | Reserved for Future Use | Placeholder for future features |
