# How I read every secret in a "military-grade" encrypted pastebin — in ~2 hours

> **TL;DR:** A web app claimed "AES-256, military-grade encryption — the key is never stored in our database." I read every paste inside it in about two hours. **Four flags recovered, zero passwords cracked.** The problem wasn't the cipher — it was how the app used it.

---

## Who this is for

Anyone who trusts encryption *because it says "AES-256"*. AppSec engineers, penetration testers, and especially CISOs — this is why the words "military-grade" on a landing page are not a security control.

---

## The setup

I was testing a paste-sharing web app. Every paste was encrypted before storage, and the marketing copy made a point of it:

> *"Your data is encrypted with 128-bit AES. The key is never stored in our database."*

That *sounds* right. The key isn't stored, the data is encrypted at rest, the cipher is a real standard. On paper, nothing to see here.

The reality took ~2 hours to unravel.

---

## The flaw: a padding oracle

The app encrypted each paste with **AES in CBC mode** — and crucially, it **told me when my tampering broke the padding**.

That single difference — a server that *grades your guesses* — is the entire attack. When a CBC implementation reveals "valid padding" vs "invalid padding" through an error message, a timing difference, or a status code, an attacker can decrypt the ciphertext **without the key**, one byte at a time.

This is the **padding oracle attack** (CVE-class: CWE-696, the classic Vaudenay attack). It is real, scriptable, and shows up in production products — not just CTFs.

---

## The attack, step by step

### 1. Spot the leak

The app returned a paste as a long base64 string:

```
IV (16 bytes)  +  C1  +  C2  +  C3  ...  (ciphertext blocks)
```

Nothing wrong yet. This is just standard CBC framing — an initialization vector followed by the encrypted blocks.

### 2. Probe the oracle

I flipped bits in the ciphertext and watched the response:

- **Padding valid** → the app kept going.
- **Padding invalid** → the app threw a decryption error.

That yes/no signal is the oracle. Every request I sent was one "guess" the server silently graded for me.

### 3. Recover the plaintext, byte by byte

With that single bit of feedback, I recovered the full plaintext **byte-by-byte**, then forged my own valid ciphertext. The paste I "couldn't read" decoded into a JSON secret with a flag inside.

### 4. Pivot to the database

The same encrypted blob became a second vector. A classic **SQL injection** in the `id` field dumped a tracking table, which pointed me at another user's secret paste.

**Four flags total. Zero credentials cracked.**

---

## Why this matters for your work

### Encryption ≠ security

CBC is everywhere, and the way it's *wired* — who controls the IV, where the key lives, and especially **what errors leak** — decides whether it's a vault or a sieve. The cipher choice was fine. The *oracle* was the vulnerability.

### The padding oracle is real and scriptable

This is not academic. The exact bug class shows up in real products. If your app lets users touch ciphertext and tells them when padding fails, you've handed an attacker the key — **one byte at a time**.

### For CISOs

Fund pentests that look at **crypto usage**, not just "is it TLS?". The difference between *"we encrypt"* and *"our encryption is sound"* is exactly what an attacker tests first. A pentest that only checks for TLS and strong ciphers will miss a padding oracle every time.

---

## The one-line lesson

> If your app lets users touch ciphertext **and** tells them when the padding fails, you've handed over the key — one byte at a time.

---

## Tools

- **CBC padding-oracle script** — automated byte-by-byte recovery (Python).
- **Custom base64 decoder** — to split IV from ciphertext blocks.

*(PoC scripts to be published in a follow-up; redacted for the client until disclosure is complete.)*

---

## What's the most surprising crypto mistake you've seen in a real app?

Drop it in the comments — or [connect with me](https://www.linkedin.com/in/abioye-o). I'm Abioye, a DevSecOps & Security Engineer who writes about the stuff I actually break.

---

*Tags: `#Pentesting` `#BugBounty` `#OffensiveSecurity` `#AppSec` `#InfoSec` `#Cryptography`*
