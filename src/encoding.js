/**
 * Byte encodings, defined once.
 *
 * Three things in this profile compare octets as text: the §11.6 content hash
 * (lowercase hex), the §3.1 key-distinctness test (hex of the SPKI), and the
 * §19.7 audit hash. Signatures and nonces travel as standard base64 (§3.1,
 * §19.2). One encoder for each, so the signer, the verifier and the display
 * cannot disagree about what "hex" or "base64" means.
 */

/** Lowercase hex, two digits per octet, no separators. */
export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Standard base64 with padding (RFC 4648 §4), as §3.1 requires for signatures. */
export function bytesToBase64(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}
