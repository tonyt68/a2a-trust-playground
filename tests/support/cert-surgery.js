/**
 * Certificate surgery for the negative tests: take a fixture, alter one
 * structure, re-sign under the anchor, and hand the validator something the
 * fixture script cannot express. Every function returns what it was given
 * (or a PEM) so calls chain; nothing here is used outside tests/.
 */
import { normalizeOid } from '../../src/x509.js';
import { toPem } from '../../src/mint.js';
import { privateKeyFromPem } from '../../src/crypto-sign.js';

/**
 * PKI.js renders the 2.25 arc as `2.25.{hex}`, which asn1js cannot re-encode.
 * Every extension gets its decimal OID back before the certificate is
 * serialised again.
 */
export function normalizeExtensionOids(cert) {
  for (const ext of cert.extensions ?? []) ext.extnID = normalizeOid(ext.extnID);
  return cert;
}

/** Drop every extension under `oid`, then add `replacement` if one is given. */
export function replaceExtension(cert, oid, replacement = null) {
  normalizeExtensionOids(cert);
  cert.extensions = cert.extensions.filter((e) => e.extnID !== oid);
  if (replacement) cert.extensions.push(replacement);
  return cert;
}

/** Re-sign a (possibly altered) certificate and return its PEM. `key` is a PKCS#8 PEM or a CryptoKey. */
export async function resign(cert, key) {
  normalizeExtensionOids(cert);
  const privateKey = typeof key === 'string' ? await privateKeyFromPem(key) : key;
  await cert.sign(privateKey, 'SHA-256');
  return toPem(cert);
}
