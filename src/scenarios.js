/**
 * Document manipulations shared by the page's buttons and the test suite.
 *
 * Every function here is a pure "document in, document changed" operation
 * over the JSON the editor holds. The buttons in app.js call these and then
 * validate; the unit and e2e tests call the same functions, so what is tested
 * is what the visitor presses.
 *
 * Two layers of issuance are deliberately visible here:
 *
 *   reissueThroughRegistry   the Registry's gates (§9.1, §9.2, §9.3, §10.1,
 *                            §19.2) — what a correct CA does
 *   issueRaw                 the CA key with no gate — what a compromised or
 *                            careless CA does, and what the relying party's
 *                            checks exist to catch
 */

import { Registry, issueCertificate, generateKeyPair, newAgentId, toPem, privateKeyToPem } from './mint.js';
import { signEnvelope, privateKeyFromPem } from './crypto-sign.js';
import { parseCertificate, parseTemplateExtension, parseSpawnExtension } from './x509.js';

export const agentsOf = (d) => (d.chain ?? []).filter((n) => n.role === 'agent');
export const childOf = (d) => agentsOf(d).find((n) => n.metadata?.parent_agent_id) ?? agentsOf(d)[1];
export const parentOf = (d) => agentsOf(d).find((n) => !n.metadata?.parent_agent_id) ?? agentsOf(d)[0];

/** The template inside a node's certificate — where authority actually lives. */
export const templateOf = (node) => parseTemplateExtension(parseCertificate(node.cert_pem));
export const spawnOf = (node) => parseSpawnExtension(parseCertificate(node.cert_pem));

/**
 * Re-issue an agent through the Registry the document carries, with a changed
 * template. Fresh keys, same identity — identity is the UUID, not the key. A
 * child is re-spawned, so it gets a fresh spawn nonce and timestamp.
 */
export async function reissueThroughRegistry(d, node, changes = {}, { now = new Date() } = {}) {
  const registry = await Registry.fromDocument(d, { now });
  const template = { ...templateOf(node), ...changes };
  const attested = await registry.attest(template);
  const parentId = node.metadata?.parent_agent_id ?? null;
  const issued = parentId
    ? await registry.spawn({ attested, parent: templateOf(parentOf(d)), now })
    : await registry.issue(attested, { now });
  node.cert_pem = issued.cert_pem;
  node.key_pem = issued.key_pem;
  return issued;
}

/**
 * Issue with the CA key directly, bypassing every gate.
 *
 * @param {object} d      the document
 * @param {object} node   the chain node to re-issue
 * @param {object} [opts]
 * @param {object} [opts.template]   member overrides for the Agent Template extension
 * @param {object|null} [opts.spawn] Agent Spawn members; `undefined` keeps the node's own, `null` removes it
 * @param {Date}   [opts.notBefore]
 * @param {Date}   [opts.notAfter]
 * @param {number[]} [opts.keyUsageBits]
 * @param {number} [opts.serialBytes]
 * @param {boolean} [opts.revocationSource]
 * @param {boolean} [opts.criticalExtensions]
 */
export async function issueRaw(d, node, { template = {}, spawn = undefined, ...opts } = {}) {
  const registry = await Registry.fromDocument(d);
  const merged = { ...templateOf(node), ...template };
  const keys = await generateKeyPair();
  const now = opts.notBefore ?? new Date();
  const cert = await issueCertificate({
    commonName: merged.subject, subjectPublicKey: keys.publicKey, issuer: registry.issuer,
    notBefore: now, notAfter: opts.notAfter ?? new Date(now.getTime() + merged.ttl_seconds * 1000),
    template: merged,
    spawn: spawn === undefined ? spawnOf(node) : spawn,
    keyUsageBits: opts.keyUsageBits ?? null, serialBytes: opts.serialBytes ?? 20,
    revocationSource: opts.revocationSource ?? true,
    criticalExtensions: opts.criticalExtensions ?? true,
  });
  node.cert_pem = await toPem(cert);
  node.key_pem = await privateKeyToPem(keys.privateKey);
  return cert;
}

/** Re-sign the policy envelope after editing its body, with both authority keys. */
export async function resignPolicy(d) {
  const ownerKey = await privateKeyFromPem(d.authorities.owner.key_pem);
  const paKey = await privateKeyFromPem(d.authorities.pa.key_pem);
  d.policy = await signEnvelope(d.policy.body, ownerKey, paKey, { withHash: true });
}

/**
 * Move the child to a partner organization and issue the grant that permits
 * the spawn (§13). The same Owner and Policy Authority sign for both
 * organizations here, which is the "federated CA" option of §13.3: both trust
 * one root, and this page holds every key.
 */
export async function spawnAcrossOrganizations(d, grantChanges = {}, { now = new Date() } = {}) {
  const c = childOf(d);
  const p = parentOf(d);
  await reissueThroughRegistry(d, c, { org_id: 'partner-org' }, { now });
  const childT = templateOf(c);
  const grantBody = {
    grantor: 'partner-org',
    grantee: templateOf(p).org_id,
    template: childT.subject,
    allowed_scopes: [...childT.allowed_scopes],
    issued_at: now.toISOString(),
    ttl_seconds: 3600,
    max_spawns: 3,
    ...grantChanges,
  };
  const ownerKey = await privateKeyFromPem(d.authorities.owner.key_pem);
  const paKey = await privateKeyFromPem(d.authorities.pa.key_pem);
  d.grant = await signEnvelope(grantBody, ownerKey, paKey);
  if (d.policy?.body) {
    d.policy.body.org_id = 'partner-org';
    await resignPolicy(d);
  }
  return d.grant;
}

/**
 * A second child issued under the FIRST child's nonce, with the CA key. The
 * relying party refuses the chain (§10.5: the Registry issues each nonce once).
 */
export async function issueSecondChildWithNonce(d) {
  const c = childOf(d);
  const second = JSON.parse(JSON.stringify(c));
  second.metadata.agent_id = newAgentId();
  const now = new Date();
  // The one member that must NOT be fresh: `spawn_nonce` is the first child's,
  // reused on purpose — that is the replay this scenario demonstrates.
  await issueRaw(d, second, {
    template: { subject: second.metadata.agent_id },
    spawn: { ...spawnOf(c), spawned_at: now.toISOString() },
    notBefore: now,
  });
  d.chain.push(second);
  return second;
}
