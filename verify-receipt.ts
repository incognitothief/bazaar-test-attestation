#!/usr/bin/env bun
/**
 * Bazaar — Purchase Receipt Verifier
 *
 * Verifies a purchase.receipt on a buyer's ATProto PDS without contacting
 * the Bazaar backend. Uses only public HTTP endpoints.
 *
 * Usage:
 *   bun run verify-receipt.ts <buyerHandle> <itemUri>
 *
 * Example:
 *   bun run verify-receipt.ts ranger.whereditgo.diamonds \
 *     at://did:plc:abc123.../diamonds.whereditgo.bazaar.catalog.item.digital/3kx7...
 *
 * Dependencies (bun add @noble/curves @scure/base):
 *   @noble/curves — P-256 signature verification
 *   @scure/base   — base58btc decoding for multikey public keys
 */

import { createHash } from "node:crypto";
import { p256 } from "@noble/curves/p256";
import { base58 } from "@scure/base";

const RECEIPT_COLLECTION = "diamonds.whereditgo.bazaar.purchase.receipt";
const COLLECTION_TYPE = "diamonds.whereditgo.bazaar.catalog.collection";

// ─── Types ───────────────────────────────────────────────────────────────────

interface Receipt {
  purchasedAt: string;
  paymentRef: string;
  item: { uri: string; itemType: string };
  listingCid: string;
  buyerDid: string;
  appDid: string;
  appSig: string;
  kid?: string;
  pricePaid?: { amount: number; currency: string };
  licenseGrantCid?: string;
}

interface VerificationMethod {
  id: string;
  type: string;
  publicKeyMultibase?: string;
}

// ─── Step 1: Resolve handle → DID ────────────────────────────────────────────

async function resolveHandle(handle: string): Promise<string> {
  // Try DNS TXT record first via API
  const res = await fetch(
    `https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=${handle}`,
  );
  if (!res.ok) throw new Error(`Failed to resolve handle: ${handle}`);
  const { did } = await res.json();
  return did;
}

// ─── Step 2: Resolve DID → PDS URL ───────────────────────────────────────────

async function resolvePds(did: string): Promise<string> {
  let doc: any;

  if (did.startsWith("did:web:")) {
    const domain = did.slice("did:web:".length);
    const res = await fetch(`https://${domain}/.well-known/did.json`);
    if (!res.ok) throw new Error(`Failed to fetch DID document for ${did}`);
    doc = await res.json();
  } else {
    // did:plc — resolve via PLC directory
    const res = await fetch(`https://plc.directory/${did}`);
    if (!res.ok) throw new Error(`Failed to resolve DID via PLC: ${did}`);
    doc = await res.json();
  }

  const pds = doc.service?.find(
    (s: any) => s.type === "AtprotoPersonalDataServer",
  );
  if (!pds) throw new Error(`No PDS found in DID document for ${did}`);
  return pds.serviceEndpoint;
}

// ─── Step 3: Fetch receipts from PDS ─────────────────────────────────────────

async function fetchReceipts(
  pdsUrl: string,
  did: string,
): Promise<Array<{ uri: string; cid: string; value: Receipt }>> {
  const url = new URL(`${pdsUrl}/xrpc/com.atproto.repo.listRecords`);
  url.searchParams.set("repo", did);
  url.searchParams.set("collection", RECEIPT_COLLECTION);
  url.searchParams.set("limit", "100");

  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch receipts: ${res.status}`);
  const data = await res.json();
  return data.records ?? [];
}

// ─── Step 4: Find matching receipt ───────────────────────────────────────────

async function findReceipt(
  records: Array<{ uri: string; cid: string; value: Receipt }>,
  itemUri: string,
): Promise<{ uri: string; cid: string; value: Receipt } | null> {
  // Direct match
  const direct = records.find((r) => r.value.item.uri === itemUri);
  if (direct) return direct;

  // Collection match — check if any collection receipt covers the requested item
  const collectionReceipts = records.filter(
    (r) => r.value.item.itemType === COLLECTION_TYPE,
  );
  for (const record of collectionReceipts) {
    const collectionRes = await fetch(
      `https://bsky.social/xrpc/com.atproto.repo.getRecord?repo=${record.value.buyerDid}&collection=diamonds.whereditgo.bazaar.catalog.collection&rkey=${record.value.item.uri.split("/").pop()}`,
    ).catch(() => null);
    if (!collectionRes?.ok) continue;
    const collection = await collectionRes.json();
    const items: Array<{ uri: string }> = collection.value?.items ?? [];
    if (items.some((i) => i.uri === itemUri)) return record;
  }

  return null;
}

// ─── Step 5: Resolve Storefront DID → verification key ───────────────────────

async function resolveStorefrontKey(
  appDid: string,
  kid: string | undefined,
): Promise<VerificationMethod> {
  if (!appDid.startsWith("did:web:")) {
    throw new Error(`Storefront DID must be did:web, got: ${appDid}`);
  }
  const domain = appDid.slice("did:web:".length);
  const res = await fetch(`https://${domain}/.well-known/did.json`);
  if (!res.ok) throw new Error(`Failed to fetch Storefront DID document`);
  const doc = await res.json();

  const methods: VerificationMethod[] = doc.verificationMethod ?? [];

  // Prefer key matching kid hint
  if (kid) {
    const keyId = `${appDid}#${kid}`;
    const match = methods.find((m) => m.id === keyId);
    if (match) return match;
    console.warn(`    ⚠ kid "${kid}" not found, trying all keys`);
  }

  // Fallback: try assertionMethod key
  const assertionRef: string | undefined = doc.assertionMethod?.[0];
  if (assertionRef) {
    const match = methods.find((m) => m.id === assertionRef);
    if (match) return match;
  }

  // Last resort: first key
  if (methods[0]) return methods[0];
  throw new Error("No verification key found in Storefront DID document");
}

// ─── Step 6: Decode multikey (multibase base58btc + multicodec) ───────────────

function decodeMultikey(publicKeyMultibase: string): Uint8Array {
  if (!publicKeyMultibase.startsWith("z")) {
    throw new Error("Expected multibase base58btc key (z prefix)");
  }
  // Strip multibase prefix 'z', then base58btc decode
  const bytes = base58.decode(publicKeyMultibase.slice(1));
  // Strip 2-byte multicodec prefix:
  //   p256-pub = 0x1200 → varint → [0x80, 0x24]
  // Remaining 33 bytes are the compressed P-256 public key
  return bytes.slice(2);
}

// ─── Step 7: Reconstruct canonical payload ────────────────────────────────────

function canonicalPayload(receipt: Receipt): Uint8Array {
  const str = [
    receipt.purchasedAt,
    receipt.paymentRef,
    receipt.item.uri,
    receipt.listingCid,
    receipt.buyerDid,
  ].join(":");
  return new Uint8Array(createHash("sha256").update(str).digest());
}

// ─── Step 8: Verify P-256 signature ──────────────────────────────────────────

function verifySignature(
  payloadHash: Uint8Array,
  appSig: string,
  publicKeyBytes: Uint8Array,
): boolean {
  // appSig is base64url-encoded compact (r||s) P-256 signature
  const sigBytes = Buffer.from(appSig, "base64url");
  try {
    return p256.verify(sigBytes, payloadHash, publicKeyBytes, { lowS: false });
  } catch {
    // Some signers produce low-S normalised signatures — retry without constraint
    try {
      return p256.verify(sigBytes, payloadHash, publicKeyBytes);
    } catch {
      return false;
    }
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const [buyerHandle, itemUri] = process.argv.slice(2);
  if (!buyerHandle || !itemUri) {
    console.error("Usage: bun run verify-receipt.ts <buyerHandle> <itemUri>");
    process.exit(1);
  }

  console.log();

  // 1. Resolve handle
  console.log(`[1] Resolving buyer DID for ${buyerHandle}...`);
  const buyerDid = await resolveHandle(buyerHandle);
  console.log(`    → ${buyerDid}`);

  // 2. Resolve PDS
  console.log(`[2] Fetching receipts from PDS...`);
  const pdsUrl = await resolvePds(buyerDid);
  console.log(`    → ${pdsUrl}`);

  // 3. Fetch receipts
  const records = await fetchReceipts(pdsUrl, buyerDid);
  console.log(`    → ${records.length} receipt(s) found`);

  // 4. Find matching receipt
  console.log(`[3] Matching receipt for item...`);
  const record = await findReceipt(records, itemUri);
  if (!record) {
    console.log(
      `\n✗ NO RECEIPT — no matching receipt found for this item on ${buyerHandle}'s PDS`,
    );
    process.exit(1);
  }
  const receipt = record.value;
  console.log(`    → Found: purchased ${receipt.purchasedAt}`);

  // 5. Resolve Storefront DID
  console.log(`[4] Resolving Storefront DID (${receipt.appDid})...`);
  const keyMethod = await resolveStorefrontKey(receipt.appDid, receipt.kid);
  const kidLabel = receipt.kid ?? "(no kid — using active key)";
  console.log(`    → Key: ${kidLabel}`);

  if (!keyMethod.publicKeyMultibase) {
    throw new Error("Key has no publicKeyMultibase field");
  }

  // 6. Decode public key
  const publicKeyBytes = decodeMultikey(keyMethod.publicKeyMultibase);

  // 7. Reconstruct payload
  console.log(`[5] Reconstructing canonical payload...`);
  const payloadHash = canonicalPayload(receipt);
  console.log(
    `    → SHA-256: ${Buffer.from(payloadHash).toString("hex").slice(0, 16)}...`,
  );

  // 8. Verify
  console.log(`[6] Verifying signature...`);
  const valid = verifySignature(payloadHash, receipt.appSig, publicKeyBytes);

  console.log();
  if (valid) {
    const price = receipt.pricePaid
      ? `${receipt.pricePaid.amount} ${receipt.pricePaid.currency}`
      : "(price not in receipt)";
    console.log(`✓ VALID — receipt is genuine`);
    console.log(`  buyer:    ${receipt.buyerDid}`);
    console.log(`  item:     ${receipt.item.uri}`);
    console.log(`  paid:     ${price}`);
    console.log(`  license:  ${receipt.licenseGrantCid ?? "(none)"}`);
    console.log(`  signed:   ${receipt.purchasedAt}`);
    console.log(`  storefront: ${receipt.appDid}`);
  } else {
    console.log(`✗ INVALID — signature verification failed`);
    console.log(
      `  The receipt exists on ${buyerHandle}'s PDS but its signature does not verify.`,
    );
    console.log(
      `  This means the receipt was either fabricated or tampered with after issuance.`,
    );
    process.exit(1);
  }
  console.log();
}

main().catch((err) => {
  console.error("\n✗ ERROR:", err.message);
  process.exit(1);
});
