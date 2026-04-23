import { decodeErrorResult } from "viem";
import { identityRegistryAbi } from "./contractAbi";

/** First 4 bytes of keccak256 — used when decode fails but data is present */
const REVERT_SELECTOR_MESSAGES: Record<string, string> = {
  "0x6b410356": "This identity has already been enrolled on this contract.",
  "0x864f22fb":
    "Issuer not trusted. Register this issuer’s public key on the contract first.",
  "0x09bde339": "The ZK proof was rejected by the on-chain verifier.",
  "0x30cd7471":
    "Only the contract owner can perform this action. Connect the deployer wallet.",
  "0xd3c12856": "No identity record exists for this hash ID.",
  "0x0ce8eac5": "This identity credential has expired on-chain.",
  "0xa5f90a11": "Connect a wallet before enrolling this identity.",
  "0xdef8823b": "Wallet signature did not authorize this enrollment.",
  "0xa9615b40": "Wallet signature did not authorize this revocation.",
  "0x41888f68": "Revocation signature has expired. Sign a new revocation request.",
  "0x8baa579f": "Wallet signature is malformed or invalid.",
};

const ERROR_NAME_MESSAGES: Record<string, string> = {
  IdentityAlreadyExists: REVERT_SELECTOR_MESSAGES["0x6b410356"],
  IssuerNotTrusted: REVERT_SELECTOR_MESSAGES["0x864f22fb"],
  InvalidProof: REVERT_SELECTOR_MESSAGES["0x09bde339"],
  NotOwner: REVERT_SELECTOR_MESSAGES["0x30cd7471"],
  IdentityNotFound: REVERT_SELECTOR_MESSAGES["0xd3c12856"],
  IdentityExpired: REVERT_SELECTOR_MESSAGES["0x0ce8eac5"],
  InvalidPublicSignalLength:
    "Public signals length is invalid for this verifier.",
  InvalidFieldElement:
    "One or more public signals are outside the field modulus.",
  InvalidOprfMetadata: "Invalid OPRF public key configuration (zero coordinates).",
  UntrustedOprfPublicKey:
    "Proof uses an OPRF public key that is not trusted by this contract.",
  InvalidWalletAddress: REVERT_SELECTOR_MESSAGES["0xa5f90a11"],
  InvalidEnrollmentAuthorization: REVERT_SELECTOR_MESSAGES["0xdef8823b"],
  InvalidRevocationSignature: REVERT_SELECTOR_MESSAGES["0xa9615b40"],
  RevocationSignatureExpired: REVERT_SELECTOR_MESSAGES["0x41888f68"],
  InvalidSignature: REVERT_SELECTOR_MESSAGES["0x8baa579f"],
  InvalidNullifier: "Enrollment nullifier cannot be zero.",
  InvalidIssuerPublicKey: "Issuer public key coordinates cannot be zero.",
};

function isHexData(value: unknown): value is `0x${string}` {
  return (
    typeof value === "string" &&
    /^0x[0-9a-fA-F]+$/.test(value) &&
    value.length >= 10
  );
}

function extractRevertData(err: unknown, depth = 0): `0x${string}` | undefined {
  if (!err || typeof err !== "object" || depth > 12) return undefined;
  const o = err as Record<string, unknown>;

  if ("data" in o) {
    const d = o.data;
    if (isHexData(d)) return d;
    if (d && typeof d === "object") {
      const inner = (d as { data?: unknown }).data;
      if (isHexData(inner)) return inner;
    }
  }

  const details = o.details;
  if (typeof details === "string") {
    const m = details.match(/0x[0-9a-fA-F]{8,}/);
    if (m && isHexData(m[0])) return m[0] as `0x${string}`;
  }

  const message = o.message;
  if (typeof message === "string") {
    const m = message.match(/0x[0-9a-fA-F]{8,}/);
    if (m && isHexData(m[0])) return m[0] as `0x${string}`;
  }

  if ("cause" in o && o.cause !== undefined) {
    return extractRevertData(o.cause, depth + 1);
  }
  return undefined;
}

function deepFindHexData(value: unknown, depth = 0): `0x${string}` | undefined {
  if (depth > 10) return undefined;
  if (typeof value === "string") {
    const matches = value.match(/0x[0-9a-fA-F]{8,}/g);
    if (matches) {
      for (const h of matches) {
        if (isHexData(h)) return h as `0x${string}`;
      }
    }
    return undefined;
  }
  if (!value || typeof value !== "object") return undefined;
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = deepFindHexData(item, depth + 1);
      if (found) return found;
    }
    return undefined;
  }
  for (const v of Object.values(value)) {
    const found = deepFindHexData(v, depth + 1);
    if (found) return found;
  }
  return undefined;
}

function messageFromDecodedError(errorName: string): string | undefined {
  return ERROR_NAME_MESSAGES[errorName];
}

/**
 * Prefer decoded custom errors from revert data; avoid showing selector bytes mis-read as UTF-8.
 */
export function formatIdentityRegistryTxError(err: Error): string {
  const data = extractRevertData(err) ?? deepFindHexData(err);
  if (data) {
    try {
      const decoded = decodeErrorResult({
        abi: identityRegistryAbi,
        data,
      });
      const friendly = messageFromDecodedError(decoded.errorName);
      if (friendly) return friendly;
      return `Contract reverted: ${decoded.errorName}()`;
    } catch {
      const sel = data.slice(0, 10).toLowerCase();
      if (REVERT_SELECTOR_MESSAGES[sel]) return REVERT_SELECTOR_MESSAGES[sel];
    }
  }

  const short =
    "shortMessage" in err &&
    typeof (err as { shortMessage?: string }).shortMessage === "string"
      ? (err as { shortMessage: string }).shortMessage
      : null;
  const msg = short ?? err.message;

  if (msg.includes("IssuerNotTrusted") || msg.includes("0x864f22fb")) {
    return REVERT_SELECTOR_MESSAGES["0x864f22fb"];
  }
  if (msg.includes("IdentityAlreadyExists") || msg.includes("0x6b410356")) {
    return REVERT_SELECTOR_MESSAGES["0x6b410356"];
  }
  if (msg.includes("InvalidProof") || msg.includes("0x09bde339")) {
    return REVERT_SELECTOR_MESSAGES["0x09bde339"];
  }
  if (msg.includes("NotOwner") || msg.includes("0x30cd7471")) {
    return REVERT_SELECTOR_MESSAGES["0x30cd7471"];
  }
  if (msg.includes("IdentityNotFound")) {
    return ERROR_NAME_MESSAGES.IdentityNotFound;
  }
  if (msg.includes("IdentityExpired")) {
    return ERROR_NAME_MESSAGES.IdentityExpired;
  }
  if (msg.includes("InvalidPublicSignalLength")) {
    return ERROR_NAME_MESSAGES.InvalidPublicSignalLength;
  }
  if (msg.includes("InvalidFieldElement")) {
    return ERROR_NAME_MESSAGES.InvalidFieldElement;
  }
  if (msg.includes("InvalidOprfMetadata")) {
    return ERROR_NAME_MESSAGES.InvalidOprfMetadata;
  }
  if (msg.includes("UntrustedOprfPublicKey")) {
    return ERROR_NAME_MESSAGES.UntrustedOprfPublicKey;
  }
  if (msg.includes("InvalidWalletAddress")) {
    return ERROR_NAME_MESSAGES.InvalidWalletAddress;
  }
  if (msg.includes("InvalidEnrollmentAuthorization")) {
    return ERROR_NAME_MESSAGES.InvalidEnrollmentAuthorization;
  }
  if (msg.includes("InvalidRevocationSignature")) {
    return ERROR_NAME_MESSAGES.InvalidRevocationSignature;
  }
  if (msg.includes("RevocationSignatureExpired")) {
    return ERROR_NAME_MESSAGES.RevocationSignatureExpired;
  }
  if (msg.includes("InvalidSignature")) {
    return ERROR_NAME_MESSAGES.InvalidSignature;
  }
  if (msg.includes("InvalidPublicSignalLength")) {
    return ERROR_NAME_MESSAGES.InvalidPublicSignalLength;
  }
  if (msg.includes("InvalidFieldElement")) {
    return ERROR_NAME_MESSAGES.InvalidFieldElement;
  }
  if (msg.includes("InvalidOprfMetadata")) {
    return ERROR_NAME_MESSAGES.InvalidOprfMetadata;
  }

  if (
    /user rejected|user denied|denied transaction|rejected the request/i.test(
      msg,
    )
  ) {
    return "Request was rejected in the wallet.";
  }

  // RPCs sometimes append selector bytes as a bogus "reason" string — strip if it looks like binary junk
  const reasonMatch = msg.match(
    /reverted with (?:the following )?reason:\s*([\s\S]+?)(?:\n|$)/i,
  );
  if (reasonMatch) {
    const rawReason = reasonMatch[1].trim();
    const ctrl = [...rawReason].some((c) => {
      const code = c.charCodeAt(0);
      return code < 32 && c !== "\t";
    });
    const looksLikeSelectorUtf8 =
      rawReason.length <= 6 && /^[\P{Cc}]*$/u.test(rawReason)
        ? /^[!-.~]+$/u.test(rawReason) &&
          !/\s/.test(rawReason) &&
          rawReason.length < 12
        : ctrl;
    if (ctrl || looksLikeSelectorUtf8) {
      const hex = extractRevertData(err) ?? deepFindHexData(err);
      if (hex) {
        try {
          const decoded = decodeErrorResult({
            abi: identityRegistryAbi,
            data: hex,
          });
          const friendly = messageFromDecodedError(decoded.errorName);
          if (friendly) return friendly;
        } catch {
          const sel = hex.slice(0, 10).toLowerCase();
          if (REVERT_SELECTOR_MESSAGES[sel])
            return REVERT_SELECTOR_MESSAGES[sel];
        }
      }
      return "The transaction reverted on-chain (the RPC reported a garbled revert reason).";
    }
  }

  return msg;
}
