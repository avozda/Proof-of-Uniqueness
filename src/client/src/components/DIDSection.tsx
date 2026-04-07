import { useState } from "react";
import { bigintToHex } from "../lib/did";
import type { DIDKeyPair } from "../lib/did";

interface DIDSectionProps {
  issuerDID: DIDKeyPair;
  onRegenerate: () => void;
}

export function DIDSection({ issuerDID, onRegenerate }: DIDSectionProps) {
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const copyToClipboard = (value: string, field: string) => {
    navigator.clipboard.writeText(value);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const pubKeyX = issuerDID.publicKey.x.toString();
  const pubKeyY = issuerDID.publicKey.y.toString();

  return (
    <section className="did-section">
      <div className="did-card">
        <div className="did-header">
          <div className="did-label">
            Issuer Decentralized Identifier (DID)
          </div>
          <button
            className="regenerate-button"
            onClick={onRegenerate}
            type="button"
          >
            Generate New
          </button>
        </div>
        <code className="did-value">{issuerDID.did}</code>
        <div className="did-details">
          <div className="detail-item">
            <span className="detail-label">Verification Method</span>
            <code>{issuerDID.verificationMethod}</code>
          </div>
          <div className="detail-item">
            <span className="detail-label">Public Key (Ax) - Hex</span>
            <code className="truncate">
              {bigintToHex(issuerDID.publicKey.x)}
            </code>
          </div>
          <div className="detail-item">
            <span className="detail-label">Public Key (Ay) - Hex</span>
            <code className="truncate">
              {bigintToHex(issuerDID.publicKey.y)}
            </code>
          </div>
        </div>

        <div className="uint256-section">
          <div className="uint256-header">
            <span className="uint256-label">
              Public Key (uint256 for Smart Contract)
            </span>
          </div>
          <div className="uint256-grid">
            <div className="uint256-item">
              <div className="uint256-row">
                <span className="uint256-field-label">pubKeyX:</span>
                <button
                  className={`copy-inline-btn ${copiedField === "x" ? "copied" : ""}`}
                  onClick={() => copyToClipboard(pubKeyX, "x")}
                  type="button"
                >
                  {copiedField === "x" ? "Copied" : "Copy"}
                </button>
              </div>
              <code className="uint256-value">{pubKeyX}</code>
            </div>
            <div className="uint256-item">
              <div className="uint256-row">
                <span className="uint256-field-label">pubKeyY:</span>
                <button
                  className={`copy-inline-btn ${copiedField === "y" ? "copied" : ""}`}
                  onClick={() => copyToClipboard(pubKeyY, "y")}
                  type="button"
                >
                  {copiedField === "y" ? "Copied" : "Copy"}
                </button>
              </div>
              <code className="uint256-value">{pubKeyY}</code>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
