import { useState } from "react";
import type { VerifiableCredential } from "../lib/vc";

interface CredentialDisplayProps {
  credential: VerifiableCredential;
}

export function CredentialDisplay({ credential }: CredentialDisplayProps) {
  const [copiedVC, setCopiedVC] = useState(false);

  const handleCopyVC = async () => {
    try {
      await navigator.clipboard.writeText(
        JSON.stringify(credential, null, 2)
      );
      setCopiedVC(true);
      setTimeout(() => setCopiedVC(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  return (
    <div className="credential-display">
      <div className="credential-header">
        <div className="credential-header-left">
          <span className="vc-badge">VC 2.0</span>
          <span className="vc-type">BiometricIdentityCredential</span>
        </div>
        <button
          className={`copy-button ${copiedVC ? "copied" : ""}`}
          onClick={handleCopyVC}
          type="button"
        >
          {copiedVC ? (
            <>
              <span className="copy-icon">✓</span>
              Copied!
            </>
          ) : (
            <>
              <span className="copy-icon">📋</span>
              Copy
            </>
          )}
        </button>
      </div>
      <pre className="credential-json">
        {JSON.stringify(credential, null, 2)}
      </pre>
    </div>
  );
}
