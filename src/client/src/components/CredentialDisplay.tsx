import { useState } from "react";
import type { VerifiableCredential } from "../lib/vc";

interface CredentialDisplayProps {
  credential: VerifiableCredential;
}

export function CredentialDisplay({ credential }: CredentialDisplayProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(credential, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
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
          className={`copy-button ${copied ? "copied" : ""}`}
          onClick={handleCopy}
          type="button"
        >
          {copied ? (
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

