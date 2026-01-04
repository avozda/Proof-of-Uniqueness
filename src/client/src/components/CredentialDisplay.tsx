import { useState } from "react";
import type { VerifiableCredential } from "../lib/vc";

interface CredentialDisplayProps {
  credential: VerifiableCredential;
}

export function CredentialDisplay({ credential }: CredentialDisplayProps) {
  const [copiedVC, setCopiedVC] = useState(false);
  const [copiedCircuit, setCopiedCircuit] = useState(false);
  const [showCircuitInputs, setShowCircuitInputs] = useState(false);

  // Separate circuitInputs from the VC for display
  const { circuitInputs, ...vcWithoutCircuitInputs } = credential;

  const handleCopyVC = async () => {
    try {
      await navigator.clipboard.writeText(
        JSON.stringify(vcWithoutCircuitInputs, null, 2)
      );
      setCopiedVC(true);
      setTimeout(() => setCopiedVC(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  const handleCopyCircuitInputs = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(circuitInputs, null, 2));
      setCopiedCircuit(true);
      setTimeout(() => setCopiedCircuit(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  return (
    <div className="credential-display">
      {/* Verifiable Credential Section */}
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
        {JSON.stringify(vcWithoutCircuitInputs, null, 2)}
      </pre>

      {/* Circuit Inputs Section */}
      <div className="circuit-inputs-section">
        <div className="credential-header">
          <div className="credential-header-left">
            <span className="circuit-badge">ZK</span>
            <span className="vc-type">Circuit Inputs</span>
            <button
              className="toggle-button"
              onClick={() => setShowCircuitInputs(!showCircuitInputs)}
              type="button"
            >
              {showCircuitInputs ? "▼ Hide" : "▶ Show"}
            </button>
          </div>
          {showCircuitInputs && (
            <button
              className={`copy-button ${copiedCircuit ? "copied" : ""}`}
              onClick={handleCopyCircuitInputs}
              type="button"
            >
              {copiedCircuit ? (
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
          )}
        </div>
        {showCircuitInputs && (
          <pre className="credential-json circuit-inputs-json">
            {JSON.stringify(circuitInputs, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}

