import { useState } from "react";
import {
  useAccount,
  useConnect,
  useDisconnect,
  useWriteContract,
  useWaitForTransactionReceipt,
} from "wagmi";
import { injected } from "wagmi/connectors";
import { generateProof, verifyProof, parsePublicSignals } from "../lib/proof";
import type { ZKProof, ProofOutputs } from "../lib/proof";
import type { VerifiableCredential } from "../lib/vc";
import { proofOfUniquenessAbi } from "../lib/contractAbi";
import { CONTRACT_ADDRESSES, setContractAddress } from "../lib/wagmi";

interface ZKProofSectionProps {
  credential: VerifiableCredential;
}

export function ZKProofSection({ credential }: ZKProofSectionProps) {
  const [zkProof, setZkProof] = useState<ZKProof | null>(null);
  const [proofOutputs, setProofOutputs] = useState<ProofOutputs | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [proofVerified, setProofVerified] = useState<boolean | null>(null);
  const [proofError, setProofError] = useState<string | null>(null);
  const [contractAddress, setContractAddressInput] = useState(
    CONTRACT_ADDRESSES.proofOfUniqueness
  );

  // Wagmi hooks
  const { address, isConnected } = useAccount();
  const { connect, isPending: isConnecting } = useConnect();
  const { disconnect } = useDisconnect();
  const {
    writeContract,
    data: txHash,
    isPending: isSubmitting,
    error: submitError,
    reset: resetSubmit,
  } = useWriteContract();

  const { isLoading: isConfirming, isSuccess: isConfirmed } =
    useWaitForTransactionReceipt({
      hash: txHash,
    });

  const handleGenerateProof = async () => {
    setIsGenerating(true);
    setProofError(null);
    setZkProof(null);
    setProofOutputs(null);
    setProofVerified(null);
    resetSubmit();

    try {
      const proof = await generateProof(credential);
      setZkProof(proof);

      const outputs = parsePublicSignals(proof.publicSignals);
      setProofOutputs(outputs);

      const isValid = await verifyProof(proof);
      setProofVerified(isValid);
    } catch (err) {
      console.error("Error generating proof:", err);
      setProofError(
        err instanceof Error ? err.message : "Unknown error generating proof"
      );
    } finally {
      setIsGenerating(false);
    }
  };

  const handleConnectWallet = () => {
    connect({ connector: injected() });
  };

  const handleSubmitToContract = async () => {
    if (!zkProof || !proofVerified) return;

    setContractAddress(contractAddress);

    const proof = zkProof.proof;
    const publicSignals = zkProof.publicSignals;

    // Format proof for Solidity verifier (swap pi_b coordinate order)
    const pA: [bigint, bigint] = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];
    const pB: [[bigint, bigint], [bigint, bigint]] = [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ];
    const pC: [bigint, bigint] = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];

    const pubSignals: readonly [
      bigint,
      bigint,
      bigint,
      bigint,
      bigint,
      bigint,
      bigint,
      bigint
    ] = [
      BigInt(publicSignals[0]),
      BigInt(publicSignals[1]),
      BigInt(publicSignals[2]),
      BigInt(publicSignals[3]),
      BigInt(publicSignals[4]),
      BigInt(publicSignals[5]),
      BigInt(publicSignals[6]),
      BigInt(publicSignals[7]),
    ];

    try {
      writeContract({
        address: contractAddress,
        abi: proofOfUniquenessAbi,
        functionName: "enroll",
        args: [pA, pB, pC, pubSignals],
      });
    } catch (err) {
      console.error("Error submitting to contract:", err);
    }
  };

  const handleAddressChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setContractAddressInput(e.target.value as `0x${string}`);
  };

  return (
    <div className="proof-section">
      <h3>
        <span className="proof-icon">🔐</span>
        Zero-Knowledge Proof
      </h3>
      <p className="proof-description">
        Generate a ZK proof to verify your credential without revealing private
        data.
      </p>

      <button
        className="proof-button"
        onClick={handleGenerateProof}
        disabled={isGenerating}
        type="button"
      >
        {isGenerating ? (
          <>
            <span className="spinner" />
            Generating Proof...
          </>
        ) : (
          <>
            <span className="btn-icon">🛡️</span>
            Generate ZK Proof
          </>
        )}
      </button>

      {proofError && (
        <div className="proof-error">
          <span>❌</span> {proofError}
        </div>
      )}

      {zkProof && proofOutputs && (
        <div className="proof-result">
          <div className="proof-status">
            {proofVerified === true && (
              <span className="proof-verified">✓ Proof Verified</span>
            )}
            {proofVerified === false && (
              <span className="proof-invalid">✗ Proof Invalid</span>
            )}
          </div>

          <div className="proof-outputs">
            <h4>Public Outputs</h4>
            <div className="output-grid">
              <div className="output-item">
                <span className="output-label">Hash ID</span>
                <code>{proofOutputs.hashID}</code>
              </div>
              <div className="output-item">
                <span className="output-label">Issuer</span>
                <code>{proofOutputs.outIssuer}</code>
              </div>
              <div className="output-item">
                <span className="output-label">Valid Until</span>
                <code>{proofOutputs.outValidUntil}</code>
              </div>
              <div className="output-item">
                <span className="output-label">Sketch Hash</span>
                <code>{proofOutputs.outSketchHash}</code>
              </div>
              <div className="output-item">
                <span className="output-label">Verification Key</span>
                <code>
                  [{proofOutputs.outVerificationKey[0].slice(0, 20)}...,{" "}
                  {proofOutputs.outVerificationKey[1].slice(0, 20)}...]
                </code>
              </div>
              <div className="output-item">
                <span className="output-label">Signer Public Key</span>
                <code>
                  [{proofOutputs.outSignerPubKey[0].slice(0, 20)}...,{" "}
                  {proofOutputs.outSignerPubKey[1].slice(0, 20)}...]
                </code>
              </div>
            </div>
          </div>

          <div className="contract-section">
            <h4>
              <span className="contract-icon">📜</span>
              Submit to Smart Contract
            </h4>

            <div className="contract-address-input">
              <label htmlFor="contractAddress">Contract Address:</label>
              <input
                id="contractAddress"
                type="text"
                value={contractAddress}
                onChange={handleAddressChange}
                placeholder="0x..."
                className="address-input"
              />
            </div>

            {!isConnected ? (
              <button
                className="wallet-button connect"
                onClick={handleConnectWallet}
                disabled={isConnecting}
                type="button"
              >
                {isConnecting ? (
                  <>
                    <span className="spinner" />
                    Connecting...
                  </>
                ) : (
                  <>
                    <span className="btn-icon">🦊</span>
                    Connect MetaMask
                  </>
                )}
              </button>
            ) : (
              <div className="wallet-connected">
                <div className="wallet-info">
                  <span className="wallet-address">
                    Connected: {address?.slice(0, 6)}...{address?.slice(-4)}
                  </span>
                  <button
                    className="disconnect-btn"
                    onClick={() => disconnect()}
                    type="button"
                  >
                    Disconnect
                  </button>
                </div>

                <button
                  className="submit-button"
                  onClick={handleSubmitToContract}
                  disabled={
                    isSubmitting ||
                    isConfirming ||
                    !proofVerified ||
                    contractAddress ===
                      "0x0000000000000000000000000000000000000000"
                  }
                  type="button"
                >
                  {isSubmitting ? (
                    <>
                      <span className="spinner" />
                      Submitting...
                    </>
                  ) : isConfirming ? (
                    <>
                      <span className="spinner" />
                      Confirming...
                    </>
                  ) : (
                    <>
                      <span className="btn-icon">🚀</span>
                      Enroll Identity On-Chain
                    </>
                  )}
                </button>

                {submitError && (
                  <div className="tx-error">
                    <span>❌</span>{" "}
                    {submitError.message.includes("IssuerNotTrusted")
                      ? "Issuer not trusted. Add the issuer public key to the contract first."
                      : submitError.message.includes("IdentityAlreadyExists")
                        ? "This identity has already been enrolled."
                        : submitError.message}
                  </div>
                )}

                {txHash && (
                  <div className="tx-info">
                    <span className="tx-label">Transaction:</span>
                    <code className="tx-hash">{txHash}</code>
                  </div>
                )}

                {isConfirmed && (
                  <div className="tx-success">
                    <span>✅</span> Identity successfully enrolled on-chain!
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="proof-data">
            <h4>Complete Proof Package (for verification)</h4>
            <pre className="proof-json">
              {JSON.stringify(
                {
                  proof: zkProof.proof,
                  publicSignals: zkProof.publicSignals,
                },
                null,
                2
              )}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
