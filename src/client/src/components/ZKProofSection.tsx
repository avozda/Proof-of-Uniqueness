import { useState } from "react";
import {
  useAccount,
  useConnect,
  useDisconnect,
  useReadContract,
  useWaitForTransactionReceipt,
  useWriteContract,
} from "wagmi";
import { injected } from "wagmi/connectors";

import type { VerifiableCredential } from "../lib/vc";
import type { HolderKeyPair } from "../lib/holderKey";
import { identityRegistryAbi } from "../lib/contractAbi";
import { formatIdentityRegistryTxError } from "../lib/contractErrors";
import { CONTRACT_ADDRESSES } from "../lib/wagmi";
import {
  buildVcOprfEnrollmentProofPackage,
  type OprfNetworkConfig,
  type VcOprfEnrollmentProofPackage,
} from "../lib/oprfEnrollment";

interface ZKProofSectionProps {
  credential: VerifiableCredential;
  issuerPublicKey: { x: bigint; y: bigint };
  holderKeyPair: HolderKeyPair;
}

export function ZKProofSection({
  credential,
  issuerPublicKey,
  holderKeyPair,
}: ZKProofSectionProps) {
  const [isGenerating, setIsGenerating] = useState(false);
  const [proofError, setProofError] = useState<string | null>(null);
  const [generationStatus, setGenerationStatus] = useState<string | null>(null);
  const [proofPackage, setProofPackage] =
    useState<VcOprfEnrollmentProofPackage | null>(null);

  const contractAddress = CONTRACT_ADDRESSES.identityRegistry;
  const networkConfig: OprfNetworkConfig = {
    nodeBases: ["http://127.0.0.1:10000", "http://127.0.0.1:10001", "http://127.0.0.1:10002"],
    threshold: 2,
    apiKey: "test",
    authModule: "vc-ownership",
  };

  const contractAddressValid =
    /^0x[a-fA-F0-9]{40}$/.test(contractAddress) &&
    contractAddress !== "0x0000000000000000000000000000000000000000";

  const { address, isConnected } = useAccount();
  const { connect, isPending: isConnecting } = useConnect();
  const { disconnect } = useDisconnect();

  const {
    writeContract,
    data: txHash,
    isPending: isSubmitting,
    error: submitError,
    reset: resetSubmit,
  } = useWriteContract({ mutation: { retry: false } });

  const {
    writeContract: writeIssuerTx,
    data: issuerTxHash,
    isPending: isIssuerSubmitting,
    error: issuerSubmitError,
    reset: resetIssuerSubmit,
  } = useWriteContract({ mutation: { retry: false } });

  const {
    data: receipt,
    isLoading: isConfirming,
    isSuccess: receiptReady,
    isError: receiptWaitFailed,
    error: receiptWaitError,
  } = useWaitForTransactionReceipt({ hash: txHash, query: { retry: false } });

  const {
    data: issuerReceipt,
    isLoading: isIssuerConfirming,
    isSuccess: issuerReceiptReady,
    isError: issuerReceiptWaitFailed,
    error: issuerReceiptWaitError,
  } = useWaitForTransactionReceipt({
    hash: issuerTxHash,
    query: { retry: false },
  });

  const {
    data: issuerTrusted,
    isFetching: issuerTrustLoading,
  } = useReadContract({
    address: contractAddressValid ? contractAddress : undefined,
    abi: identityRegistryAbi,
    functionName: "isIssuerTrusted",
    args: [issuerPublicKey.x, issuerPublicKey.y],
    query: {
      enabled: Boolean(isConnected && contractAddressValid),
      retry: false,
    },
  });

  const handleGenerateProof = async () => {
    setIsGenerating(true);
    setProofError(null);
    setGenerationStatus("Preparing VC and OPRF request...");
    setProofPackage(null);
    resetSubmit();
    resetIssuerSubmit();

    try {
      const built = await buildVcOprfEnrollmentProofPackage(
        credential,
        issuerPublicKey,
        holderKeyPair,
        networkConfig,
        (message) => setGenerationStatus(message),
      );
      setProofPackage(built);
      setGenerationStatus("OPRF package generated successfully.");
    } catch (err) {
      setProofError(
        err instanceof Error ? err.message : "Unknown error generating proof package",
      );
      setGenerationStatus(null);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleRegisterIssuerOnChain = () => {
    if (!contractAddressValid) return;
    resetIssuerSubmit();
    writeIssuerTx({
      address: contractAddress,
      abi: identityRegistryAbi,
      functionName: "addTrustedIssuer",
      args: [issuerPublicKey.x, issuerPublicKey.y],
    });
  };

  const handleSubmitToContract = () => {
    if (!proofPackage) return;
    if (!contractAddressValid) {
      setProofError("IdentityRegistry address is not configured correctly.");
      return;
    }

    resetSubmit();
    writeContract({
      address: contractAddress,
      abi: identityRegistryAbi,
      functionName: "enroll",
      args: [proofPackage.proof, proofPackage.publicSignals],
    });
  };

  const txFailedOnChain =
    Boolean(txHash) && receiptReady && receipt != null && receipt.status !== "success";
  const txSucceededOnChain =
    Boolean(txHash) && receiptReady && receipt != null && receipt.status === "success";
  const txOutcomeSettled = Boolean(txHash) && !isSubmitting && !isConfirming;
  const displayTxError =
    submitError != null
      ? formatIdentityRegistryTxError(submitError)
      : txOutcomeSettled && receiptWaitFailed
        ? receiptWaitError instanceof Error
          ? formatIdentityRegistryTxError(receiptWaitError)
          : String(receiptWaitError)
        : txOutcomeSettled && txFailedOnChain
          ? "Transaction was mined but did not succeed (reverted or missing status)."
          : null;

  const issuerTxFailedOnChain =
    Boolean(issuerTxHash) &&
    issuerReceiptReady &&
    issuerReceipt != null &&
    issuerReceipt.status !== "success";
  const issuerTxOutcomeSettled =
    Boolean(issuerTxHash) && !isIssuerSubmitting && !isIssuerConfirming;
  const displayIssuerTxError =
    issuerSubmitError != null
      ? formatIdentityRegistryTxError(issuerSubmitError)
      : issuerTxOutcomeSettled && issuerReceiptWaitFailed
        ? issuerReceiptWaitError instanceof Error
          ? formatIdentityRegistryTxError(issuerReceiptWaitError)
          : String(issuerReceiptWaitError)
        : issuerTxOutcomeSettled && issuerTxFailedOnChain
          ? "Issuer registration transaction failed on-chain."
          : null;

  return (
    <div className="proof-section">
      <h3>
        <span className="proof-icon">🔐</span>
        OPRF Enrollment Proof
      </h3>
      <p className="proof-description">
        Generate VC+OPRF enrollment payload and submit it to the on-chain verifier.
      </p>

      <div className="proof-data">
        <p className="proof-description">
          Browser flow is locked to vc-ownership auth and strict proving.
        </p>
      </div>

      <button
        className="proof-button"
        onClick={handleGenerateProof}
        disabled={isGenerating}
        type="button"
      >
        {isGenerating ? (
          <>
            <span className="spinner" />
            Generating OPRF package...
          </>
        ) : (
          <>
            <span className="btn-icon">🛡️</span>
            Generate OPRF Enrollment Package
          </>
        )}
      </button>

      {proofError && (
        <div className="proof-error">
          <span>❌</span> {proofError}
        </div>
      )}

      {isGenerating && generationStatus && (
        <div className="proof-data" role="status" aria-live="polite">
          <p className="proof-description">{generationStatus}</p>
        </div>
      )}

      {proofPackage && (
        <div className="proof-result">
          <div className="proof-status">
            <span className="proof-verified">✓ Package Ready</span>
          </div>

          <div className="proof-outputs">
            <h4>Public Outputs</h4>
            <div className="output-grid">
              <div className="output-item">
                <span className="output-label">Nullifier</span>
                <code>{proofPackage.decoded.nullifier}</code>
              </div>
              <div className="output-item">
                <span className="output-label">Valid Until</span>
                <code>{proofPackage.decoded.validUntil}</code>
              </div>
              <div className="output-item">
                <span className="output-label">Holder Public Key</span>
                <code>
                  [{proofPackage.decoded.holderPubKeyX.slice(0, 20)}...,{" "}
                  {proofPackage.decoded.holderPubKeyY.slice(0, 20)}...]
                </code>
              </div>
              <div className="output-item">
                <span className="output-label">Issuer Public Key</span>
                <code>
                  [{proofPackage.decoded.issuerPubKeyX.slice(0, 20)}...,{" "}
                  {proofPackage.decoded.issuerPubKeyY.slice(0, 20)}...]
                </code>
              </div>
              <div className="output-item">
                <span className="output-label">OPRF Key / Epoch</span>
                <code>
                  {proofPackage.decoded.oprfKeyId} / {proofPackage.decoded.oprfEpoch}
                </code>
              </div>
            </div>
          </div>

          <div className="contract-section">
            <h4>
              <span className="contract-icon">📜</span>
              Submit to Smart Contract
            </h4>

            {!isConnected ? (
              <button
                className="wallet-button connect"
                onClick={() => connect({ connector: injected() })}
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

                <div className="issuer-onchain-block">
                  <p className="issuer-onchain-hint">
                    Contract only accepts trusted issuers. Register this issuer key first.
                  </p>
                  <div className="issuer-trust-row">
                    {issuerTrustLoading ? (
                      <span className="issuer-trust-status">Checking issuer on-chain…</span>
                    ) : issuerTrusted ? (
                      <span className="issuer-trust-badge trusted">
                        ✓ Issuer trusted for this contract
                      </span>
                    ) : contractAddressValid ? (
                      <span className="issuer-trust-badge untrusted">
                        Issuer not registered on this contract
                      </span>
                    ) : (
                      <span className="issuer-trust-badge untrusted">
                        IdentityRegistry address is not configured correctly
                      </span>
                    )}
                  </div>

                  <button
                    type="button"
                    className="issuer-register-button"
                    onClick={handleRegisterIssuerOnChain}
                    disabled={
                      !contractAddressValid ||
                      isIssuerSubmitting ||
                      isIssuerConfirming ||
                      issuerTrusted === true
                    }
                  >
                    {isIssuerSubmitting ? (
                      <>
                        <span className="spinner" />
                        Submitting…
                      </>
                    ) : isIssuerConfirming ? (
                      <>
                        <span className="spinner" />
                        Confirming…
                      </>
                    ) : issuerTrusted ? (
                      <>
                        <span className="btn-icon">✓</span>
                        Issuer already on-chain
                      </>
                    ) : (
                      <>
                        <span className="btn-icon">📌</span>
                        Register current issuer on-chain
                      </>
                    )}
                  </button>

                  {displayIssuerTxError != null && (
                    <div className="tx-error issuer-tx-error" role="alert">
                      <span className="tx-error-icon">❌</span>
                      <span className="tx-error-text">{displayIssuerTxError}</span>
                    </div>
                  )}
                </div>

                <button
                  className="submit-button"
                  onClick={handleSubmitToContract}
                  disabled={
                    isSubmitting ||
                    isConfirming ||
                    isIssuerSubmitting ||
                    isIssuerConfirming ||
                    !contractAddressValid
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

                {displayTxError != null && (
                  <div className="tx-error" role="alert">
                    <span className="tx-error-icon">❌</span>
                    <span className="tx-error-text">{displayTxError}</span>
                  </div>
                )}

                {txSucceededOnChain && (
                  <div className="proof-status" role="status">
                    <span className="proof-verified">✓ Identity enrolled on-chain</span>
                  </div>
                )}

                {txHash && (
                  <div className="tx-info">
                    <span className="tx-label">Transaction:</span>
                    <code className="tx-hash">{txHash}</code>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="proof-data">
            <h4>Complete Proof Package</h4>
            <pre className="proof-json">{JSON.stringify(proofPackage, null, 2)}</pre>
          </div>

        </div>
      )}
    </div>
  );
}
