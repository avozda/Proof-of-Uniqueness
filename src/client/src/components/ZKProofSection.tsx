import { useEffect, useState } from "react";
import {
  useAccount,
  useChainId,
  useConnect,
  useDisconnect,
  useReadContract,
  useSignTypedData,
  useWaitForTransactionReceipt,
  useWriteContract,
} from "wagmi";
import { injected } from "wagmi/connectors";
import { concatHex, keccak256, type Address, type Hex } from "viem";

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

const EIP712_DOMAIN = {
  name: "IdentityRegistry",
  version: "1",
} as const;

const ENROLL_TYPES = {
  Enroll: [
    { name: "nullifier", type: "uint256" },
    { name: "publicSignalsHash", type: "bytes32" },
    { name: "proofHash", type: "bytes32" },
    { name: "walletAddress", type: "address" },
  ],
} as const;

const REVOKE_TYPES = {
  Revoke: [
    { name: "nullifier", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

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
  const [isEnrolling, setIsEnrolling] = useState(false);
  const [proofError, setProofError] = useState<string | null>(null);
  const [generationStatus, setGenerationStatus] = useState<string | null>(null);
  const [proofPackage, setProofPackage] =
    useState<VcOprfEnrollmentProofPackage | null>(null);
  const [isRevoking, setIsRevoking] = useState(false);
  const [revocationStatus, setRevocationStatus] = useState<string | null>(null);

  const contractAddress = CONTRACT_ADDRESSES.identityRegistry;
  const chainId = useChainId();
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
  const { signTypedDataAsync } = useSignTypedData();

  const {
    writeContract,
    data: txHash,
    isPending: isSubmitting,
    error: submitError,
    reset: resetSubmit,
  } = useWriteContract({ mutation: { retry: false } });

  const {
    writeContract: writeRevokeContract,
    data: revokeTxHash,
    isPending: isRevocationSubmitting,
    error: revokeSubmitError,
    reset: resetRevokeSubmit,
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
    data: revokeReceipt,
    isLoading: isRevokeConfirming,
    isSuccess: revokeReceiptReady,
    isError: revokeReceiptWaitFailed,
    error: revokeReceiptWaitError,
  } = useWaitForTransactionReceipt({ hash: revokeTxHash, query: { retry: false } });

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

  const buildTypedDataDomain = () => ({
    ...EIP712_DOMAIN,
    chainId,
    verifyingContract: contractAddress as Address,
  });

  const handleRevokeIdentity = async () => {
    if (!proofPackage || !contractAddressValid || !address) return;
    setIsRevoking(true);
    setRevocationStatus("Requesting revocation signature...");
    setProofError(null);
    resetRevokeSubmit();

    try {
      const nullifier = BigInt(proofPackage.decoded.nullifier);
      const deadline = BigInt(Math.floor(Date.now() / 1000) + 10 * 60);
      const signature = await signTypedDataAsync({
        domain: buildTypedDataDomain(),
        types: REVOKE_TYPES,
        primaryType: "Revoke",
        message: {
          nullifier,
          deadline,
        },
      });

      setRevocationStatus("Submitting revocation transaction...");
      writeRevokeContract({
        address: contractAddress,
        abi: identityRegistryAbi,
        functionName: "revoke",
        args: [nullifier, deadline, signature],
      });
      setRevocationStatus("Revocation transaction submitted. Waiting for confirmation...");
      setIsRevoking(false);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown revocation error";
      setProofError(msg);
      setRevocationStatus(`Revocation failed: ${msg}`);
      setIsRevoking(false);
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

  const handleSubmitToContract = async () => {
    if (!proofPackage || !address) return;
    if (!contractAddressValid) {
      setProofError("IdentityRegistry address is not configured correctly.");
      return;
    }

    resetSubmit();
    setIsEnrolling(true);
    try {
      const signature = await signTypedDataAsync({
        domain: buildTypedDataDomain(),
        types: ENROLL_TYPES,
        primaryType: "Enroll",
        message: {
          nullifier: BigInt(proofPackage.decoded.nullifier),
          publicSignalsHash: keccak256(concatHex(proofPackage.publicSignals as Hex[])),
          proofHash: keccak256(proofPackage.proof),
          walletAddress: address,
        },
      });
      writeContract({
        address: contractAddress,
        abi: identityRegistryAbi,
        functionName: "enroll",
        args: [
          proofPackage.proof,
          proofPackage.publicSignals,
          address,
          signature,
        ],
      });
    } catch (err) {
      setIsEnrolling(false);
      setProofError(err instanceof Error ? err.message : "Enrollment signature failed");
    }
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

  const revokeTxFailedOnChain =
    Boolean(revokeTxHash) &&
    revokeReceiptReady &&
    revokeReceipt != null &&
    revokeReceipt.status !== "success";
  const revokeTxSucceededOnChain =
    Boolean(revokeTxHash) &&
    revokeReceiptReady &&
    revokeReceipt != null &&
    revokeReceipt.status === "success";
  const revokeTxOutcomeSettled =
    Boolean(revokeTxHash) && !isRevocationSubmitting && !isRevokeConfirming;
  const displayRevokeTxError =
    revokeSubmitError != null
      ? formatIdentityRegistryTxError(revokeSubmitError)
      : revokeTxOutcomeSettled && revokeReceiptWaitFailed
        ? revokeReceiptWaitError instanceof Error
          ? formatIdentityRegistryTxError(revokeReceiptWaitError)
          : String(revokeReceiptWaitError)
        : revokeTxOutcomeSettled && revokeTxFailedOnChain
          ? "Revocation transaction was mined but did not succeed."
          : null;

  const revokePhaseActive = isRevoking || isRevocationSubmitting || isRevokeConfirming;

  useEffect(() => {
    if (!isEnrolling) return;
    if (submitError || txOutcomeSettled) {
      setIsEnrolling(false);
      return;
    }
    const timeout = setTimeout(() => {
      setIsEnrolling(false);
      setProofError(
        "Enrollment is taking longer than expected. Check wallet and chain status, then retry.",
      );
    }, 25000);
    return () => clearTimeout(timeout);
  }, [isEnrolling, submitError, txOutcomeSettled]);

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
            Generate OPRF Enrollment Package
          </>
        )}
      </button>

      {proofError && (
        <div className="proof-error">
          {proofError}
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
            <span className="proof-verified">Package Ready</span>
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
                <span className="output-label">Issuer Public Key</span>
                <code>
                  [{proofPackage.decoded.issuerPubKeyX.slice(0, 20)}...,{" "}
                  {proofPackage.decoded.issuerPubKeyY.slice(0, 20)}...]
                </code>
              </div>
            </div>
          </div>

          <div className="contract-section">
            <h4>
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
                        Issuer trusted for this contract
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
                        Issuer already on-chain
                      </>
                    ) : (
                      <>
                        Register current issuer on-chain
                      </>
                    )}
                  </button>

                  {displayIssuerTxError != null && (
                    <div className="tx-error issuer-tx-error" role="alert">
                      <span className="tx-error-text">{displayIssuerTxError}</span>
                    </div>
                  )}
                </div>

                <button
                  className="submit-button"
                  onClick={handleSubmitToContract}
                  disabled={
                    isEnrolling ||
                    isIssuerSubmitting ||
                    isIssuerConfirming ||
                    !contractAddressValid
                  }
                  type="button"
                >
                  {isEnrolling ? (
                    <>
                      <span className="spinner" />
                      {txHash ? "Confirming..." : "Submitting..."}
                    </>
                  ) : (
                    <>
                      Enroll Identity On-Chain
                    </>
                  )}
                </button>

                <button
                  className="submit-button"
                  onClick={handleRevokeIdentity}
                  disabled={
                    isRevoking ||
                    isRevocationSubmitting ||
                    isRevokeConfirming ||
                    isSubmitting ||
                    isConfirming ||
                    !contractAddressValid
                  }
                  type="button"
                >
                  {isRevoking || isRevocationSubmitting ? (
                    <>
                      <span className="spinner" />
                      Revoking...
                    </>
                  ) : isRevokeConfirming ? (
                    <>
                      <span className="spinner" />
                      Confirming revocation...
                    </>
                  ) : (
                    <>
                      Revoke Identity
                    </>
                  )}
                </button>

                {revokePhaseActive && revocationStatus && (
                  <div className="proof-data" role="status" aria-live="polite">
                    <p className="proof-description">{revocationStatus}</p>
                  </div>
                )}

                {displayRevokeTxError != null && (
                  <div className="tx-error" role="alert">
                    <span className="tx-error-text">{displayRevokeTxError}</span>
                  </div>
                )}

                {revokeTxSucceededOnChain && (
                  <div className="proof-status" role="status">
                    <span className="proof-verified">Identity revoked on-chain</span>
                  </div>
                )}

                {revokeTxHash && (
                  <div className="tx-info">
                    <span className="tx-label">Revocation Tx:</span>
                    <code className="tx-hash">{revokeTxHash}</code>
                  </div>
                )}

                {displayTxError != null && (
                  <div className="tx-error" role="alert">
                    <span className="tx-error-text">{displayTxError}</span>
                  </div>
                )}

                {txSucceededOnChain && (
                  <div className="proof-status" role="status">
                    <span className="proof-verified">Identity enrolled on-chain</span>
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
