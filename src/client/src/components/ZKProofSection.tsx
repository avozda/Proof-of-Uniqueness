import { useState, useEffect, useMemo } from "react";
import {
  useAccount,
  useConnect,
  useDisconnect,
  useReadContract,
  useWriteContract,
  useWaitForTransactionReceipt,
  usePublicClient,
} from "wagmi";
import { injected } from "wagmi/connectors";
import {
  generateProof,
  verifyProof,
  parsePublicSignals,
  generateRevocationProof,
  verifyRevocationProof,
} from "../lib/proof";
import type { ZKProof, ProofOutputs, RevocationProof } from "../lib/proof";
import type { VerifiableCredential } from "../lib/vc";
import type { MockBiometricData } from "../lib/biometrics";
import { identityRegistryAbi } from "../lib/contractAbi";
import { formatIdentityRegistryTxError } from "../lib/contractErrors";
import { CONTRACT_ADDRESSES, setContractAddress } from "../lib/wagmi";

interface ZKProofSectionProps {
  credential: VerifiableCredential;
  issuerPublicKey: { x: bigint; y: bigint };
  biometricData: MockBiometricData;
}

export function ZKProofSection({
  credential,
  issuerPublicKey,
  biometricData,
}: ZKProofSectionProps) {
  const [zkProof, setZkProof] = useState<ZKProof | null>(null);
  const [proofOutputs, setProofOutputs] = useState<ProofOutputs | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [proofVerified, setProofVerified] = useState<boolean | null>(null);
  const [proofError, setProofError] = useState<string | null>(null);
  const [contractAddress, setContractAddressInput] = useState(
    CONTRACT_ADDRESSES.identityRegistry,
  );
  const [revokeHashIdInput, setRevokeHashIdInput] = useState("");
  const [revokeError, setRevokeError] = useState<string | null>(null);
  const [revokeProof, setRevokeProof] = useState<RevocationProof | null>(null);
  const [revokeProofVerified, setRevokeProofVerified] = useState<boolean | null>(null);
  const publicClient = usePublicClient();

  const parsedRevokeHashId = /^\d+$/.test(revokeHashIdInput)
    ? BigInt(revokeHashIdInput)
    : null;

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
  } = useWriteContract({
    mutation: { retry: false },
  });

  const {
    writeContract: writeIssuerTx,
    data: issuerTxHash,
    isPending: isIssuerSubmitting,
    error: issuerSubmitError,
    reset: resetIssuerSubmit,
  } = useWriteContract({
    mutation: { retry: false },
  });

  const {
    data: receipt,
    isLoading: isConfirming,
    isSuccess: receiptReady,
    isError: receiptWaitFailed,
    error: receiptWaitError,
  } = useWaitForTransactionReceipt({
    hash: txHash,
    query: { retry: false },
  });

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

  const contractAddressValid =
    /^0x[a-fA-F0-9]{40}$/.test(contractAddress) &&
    contractAddress !== "0x0000000000000000000000000000000000000000";

  const {
    data: issuerTrusted,
    isFetching: issuerTrustLoading,
    refetch: refetchIssuerTrust,
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

  const {
    data: enrollmentVerifierAddress,
    refetch: refetchEnrollmentVerifierAddress,
  } = useReadContract({
    address: contractAddressValid ? contractAddress : undefined,
    abi: identityRegistryAbi,
    functionName: "enrollmentVerifier",
    query: {
      enabled: Boolean(isConnected && contractAddressValid),
      retry: false,
    },
  });

  const {
    writeContract: writeRevokeTx,
    data: revokeTxHash,
    isPending: isRevoking,
    error: revokeSubmitError,
    reset: resetRevokeSubmit,
  } = useWriteContract({
    mutation: { retry: false },
  });

  const {
    data: revokeReceipt,
    isLoading: isRevokeConfirming,
    isSuccess: revokeReceiptReady,
    isError: revokeReceiptWaitFailed,
    error: revokeReceiptWaitError,
  } = useWaitForTransactionReceipt({
    hash: revokeTxHash,
    query: { retry: false },
  });

  // viem only maps status for exact "0x0"/"0x1"; some RPCs return variants so status can be
  // undefined even when the tx reverted — treat any non-success receipt as failure.
  const txFailedOnChain =
    Boolean(txHash) &&
    receiptReady &&
    receipt != null &&
    receipt.status !== "success";

  const isEnrolledOnChain =
    receiptReady && receipt != null && receipt.status === "success";

  const txOutcomeSettled = Boolean(txHash) && !isSubmitting && !isConfirming;

  const displayTxError =
    submitError != null
      ? formatIdentityRegistryTxError(submitError)
      : txOutcomeSettled && receiptWaitFailed
        ? receiptWaitError instanceof Error
          ? formatIdentityRegistryTxError(receiptWaitError)
          : String(receiptWaitError)
        : txOutcomeSettled && txFailedOnChain
          ? receipt?.status === "reverted"
            ? "Transaction reverted on-chain."
            : "Transaction was mined but did not succeed (reverted, or receipt status missing / not recognized by the client)."
          : null;

  const issuerTxFailedOnChain =
    Boolean(issuerTxHash) &&
    issuerReceiptReady &&
    issuerReceipt != null &&
    issuerReceipt.status !== "success";

  const issuerRegisteredOnChain =
    issuerReceiptReady &&
    issuerReceipt != null &&
    issuerReceipt.status === "success";

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
          ? issuerReceipt?.status === "reverted"
            ? "Transaction reverted on-chain."
            : "Transaction was mined but did not succeed (reverted, or receipt status missing / not recognized by the client)."
          : null;

  useEffect(() => {
    if (issuerRegisteredOnChain) void refetchIssuerTrust();
  }, [issuerRegisteredOnChain, refetchIssuerTrust]);

  const handleGenerateProof = async () => {
    setIsGenerating(true);
    setProofError(null);
    setZkProof(null);
    setProofOutputs(null);
    setProofVerified(null);
    resetSubmit();
    resetIssuerSubmit();

    try {
      const proof = await generateProof(credential);
      setZkProof(proof);

      const outputs = parsePublicSignals(proof.publicSignals);
      setProofOutputs(outputs);
      setRevokeHashIdInput(outputs.hashID);

      const isValid = await verifyProof(proof);
      setProofVerified(isValid);
    } catch (err) {
      console.error("Error generating proof:", err);
      setProofError(
        err instanceof Error ? err.message : "Unknown error generating proof",
      );
    } finally {
      setIsGenerating(false);
    }
  };

  const revokeTxFailedOnChain =
    Boolean(revokeTxHash) &&
    revokeReceiptReady &&
    revokeReceipt != null &&
    revokeReceipt.status !== "success";

  const revokeTxOutcomeSettled =
    Boolean(revokeTxHash) && !isRevoking && !isRevokeConfirming;

  const displayRevokeTxError =
    revokeSubmitError != null
      ? formatIdentityRegistryTxError(revokeSubmitError)
      : revokeTxOutcomeSettled && revokeReceiptWaitFailed
        ? revokeReceiptWaitError instanceof Error
          ? formatIdentityRegistryTxError(revokeReceiptWaitError)
          : String(revokeReceiptWaitError)
        : revokeTxOutcomeSettled && revokeTxFailedOnChain
          ? revokeReceipt?.status === "reverted"
            ? "Transaction reverted on-chain."
            : "Transaction was mined but did not succeed (reverted, or receipt status missing / not recognized by the client)."
          : null;

  const revokeSucceeded =
    revokeReceiptReady && revokeReceipt != null && revokeReceipt.status === "success";

  const handleRevokeIdentity = async () => {
    if (!contractAddressValid) {
      setRevokeError("Enter a valid contract address.");
      return;
    }
    if (!revokeHashIdInput) {
      setRevokeError("Enter a hash ID to revoke.");
      return;
    }
    if (parsedRevokeHashId == null) {
      setRevokeError("Hash ID must be a decimal uint256 value.");
      return;
    }

    setRevokeError(null);

    try {
      const hashID = parsedRevokeHashId;
      if (!publicClient) {
        throw new Error("Public client is not ready.");
      }

      const identityRecord = (await publicClient.readContract({
        address: contractAddress,
        abi: identityRegistryAbi,
        functionName: "identities",
        args: [hashID],
      })) as readonly [bigint, bigint, bigint, bigint, bigint, boolean];
      if (!identityRecord?.[5]) {
        throw new Error(
          `No enrollment found for hashID ${hashID.toString()} on contract ${contractAddress}.`,
        );
      }

      const challengeBlock = await publicClient.getBlockNumber();
      const walletChainId = await publicClient.getChainId();

      const revokeZkProof = await generateRevocationProof(
        biometricData,
        contractAddress,
        BigInt(walletChainId),
        hashID,
        challengeBlock,
      );
      setRevokeProof(revokeZkProof);

      const localValid = await verifyRevocationProof(revokeZkProof);
      setRevokeProofVerified(localValid);
      if (!localValid) {
        throw new Error("Generated revocation proof failed local verification.");
      }

      const proof = revokeZkProof.proof;
      const pA: [bigint, bigint] = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];
      const pB: [[bigint, bigint], [bigint, bigint]] = [
        [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
        [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
      ];
      const pC: [bigint, bigint] = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];
      const pubSignals: readonly [bigint, bigint, bigint, bigint] = [
        BigInt(revokeZkProof.publicSignals[0]),
        BigInt(revokeZkProof.publicSignals[1]),
        BigInt(revokeZkProof.publicSignals[2]),
        BigInt(revokeZkProof.publicSignals[3]),
      ];

      resetRevokeSubmit();
      writeRevokeTx({
        address: contractAddress,
        abi: identityRegistryAbi,
        functionName: "revokeIdentityWithProof",
        args: [pA, pB, pC, pubSignals],
      });
    } catch (err) {
      setRevokeError(err instanceof Error ? err.message : "Revocation failed.");
    }
  };

  const handleConnectWallet = () => {
    connect({ connector: injected() });
  };

  const handleRegisterIssuerOnChain = () => {
    if (!contractAddressValid) return;
    setContractAddress(contractAddress);
    resetIssuerSubmit();
    writeIssuerTx({
      address: contractAddress,
      abi: identityRegistryAbi,
      functionName: "addTrustedIssuer",
      args: [issuerPublicKey.x, issuerPublicKey.y],
    });
  };

  const handleSubmitToContract = async () => {
    if (!zkProof || !proofVerified) return;

    setContractAddress(contractAddress);

    if (!contractAddressValid) {
      setProofError("Enter a valid contract address.");
      return;
    }

    if (!publicClient) {
      setProofError("Public client is not ready.");
      return;
    }

    const onchainEnrollmentVerifier =
      enrollmentVerifierAddress ?? (await refetchEnrollmentVerifierAddress()).data;
    if (typeof onchainEnrollmentVerifier !== "string") {
      setProofError(
        "Connected contract does not expose enrollmentVerifier(). Redeploy the new IdentityRegistry version.",
      );
      return;
    }

    if (
      onchainEnrollmentVerifier.toLowerCase() ===
      "0x0000000000000000000000000000000000000000"
    ) {
      setProofError("Contract enrollment verifier is not configured.");
      return;
    }

    const proof = zkProof.proof;
    const publicSignals = zkProof.publicSignals;
    const hashIDToEnroll = BigInt(publicSignals[0]);

    const existingRecord = (await publicClient.readContract({
      address: contractAddress,
      abi: identityRegistryAbi,
      functionName: "identities",
      args: [hashIDToEnroll],
    })) as readonly [bigint, bigint, bigint, bigint, bigint, boolean];
    if (existingRecord?.[5]) {
      setProofError(
        `HashID ${hashIDToEnroll.toString()} is already enrolled on ${contractAddress}.`,
      );
      return;
    }

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
      bigint,
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

    resetSubmit();
    writeContract({
      address: contractAddress,
      abi: identityRegistryAbi,
      functionName: "enroll",
      args: [pA, pB, pC, pubSignals],
    });
  };

  const handleAddressChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setContractAddressInput(e.target.value as `0x${string}`);
  };

  const maxRevokeBlockAge = useMemo(() => 20, []);

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

                <div className="issuer-onchain-block">
                  <p className="issuer-onchain-hint">
                    The contract only accepts enrollments from trusted issuers.
                    Register this app&apos;s issuer key (your DID) before
                    enrolling. You must use the contract owner account (same as
                    deployer).
                  </p>
                  <div className="issuer-trust-row">
                    {issuerTrustLoading ? (
                      <span className="issuer-trust-status">
                        Checking issuer on-chain…
                      </span>
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
                        Enter a valid contract address to check issuer status
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
                      <span className="tx-error-text">
                        {displayIssuerTxError}
                      </span>
                    </div>
                  )}
                  {issuerTxHash && (
                    <div className="tx-info issuer-tx-info">
                      <span className="tx-label">Issuer registration tx:</span>
                      <code className="tx-hash">{issuerTxHash}</code>
                    </div>
                  )}
                  {issuerRegisteredOnChain && (
                    <div className="tx-success issuer-tx-success">
                      <span>✅</span> Issuer registered successfully.
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

                {displayTxError != null && (
                  <div className="tx-error" role="alert">
                    <span className="tx-error-icon">❌</span>
                    <span className="tx-error-text">{displayTxError}</span>
                  </div>
                )}

                {txHash && (
                  <div className="tx-info">
                    <span className="tx-label">Transaction:</span>
                    <code className="tx-hash">{txHash}</code>
                  </div>
                )}

                {isEnrolledOnChain && (
                  <div className="tx-success">
                    <span>✅</span> Identity successfully enrolled on-chain!
                  </div>
                )}

                {isEnrolledOnChain && (
                  <>
                    <div className="revoke-block">
                      <h5>Revoke Enrollment</h5>
                      <p>
                        Unlock your sketch, sign a fresh block challenge, and remove
                        this identity from the registry.
                      </p>
                      <p className="meta-note">
                        Freshness window: signed block must be within last {maxRevokeBlockAge} blocks.
                      </p>
                      <div className="contract-address-input">
                        <label htmlFor="revokeHashId">Hash ID to revoke:</label>
                        <input
                          id="revokeHashId"
                          type="text"
                          value={revokeHashIdInput}
                          onChange={(e) => setRevokeHashIdInput(e.target.value)}
                          placeholder="123456..."
                          className="address-input"
                        />
                      </div>
                      <button
                        className="submit-button revoke-button"
                        onClick={handleRevokeIdentity}
                        disabled={
                          isRevoking ||
                          isRevokeConfirming ||
                          parsedRevokeHashId == null
                        }
                        type="button"
                      >
                        {isRevoking ? (
                          <>
                            <span className="spinner" />
                            Submitting revoke...
                          </>
                        ) : isRevokeConfirming ? (
                          <>
                            <span className="spinner" />
                            Confirming revoke...
                          </>
                        ) : (
                          <>
                            <span className="btn-icon">🗑️</span>
                            Revoke Identity On-Chain
                          </>
                        )}
                      </button>
                      {revokeError && (
                        <div className="tx-error" role="alert">
                          <span className="tx-error-icon">❌</span>
                          <span className="tx-error-text">{revokeError}</span>
                        </div>
                      )}
                      {displayRevokeTxError != null && (
                        <div className="tx-error" role="alert">
                          <span className="tx-error-icon">❌</span>
                          <span className="tx-error-text">{displayRevokeTxError}</span>
                        </div>
                      )}
                      {revokeTxHash && (
                        <div className="tx-info">
                          <span className="tx-label">Revoke transaction:</span>
                          <code className="tx-hash">{revokeTxHash}</code>
                        </div>
                      )}
                      {revokeSucceeded && (
                        <div className="tx-success">
                          <span>✅</span> Identity revoked successfully.
                        </div>
                      )}
                    </div>

                    {revokeProof && (
                      <div className="tx-info">
                        <span className="tx-label">Revocation proof public signals:</span>
                        <code className="tx-hash">[{revokeProof.publicSignals.join(", ")}]</code>
                        <span className="tx-label">Local proof check:</span>
                        <code className="tx-hash">
                          {revokeProofVerified === true
                            ? "valid"
                            : revokeProofVerified === false
                              ? "invalid"
                              : "pending"}
                        </code>
                      </div>
                    )}
                  </>
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
                2,
              )}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
