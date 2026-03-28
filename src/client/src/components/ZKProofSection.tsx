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
import { generateProof, verifyProof, parsePublicSignals } from "../lib/proof";
import type { ZKProof, ProofOutputs } from "../lib/proof";
import type { VerifiableCredential } from "../lib/vc";
import type { MockBiometricData, SignatureParts } from "../lib/biometrics";
import { identityRegistryAbi } from "../lib/contractAbi";
import { formatIdentityRegistryTxError } from "../lib/contractErrors";
import { CONTRACT_ADDRESSES, setContractAddress } from "../lib/wagmi";
import {
  buildAuthorizeChallengeDigest,
  buildRevokeChallengeDigest,
  generateAuthorizeChallenge,
  signChallengeWithBiometric,
  verifyChallengeSignature,
} from "../lib/biometrics";
import { bytesToHex } from "@noble/hashes/utils.js";

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
  const [authorizeHashIdInput, setAuthorizeHashIdInput] = useState("");
  const [revokeError, setRevokeError] = useState<string | null>(null);
  const [authorizeError, setAuthorizeError] = useState<string | null>(null);
  const [authorizeResult, setAuthorizeResult] = useState<boolean | null>(null);
  const [authorizeChallengeHex, setAuthorizeChallengeHex] = useState<string | null>(
    null,
  );
  const [authorizeSignature, setAuthorizeSignature] = useState<SignatureParts | null>(
    null,
  );
  const [isAuthorizing, setIsAuthorizing] = useState(false);
  const [authorizeVkFromChain, setAuthorizeVkFromChain] = useState<
    readonly [bigint, bigint] | null
  >(null);
  const publicClient = usePublicClient();

  const parsedAuthorizeHashId = /^\d+$/.test(authorizeHashIdInput)
    ? BigInt(authorizeHashIdInput)
    : null;
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

  const {
    refetch: refetchAuthorizeVk,
    isFetching: isAuthorizeVkFetching,
  } = useReadContract({
    address: contractAddressValid ? contractAddress : undefined,
    abi: identityRegistryAbi,
    functionName: "getVerificationKey",
    args: parsedAuthorizeHashId != null ? [parsedAuthorizeHashId] : undefined,
    query: {
      enabled: false,
      retry: false,
    },
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
      setAuthorizeHashIdInput(outputs.hashID);

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

  const handleAuthorizeMock = async () => {
    if (!contractAddressValid) {
      setAuthorizeError("Enter a valid contract address.");
      return;
    }
    if (!authorizeHashIdInput) {
      setAuthorizeError("Enter a hash ID to authorize.");
      return;
    }
    if (parsedAuthorizeHashId == null) {
      setAuthorizeError("Hash ID must be a decimal uint256 value.");
      return;
    }

    setIsAuthorizing(true);
    setAuthorizeError(null);
    setAuthorizeResult(null);
    setAuthorizeChallengeHex(null);
    setAuthorizeSignature(null);

    try {
      const hashID = parsedAuthorizeHashId;
      const vkResult = await refetchAuthorizeVk();
      const vk = vkResult.data;
      if (!vk) {
        throw new Error("Verification key not found for hash ID.");
      }

      const [vkX, vkY] = vk as readonly [bigint, bigint];
      setAuthorizeVkFromChain([vkX, vkY]);
      const challenge = generateAuthorizeChallenge();
      const digest = buildAuthorizeChallengeDigest(hashID, challenge);
      const signature = signChallengeWithBiometric(
        biometricData.rawBiometric,
        biometricData.sketch,
        digest,
      );
      const ok = verifyChallengeSignature(vkX, vkY, digest, signature);

      setAuthorizeChallengeHex(`0x${bytesToHex(challenge)}`);
      setAuthorizeSignature(signature);
      setAuthorizeResult(ok);
    } catch (err) {
      setAuthorizeError(
        err instanceof Error ? err.message : "Authorization mock failed.",
      );
    } finally {
      setIsAuthorizing(false);
    }
  };

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

      const challengeBlock = await publicClient.getBlockNumber();
      const walletChainId = await publicClient.getChainId();

      const digest = buildRevokeChallengeDigest(
        contractAddress,
        BigInt(walletChainId),
        hashID,
        challengeBlock,
      );

      const signature = signChallengeWithBiometric(
        biometricData.rawBiometric,
        biometricData.sketch,
        digest,
      );

      resetRevokeSubmit();
      writeRevokeTx({
        address: contractAddress,
        abi: identityRegistryAbi,
        functionName: "revokeIdentity",
        args: [hashID, challengeBlock, signature.v, signature.r, signature.s],
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

                    <div className="authorize-block">
                      <h5>Authorization (Mock)</h5>
                      <p>
                        Fetch verification key by hash ID, generate random challenge,
                        sign with unlocked sketch key, then verify locally.
                      </p>
                      <div className="contract-address-input">
                        <label htmlFor="authorizeHashId">Hash ID to authorize:</label>
                        <input
                          id="authorizeHashId"
                          type="text"
                          value={authorizeHashIdInput}
                          onChange={(e) => setAuthorizeHashIdInput(e.target.value)}
                          placeholder="123456..."
                          className="address-input"
                        />
                      </div>
                      <button
                        className="submit-button authorize-button"
                        onClick={handleAuthorizeMock}
                        disabled={
                          isAuthorizing ||
                          isAuthorizeVkFetching ||
                          parsedAuthorizeHashId == null
                        }
                        type="button"
                      >
                        {isAuthorizing || isAuthorizeVkFetching ? (
                          <>
                            <span className="spinner" />
                            Authorizing...
                          </>
                        ) : (
                          <>
                            <span className="btn-icon">✅</span>
                            Run Authorization Mock
                          </>
                        )}
                      </button>
                      {authorizeError && (
                        <div className="tx-error" role="alert">
                          <span className="tx-error-icon">❌</span>
                          <span className="tx-error-text">{authorizeError}</span>
                        </div>
                      )}
                      {authorizeChallengeHex && authorizeSignature && (
                        <div className="tx-info">
                          {authorizeVkFromChain && (
                            <>
                              <span className="tx-label">Verification key from contract:</span>
                              <code className="tx-hash">
                                x={authorizeVkFromChain[0].toString()} y={authorizeVkFromChain[1].toString()}
                              </code>
                            </>
                          )}
                          <span className="tx-label">Random challenge:</span>
                          <code className="tx-hash">{authorizeChallengeHex}</code>
                          <span className="tx-label">Signature (v,r,s):</span>
                          <code className="tx-hash">
                            v={authorizeSignature.v} r={authorizeSignature.r} s={authorizeSignature.s}
                          </code>
                        </div>
                      )}
                      {authorizeResult !== null && (
                        <div className={authorizeResult ? "tx-success" : "tx-error"}>
                          {authorizeResult ? (
                            <>
                              <span>✅</span> Authorization mock succeeded (signature verified).
                            </>
                          ) : (
                            <>
                              <span className="tx-error-icon">❌</span>
                              <span className="tx-error-text">
                                Authorization mock failed (signature did not verify).
                              </span>
                            </>
                          )}
                        </div>
                      )}
                    </div>
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
