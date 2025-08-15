import {
  writeContract,
  waitForTransactionReceipt,
  simulateContract,
} from "wagmi/actions";
import { config } from "../config/wagmi";
import {
  identityVerificationABI,
  contractAddresses,
} from "../contracts/IdentityVerification";
import type { ZKProofResult } from "./zkProof";

export interface ContractSubmissionResult {
  hash: `0x${string}`;
  receipt: {
    blockNumber?: bigint;
    gasUsed?: bigint;
    effectiveGasPrice?: bigint;
    status?: "success" | "reverted";
    [key: string]: unknown;
  };
  success: boolean;
}

// Convert snarkjs proof format to contract format
export function formatProofForContract(zkProof: ZKProofResult) {
  const { proof, publicSignals } = zkProof;

  // Convert proof components to the format expected by the smart contract
  const pA: [bigint, bigint] = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];
  const pB: [[bigint, bigint], [bigint, bigint]] = [
    [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])], // Note: pB coordinates are swapped
    [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
  ];
  const pC: [bigint, bigint] = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];

  // Convert public signals to array format
  const pubSignals: [bigint] = [BigInt(publicSignals[0] || "0")];

  return {
    pA,
    pB,
    pC,
    pubSignals,
  };
}

export async function submitProofToContract(
  zkProof: ZKProofResult,
  chainId: number = 1 // Default to mainnet, but this should be configurable
): Promise<ContractSubmissionResult> {
  try {
    console.log("Formatting proof for contract submission...");
    const formattedProof = formatProofForContract(zkProof);

    console.log("Formatted proof:", formattedProof);

    // Get the appropriate contract address for the chain
    const contractAddress = getContractAddress(chainId);

    console.log("Submitting to contract:", contractAddress);

    // Step 1: Simulate the contract call first to catch any reverts
    console.log("Simulating contract call to validate proof...");
    try {
      const simulationResult = await simulateContract(config, {
        abi: identityVerificationABI,
        address: contractAddress,
        functionName: "verify",
        args: [
          formattedProof.pA,
          formattedProof.pB,
          formattedProof.pC,
          formattedProof.pubSignals,
        ],
      });
      console.log("Simulation successful:", simulationResult);
    } catch (simulationError) {
      console.error("Simulation failed:", simulationError);

      // Parse the error to provide a more user-friendly message
      let errorMessage = "Proof validation failed";
      if (simulationError instanceof Error) {
        if (simulationError.message.includes("Invalid ZK proof")) {
          errorMessage =
            "Invalid ZK proof - the proof does not verify correctly";
        } else if (
          simulationError.message.includes("Verification call failed")
        ) {
          errorMessage =
            "Verification call failed - there may be an issue with the proof format";
        } else {
          errorMessage = `Contract validation failed: ${simulationError.message}`;
        }
      }

      throw new Error(errorMessage);
    }

    // Step 2: If simulation passes, submit the actual transaction
    console.log("Proof validated successfully, submitting transaction...");
    const hash = await writeContract(config, {
      abi: identityVerificationABI,
      address: contractAddress,
      functionName: "verify",
      args: [
        formattedProof.pA,
        formattedProof.pB,
        formattedProof.pC,
        formattedProof.pubSignals,
      ],
    });

    console.log("Transaction submitted:", hash);

    // Step 3: Wait for the transaction to be mined and check status
    const receipt = await waitForTransactionReceipt(config, {
      hash,
      confirmations: 1, // Wait for at least 1 confirmation
    });

    console.log("Transaction confirmed:", receipt);

    // Step 4: Verify the transaction was successful
    if (receipt.status === "reverted") {
      throw new Error(
        "Transaction was reverted - the proof may be invalid or already used"
      );
    }

    // Step 5: Additional verification - check if the event was emitted
    const hasExpectedEvent = receipt.logs.some((log) => {
      try {
        // Check if this log matches our contract and event
        return (
          log.address.toLowerCase() === contractAddress.toLowerCase() &&
          log.topics.length > 0
        ); // HashIDClaim event should have topics
      } catch {
        return false;
      }
    });

    if (!hasExpectedEvent) {
      console.warn("Expected HashIDClaim event not found in transaction logs");
    }

    return {
      hash,
      receipt,
      success: receipt.status === "success",
    };
  } catch (error) {
    console.error("Error submitting proof to contract:", error);

    // Provide more specific error messages
    if (error instanceof Error) {
      // Re-throw our custom error messages
      if (
        error.message.includes("Proof validation failed") ||
        error.message.includes("Invalid ZK proof") ||
        error.message.includes("Contract validation failed")
      ) {
        throw error;
      }

      // Handle common wagmi/viem errors
      if (error.message.includes("User rejected")) {
        throw new Error("Transaction was rejected by user");
      }

      if (error.message.includes("insufficient funds")) {
        throw new Error("Insufficient funds to pay for gas");
      }

      if (error.message.includes("nonce too low")) {
        throw new Error("Transaction nonce issue - please try again");
      }

      // Generic error fallback
      throw new Error(`Failed to submit proof to contract: ${error.message}`);
    }

    throw new Error("Unknown error occurred while submitting proof");
  }
}

function getContractAddress(chainId: number): `0x${string}` {
  switch (chainId) {
    case 1: // Mainnet
      return contractAddresses.mainnet;
    case 11155111: // Sepolia
      return contractAddresses.sepolia;
    case 31337: // Anvil local
      return contractAddresses.anvil;
    default:
      console.warn(
        `Unknown chain ID ${chainId}, using default contract address`
      );
      return contractAddresses.identityVerification;
  }
}

// Utility function to download transaction details
export function downloadTransactionDetails(
  result: ContractSubmissionResult,
  filename: string = "transaction_details.json"
): void {
  const transactionData = {
    hash: result.hash,
    success: result.success,
    blockNumber: result.receipt?.blockNumber,
    gasUsed: result.receipt?.gasUsed,
    effectiveGasPrice: result.receipt?.effectiveGasPrice,
    timestamp: new Date().toISOString(),
  };

  const dataStr = JSON.stringify(transactionData, null, 2);
  const dataBlob = new Blob([dataStr], { type: "application/json" });
  const url = URL.createObjectURL(dataBlob);

  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
