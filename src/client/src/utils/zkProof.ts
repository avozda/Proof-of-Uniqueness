import { groth16 } from "snarkjs";
import type { CircuitInputs } from "../types/credentials";
import type { PublicSignals, Groth16Proof } from "snarkjs";

export interface ZKProofResult {
  proof: Groth16Proof;
  publicSignals: PublicSignals;
}

export async function generateZKProof(
  circuitInputs: CircuitInputs
): Promise<ZKProofResult> {
  try {
    const wasmPath = "/zk/HashIDClaim.wasm";
    const zkeyPath = "/zk/hashIdClaim_final.zkey";

    console.log("Generating ZK proof with inputs:", circuitInputs);

    const { proof, publicSignals } = await groth16.fullProve(
      circuitInputs,
      wasmPath,
      zkeyPath
    );

    console.log("ZK proof generated successfully");
    console.log("Proof:", proof);
    console.log("Public signals:", publicSignals);

    return { proof, publicSignals };
  } catch (error) {
    console.error("Error generating ZK proof:", error);
    throw new Error(`Failed to generate ZK proof: ${error}`);
  }
}

export function downloadProof(
  proofResult: ZKProofResult,
  filename: string = "zk_proof.json"
): void {
  const dataStr = JSON.stringify(proofResult, null, 2);
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
