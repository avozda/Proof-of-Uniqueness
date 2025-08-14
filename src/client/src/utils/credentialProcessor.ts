import { signVerifiableCredential, createCredentialFromData } from "./signVC";
import { createCircuitInputs, downloadCircuitInputs } from "./createInput";
import { generateZKProof, downloadProof } from "./zkProof";
import type {
  VerifiableCredential,
  SignedVerifiableCredential,
  CircuitInputs,
  FormData,
} from "../types/credentials";
import type { ZKProofResult } from "./zkProof";

export interface ProcessingResult {
  credential: VerifiableCredential;
  signedCredential: SignedVerifiableCredential;
  circuitInputs: CircuitInputs;
  zkProof: ZKProofResult;
}

export interface ProcessingSteps {
  step: string;
  completed: boolean;
  data?: unknown;
}

export class CredentialProcessor {
  private steps: ProcessingSteps[] = [
    { step: "Creating credential", completed: false },
    { step: "Signing credential", completed: false },
    { step: "Creating circuit inputs", completed: false },
    { step: "Generating ZK proof", completed: false },
  ];

  private onProgress?: (steps: ProcessingSteps[]) => void;

  constructor(onProgress?: (steps: ProcessingSteps[]) => void) {
    this.onProgress = onProgress;
  }

  private updateProgress(stepIndex: number, data?: unknown) {
    this.steps[stepIndex].completed = true;
    this.steps[stepIndex].data = data;
    this.onProgress?.(this.steps);
  }

  async processCredential(
    formData: FormData,
    privateKeyHex?: string
  ): Promise<ProcessingResult> {
    try {
      // Step 1: Create credential from form data
      console.log("Step 1: Creating credential from form data");
      const credentialData = {
        givenName: formData.givenName,
        familyName: formData.familyName,
        dateOfBirth: formData.dateOfBirth,
        nationality: formData.nationality,
        issuer: "did:web:postsignum.cz",
      };

      const credential = createCredentialFromData(credentialData);
      this.updateProgress(0, credential);

      // Step 2: Sign the credential
      console.log("Step 2: Signing credential");
      const signedCredential = await signVerifiableCredential(
        credential,
        privateKeyHex
      );
      this.updateProgress(1, signedCredential);

      // Step 3: Create circuit inputs
      console.log("Step 3: Creating circuit inputs");
      const circuitInputs = await createCircuitInputs(signedCredential);
      this.updateProgress(2, circuitInputs);

      // Step 4: Generate ZK proof
      console.log("Step 4: Generating ZK proof");
      const zkProof = await generateZKProof(circuitInputs);
      this.updateProgress(3, zkProof);

      console.log("All steps completed successfully!");

      return {
        credential,
        signedCredential,
        circuitInputs,
        zkProof,
      };
    } catch (error) {
      console.error("Error in credential processing:", error);
      throw error;
    }
  }

  downloadAll(result: ProcessingResult) {
    // Download signed credential
    const signedCredentialStr = JSON.stringify(
      result.signedCredential,
      null,
      2
    );
    const signedCredentialBlob = new Blob([signedCredentialStr], {
      type: "application/json",
    });
    const signedCredentialUrl = URL.createObjectURL(signedCredentialBlob);

    const signedCredentialLink = document.createElement("a");
    signedCredentialLink.href = signedCredentialUrl;
    signedCredentialLink.download = "signed_credential.json";
    document.body.appendChild(signedCredentialLink);
    signedCredentialLink.click();
    document.body.removeChild(signedCredentialLink);
    URL.revokeObjectURL(signedCredentialUrl);

    // Download circuit inputs
    downloadCircuitInputs(result.circuitInputs, "circuit_inputs.json");

    // Download ZK proof
    downloadProof(result.zkProof, "zk_proof.json");
  }

  getSteps(): ProcessingSteps[] {
    return [...this.steps];
  }

  reset() {
    this.steps = this.steps.map((step) => ({
      ...step,
      completed: false,
      data: undefined,
    }));
  }
}
