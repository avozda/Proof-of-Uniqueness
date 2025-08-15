import { signVerifiableCredential, createCredentialFromData } from "./signVC";
import { createCircuitInputs, downloadCircuitInputs } from "./createInput";
import { generateZKProof, downloadProof } from "./zkProof";
import {
  submitProofToContract,
  downloadTransactionDetails,
} from "./contractSubmission";
import type {
  VerifiableCredential,
  SignedVerifiableCredential,
  CircuitInputs,
  FormData,
} from "../types/credentials";
import type { ZKProofResult } from "./zkProof";
import type { ContractSubmissionResult } from "./contractSubmission";

export interface ProcessingResult {
  credential: VerifiableCredential;
  signedCredential: SignedVerifiableCredential;
  circuitInputs: CircuitInputs;
  zkProof: ZKProofResult;
  contractSubmission?: ContractSubmissionResult;
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
    { step: "Validating proof on-chain", completed: false },
    { step: "Submitting to blockchain", completed: false },
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
    privateKeyHex?: string,
    submitToContract: boolean = false,
    chainId?: number
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
      const circuitInputs = await createCircuitInputs(
        signedCredential as SignedVerifiableCredential
      );
      this.updateProgress(2, circuitInputs);

      // Step 4: Generate ZK proof
      console.log("Step 4: Generating ZK proof");
      const zkProof = await generateZKProof(circuitInputs);
      this.updateProgress(3, zkProof);

      let contractSubmission: ContractSubmissionResult | undefined;

      // Steps 5 & 6: Validate and submit to blockchain (optional)
      if (submitToContract) {
        console.log("Steps 5-6: Validating and submitting to blockchain");
        // The submitProofToContract function now handles both validation and submission
        // The progress steps will be updated internally by the validation and submission process
        contractSubmission = await submitProofToContract(zkProof, chainId);
        this.updateProgress(4, { validation: "successful" }); // Mark validation step as complete
        this.updateProgress(5, contractSubmission); // Mark submission step as complete
      } else {
        // Skip blockchain submission but mark both steps as completed
        this.updateProgress(4, { skipped: true });
        this.updateProgress(5, { skipped: true });
      }

      console.log("All steps completed successfully!");

      return {
        credential,
        signedCredential: signedCredential as SignedVerifiableCredential,
        circuitInputs,
        zkProof,
        contractSubmission,
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

    // Download transaction details if available
    if (result.contractSubmission) {
      downloadTransactionDetails(
        result.contractSubmission,
        "transaction_details.json"
      );
    }
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
