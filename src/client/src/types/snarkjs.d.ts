declare module "snarkjs" {
  export interface Groth16Proof {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  }

  export interface PublicSignals {
    [index: number]: string;
  }

  export interface VerificationKey {
    protocol: string;
    curve: string;
    nPublic: number;
    vk_alpha_1: string[];
    vk_beta_2: string[][];
    vk_gamma_2: string[][];
    vk_delta_2: string[][];
    vk_alphabeta_12: string[][][];
    IC: string[][];
  }

  export const groth16: {
    fullProve(
      input: Record<string, unknown>,
      wasmFile: string | Uint8Array,
      zkeyFile: string | Uint8Array
    ): Promise<{ proof: Groth16Proof; publicSignals: string[] }>;

    verify(
      verificationKey: VerificationKey,
      publicSignals: string[],
      proof: Groth16Proof
    ): Promise<boolean>;

    exportSolidityCallData(
      proof: Groth16Proof,
      publicSignals: string[]
    ): Promise<string>;
  };
}

