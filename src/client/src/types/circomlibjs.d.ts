declare module "circomlibjs" {
  export interface FieldElement {
    toString(): string;
  }

  export interface Point {
    x: FieldElement;
    y: FieldElement;
  }

  export interface Signature {
    R8: [FieldElement, FieldElement];
    S: FieldElement;
  }

  export interface EdDSA {
    babyJub: {
      F: {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        e(value: any): FieldElement;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        toObject(value: any): bigint;
      };
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      packPoint(point: any[]): Uint8Array;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      unpackPoint(bytes: Uint8Array): any[] | null;
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    prv2pub(privateKey: Buffer): any[];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    signPoseidon(privateKey: Buffer, message: any): Signature;

    verifyPoseidon(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      message: any,
      signature: Signature,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      publicKey: any[]
    ): boolean;
    packSignature(signature: Signature): Uint8Array;
    unpackSignature(packed: Uint8Array): Signature;
  }

  export function buildEddsa(): Promise<EdDSA>;
}
