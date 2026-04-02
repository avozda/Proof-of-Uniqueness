declare module "circomlibjs" {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export type FieldElement = any;

  export interface EdDSAInstance {
    F: {
      e: (value: bigint | number | string) => FieldElement;
      toObject: (element: FieldElement) => bigint;
    };
    prv2pub: (privateKey: Uint8Array) => FieldElement[];
    signPoseidon: (
      privateKey: Uint8Array,
      message: FieldElement
    ) => {
      R8: FieldElement[];
      S: bigint;
    };
    verifyPoseidon: (
      message: FieldElement,
      signature: { R8: FieldElement[]; S: bigint },
      publicKey: FieldElement[]
    ) => boolean;
    babyJub: {
      packPoint: (point: FieldElement[]) => Uint8Array;
      unpackPoint: (point: Uint8Array) => FieldElement[] | null;
      inCurve: (point: FieldElement[]) => boolean;
    };
  }

  export interface PoseidonInstance {
    (inputs: bigint[]): FieldElement;
    F: {
      toObject: (element: FieldElement) => bigint;
    };
  }

  export function buildEddsa(): Promise<EdDSAInstance>;
  export function buildPoseidon(): Promise<PoseidonInstance>;
  export function buildBabyjub(): Promise<unknown>;
}
