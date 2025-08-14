declare module "poseidon-lite" {
  export function poseidon1(inputs: bigint[]): bigint;
  export function poseidon2(inputs: [bigint, bigint]): bigint;
  export function poseidon3(inputs: [bigint, bigint, bigint]): bigint;
  export function poseidon4(inputs: [bigint, bigint, bigint, bigint]): bigint;
}
