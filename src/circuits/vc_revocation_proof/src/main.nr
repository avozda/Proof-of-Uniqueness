use ec::consts::te::baby_jubjub;
use ec::tecurve::affine::Point as TEPoint;
use poseidon::poseidon::PoseidonHasher;
use std::default::Default;
use std::hash::Hasher;

global REVOKE_DOMAIN_SEPARATOR: Field = 581564822560125587885439217300392511509116045944773424422209198;

fn hash_n<let N: u32>(values: [Field; N]) -> Field {
    let mut hasher = PoseidonHasher::default();
    for i in 0..N {
        hasher.write(values[i]);
    }
    hasher.finish()
}

fn eddsa_verify_poseidon(
    pub_key_x: Field,
    pub_key_y: Field,
    signature_s: Field,
    signature_r8_x: Field,
    signature_r8_y: Field,
    message: Field,
) -> bool {
    let bjj = baby_jubjub();

    let pub_key = TEPoint::new(pub_key_x, pub_key_y);
    assert(bjj.curve.contains(pub_key));

    let signature_r8 = TEPoint::new(signature_r8_x, signature_r8_y);
    assert(bjj.curve.contains(signature_r8));
    assert(signature_s.lt(bjj.suborder));

    let mut hasher = PoseidonHasher::default();
    hasher.write(signature_r8_x);
    hasher.write(signature_r8_y);
    hasher.write(pub_key_x);
    hasher.write(pub_key_y);
    hasher.write(message);
    let hash: Field = hasher.finish();

    let pub_key_mul_2 = bjj.curve.add(pub_key, pub_key);
    let pub_key_mul_4 = bjj.curve.add(pub_key_mul_2, pub_key_mul_2);
    let pub_key_mul_8 = bjj.curve.add(pub_key_mul_4, pub_key_mul_4);
    assert(!pub_key_mul_8.is_zero());

    let right = bjj.curve.add(signature_r8, bjj.curve.mul(hash, pub_key_mul_8));
    let left = bjj.curve.mul(signature_s, bjj.base8);

    left.eq(right)
}

fn main(
    nullifier: pub Field,
    holder_pub_key_x: pub Field,
    holder_pub_key_y: pub Field,
    challenge_block_hash: pub Field,
    holder_sig_r8: [Field; 2],
    holder_sig_s: Field,
) {
    let revoke_msg = hash_n([
        REVOKE_DOMAIN_SEPARATOR,
        nullifier,
        challenge_block_hash,
    ]);

    let valid = eddsa_verify_poseidon(
        holder_pub_key_x,
        holder_pub_key_y,
        holder_sig_s,
        holder_sig_r8[0],
        holder_sig_r8[1],
        revoke_msg,
    );
    assert(valid);
}
