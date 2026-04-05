use babyjubjub::BabyJubJubPoint;
use ec::consts::te::baby_jubjub;
use ec::tecurve::affine::Point as TEPoint;
use oprf::oprf_output::verified_oprf;
use poseidon::poseidon::PoseidonHasher;
use std::default::Default;
use std::hash::Hasher;

global OPRF_DS_N: Field = 24546418369108709687614662004;
global OPRF_DS_DLOG: Field = 1523098184080632582082867317389990410064981862;

fn hash2(left: Field, right: Field) -> Field {
    let mut hasher = PoseidonHasher::default();
    hasher.write(left);
    hasher.write(right);
    hasher.finish()
}

fn hash_n<let N: u32>(values: [Field; N]) -> Field {
    let mut hasher = PoseidonHasher::default();
    for i in 0..N {
        hasher.write(values[i]);
    }
    hasher.finish()
}

fn merkle_root_16(leaves: [Field; 16]) -> Field {
    let mut level0 = [0; 8];
    for i in 0..8 {
        level0[i] = hash2(leaves[2 * i], leaves[(2 * i) + 1]);
    }

    let mut level1 = [0; 4];
    for i in 0..4 {
        level1[i] = hash2(level0[2 * i], level0[(2 * i) + 1]);
    }

    let mut level2 = [0; 2];
    for i in 0..2 {
        level2[i] = hash2(level1[2 * i], level1[(2 * i) + 1]);
    }

    hash2(level2[0], level2[1])
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

fn compute_hash_id(
    field_values: [Field; 13],
) -> Field {
    hash_n([
        field_values[12],
        field_values[2],
        field_values[5],
        field_values[3],
        field_values[8],
        field_values[9],
        field_values[6],
        field_values[7],
        field_values[10],
        field_values[0],
        field_values[1],
    ])
}

fn main(
    // VC proof inputs
    domain_separator: Field,
    merkle_leaves: [Field; 16],
    field_values: [Field; 13],
    signer_pub_key: [Field; 2],
    signature_r8: [Field; 2],
    signature_s: Field,
    holder_signature_r8: [Field; 2],
    holder_signature_s: Field,
    // OPRF transcript inputs
    beta: Field,
    oprf_pk: pub BabyJubJubPoint,
    dlog_e: Field,
    dlog_s: Field,
    oprf_response_blinded: BabyJubJubPoint,
    oprf_response: BabyJubJubPoint,
    // Additional public outputs needed on-chain
    valid_until: pub Field,
    holder_pub_key_x: pub Field,
    holder_pub_key_y: pub Field,
    issuer_pub_key_x: pub Field,
    issuer_pub_key_y: pub Field,
    oprf_key_id: pub Field,
    oprf_epoch: pub Field,
) -> pub Field {
    let field_labels = [
        2118198470571567473536145588563504,
        2118198470571567473536145588563505,
        2217739077219273223255122644505107646662330724,
        6582114,
        115944579229042,
        1851878757,
        133442057126172576218444921,
        641669309618204160221840285997001192639266124648,
        34793344991585695257288930408,
        7562616,
        2183735902496290402157,
        559036391039114700679532,
        1986218340,
    ];

    for i in 0..13 {
        let computed_leaf = hash2(field_labels[i], field_values[i]);
        assert(computed_leaf == merkle_leaves[i]);
    }

    let root = merkle_root_16(merkle_leaves);
    let signed_message = hash2(domain_separator, root);
    let issuer_valid = eddsa_verify_poseidon(
        signer_pub_key[0],
        signer_pub_key[1],
        signature_s,
        signature_r8[0],
        signature_r8[1],
        signed_message,
    );
    assert(issuer_valid);

    let hash_id = compute_hash_id(
        field_values,
    );
    let holder_valid = eddsa_verify_poseidon(
        field_values[0],
        field_values[1],
        holder_signature_s,
        holder_signature_r8[0],
        holder_signature_r8[1],
        hash_id,
    );
    assert(holder_valid);

    assert(valid_until == field_values[11]);
    assert(holder_pub_key_x == field_values[0]);
    assert(holder_pub_key_y == field_values[1]);
    assert(issuer_pub_key_x == signer_pub_key[0]);
    assert(issuer_pub_key_y == signer_pub_key[1]);
    assert(oprf_key_id != 0);
    assert(oprf_epoch != 0);

    verified_oprf(
        beta,
        oprf_pk,
        dlog_e,
        dlog_s,
        oprf_response_blinded,
        oprf_response,
        hash_id,
        OPRF_DS_DLOG,
        OPRF_DS_N,
    )
}
