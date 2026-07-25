use babyjubjub::BabyJubJubPoint;
use ec::consts::te::baby_jubjub;
use ec::tecurve::affine::Point as TEPoint;
use oprf::blinded_query::blinded_query;
use poseidon::poseidon::PoseidonHasher;

// Field-encoded "holder-bjj-oprf-auth:v1" domain separator for the holder's OPRF auth signature.
global HOLDER_OPRF_AUTH_DOMAIN: Field = 10002909461492902845723255642703998760851194670009185841;

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
    field_values: [Field; 12],
) -> Field {
    // This is the stable private identifier derived from the VC payload.
    // It is what the holder signs, and it is also the input that gets blinded for the OPRF query.
    hash_n([
        field_values[2], // credentialSubject.id
        field_values[3], // dateOfBirth
        field_values[7], // placeOfBirth
    ])
}

fn main(
    request_id_field: pub Field,
    merkle_leaves: [Field; 16],
    field_values: [Field; 12],
    signer_pub_key: [Field; 2],
    signature_r8: [Field; 2],
    signature_s: Field,
    holder_signature_r8: [Field; 2],
    holder_signature_s: Field,
    beta: Field,
) -> pub BabyJubJubPoint {
    // These labels must stay in the same order as the VC field encoder outside the circuit.
    // Each checked Merkle leaf is Poseidon(label, value).
    let field_labels = [
        2118198470571567473536145588563504, // holderPublicKey.x
        2118198470571567473536145588563505, // holderPublicKey.y
        2217739077219273223255122644505107646662330724, // credentialSubject.id
        6582114, // dateOfBirth
        115944579229042, // issuer.id
        1851878757, // name
        133442057126172576218444921, // nationality
        34793344991585695257288930408, // placeOfBirth
        7562616, // sex
        2183735902496290402157, // validFrom
        559036391039114700679532, // validUntil
        1986218340, // vc.id
    ];

    // The first 12 leaves carry the labeled VC fields.
    // The tree is 16 leaves wide, so the remaining leaves are padding slots.
    for i in 0..12 {
        let computed_leaf = hash2(field_labels[i], field_values[i]);
        assert(computed_leaf == merkle_leaves[i]);
    }

    let root = merkle_root_16(merkle_leaves);
    // In this circuit variant, the issuer signature is over the Merkle root hash only.
    let signed_message = hash_n([root]);
    let issuer_valid = eddsa_verify_poseidon(
        signer_pub_key[0],
        signer_pub_key[1],
        signature_s,
        signature_r8[0],
        signature_r8[1],
        signed_message,
    );
    assert(issuer_valid);

    // The holder signs the derived private identifier to prove control of the holder key
    // embedded in the VC itself.
    let hash_id = compute_hash_id(
        field_values,
    );
    let blinded = blinded_query(beta, hash_id);
    let holder_auth_message = hash_n([
        HOLDER_OPRF_AUTH_DOMAIN,
        request_id_field,
        blinded.x,
        blinded.y,
    ]);
    let holder_valid = eddsa_verify_poseidon(
        field_values[0],
        field_values[1],
        holder_signature_s,
        holder_signature_r8[0],
        holder_signature_r8[1],
        holder_auth_message,
    );
    assert(holder_valid);

    // Output only the blinded OPRF query point.
    blinded
}
