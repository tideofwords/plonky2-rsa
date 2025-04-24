use num::BigUint;
use num::FromPrimitive;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, Field64};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::generator::generate_partial_witness;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::serialization::DefaultGateSerializer;

use plonky2_rsa::gadgets::biguint::{
    BigUintTarget, CircuitBuilderBiguint, CircuitBuilderBiguintFromField, WitnessBigUint,
};
use plonky2_rsa::gadgets::rsa::{RSAGateSerializer, includes, verify_sig};
use plonky2_rsa::rsa::{RSADigest, RSAKeypair, RSAPubkey};

use serde::Serialize;

use base64::prelude::*;

#[derive(Serialize)]
struct ExportData {
    proof: String,
    verifier_only: String,
    common: String,
}

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = <C as GenericConfig<D>>::F;

fn hash(builder: &mut CircuitBuilder<F, D>, message: &[Target]) -> BigUintTarget {
    let field_size_const = BigUint::from_u64(GoldilocksField::ORDER).unwrap();
    let field_size = builder.constant_biguint(&field_size_const);
    let hashed_arr = builder.hash_or_noop::<PoseidonHash>(message.into());
    let mut hashed = builder.zero_biguint();
    for x in hashed_arr.elements.iter() {
        let x_big = builder.field_to_biguint(*x);
        hashed = builder.mul_add_biguint(&hashed, &field_size, &x_big);
    }
    hashed
}

fn compute_hash(message: &[GoldilocksField]) -> BigUint {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut message_targets = Vec::with_capacity(message.len());
    for e in message {
        message_targets.push(builder.constant(*e));
    }
    let hash_target = hash(&mut builder, &message_targets);
    let data = builder.build_prover::<C>();
    let witness =
        generate_partial_witness(PartialWitness::new(), &data.prover_only, &data.common).unwrap();
    witness.get_biguint_target(hash_target)
}

fn main() -> anyhow::Result<()> {
    let n = 10;

    let config = CircuitConfig::standard_recursion_zk_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    let keypairs: Vec<_> = (0..n).map(|_| RSAKeypair::new()).collect();
    let i = 6;

    let msg: Vec<GoldilocksField> = vec![12, 20, 23]
        .iter()
        .map(|x| GoldilocksField(*x))
        .collect();
    let digest = RSADigest {
        val: compute_hash(&msg),
    };
    let sig_val = keypairs[i].sign(&digest);
    let pk_val = keypairs[i].get_pubkey();

    let message = builder.add_virtual_targets(3);
    let hash = hash(&mut builder, &message);
    let sig = builder.add_virtual_biguint_target(64);
    let modulus = builder.add_virtual_biguint_target(64);
    let pks = (0..n)
        .map(|_| builder.add_virtual_public_biguint_target(64))
        .collect::<Vec<_>>();

    includes(&mut builder, &pks, &modulus);
    verify_sig(&mut builder, &hash, &sig, &modulus);

    let data = builder.build::<C>();

    pw.set_target_arr(&message, &msg)?;
    pw.set_biguint_target(&modulus, &pk_val.n)?;
    pw.set_biguint_target(&sig, &sig_val.sig)?;
    pks.iter()
        .zip(keypairs.iter())
        .map(|(target, value)| pw.set_biguint_target(target, &value.get_pubkey().n))
        .collect::<Result<Vec<_>, _>>()?;
    let proof = data.prove(pw)?;
    println!("TEST: {:?}", proof.public_inputs);
    data.verify(proof.clone()).unwrap();

    let gate_serializer = RSAGateSerializer;

    let verifier_only_bytes = data.verifier_only.to_bytes().unwrap();

    println!(
        "About to serialize common data with {} gates",
        data.common.gates.len()
    );
    for (i, gate) in data.common.gates.iter().enumerate() {
        let type_name = std::any::type_name_of_val(gate);
        println!("Gate {}: {:?}", i, gate);
    }
    let common_data_bytes = data.common.to_bytes(&gate_serializer).unwrap();

    let proof_bytes = bincode::serialize(&proof).unwrap(); // this one is still bincode

    let export_data = ExportData {
        proof: BASE64_STANDARD.encode(&proof_bytes),
        verifier_only: BASE64_STANDARD.encode(&verifier_only_bytes),
        common: BASE64_STANDARD.encode(&common_data_bytes),
    };

    let json = serde_json::to_string_pretty(&export_data).unwrap();
    println!("JSON: {}", json);

    let test = keypairs
        .iter()
        .map(|v| v.get_pubkey().base64())
        .collect::<Vec<_>>();
    println!("PUBLIC DATA: {:?}", test);

    Ok(())
}
