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

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read, Write};

use base64::prelude::*;

#[derive(Serialize)]
struct ExportData {
    proof: String,
    verifier_only: String,
    common: String,
}

#[derive(Deserialize)]
struct PublicInputData {
    public_keys: Vec<String>,
    message: String,
}

#[derive(Deserialize)]
struct PrivateKeyData {
    private_key: String,
    public_key: String,
}

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = <C as GenericConfig<D>>::F;

fn read_file_to_string(file_path: &str) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

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
    // Read public keys and message from JSON file
    let public_input_json = read_file_to_string("public_input.json")?;
    let public_input_data: PublicInputData = serde_json::from_str(&public_input_json)?;

    // Read private key and its public key from another JSON file
    let private_key_json = read_file_to_string("keypair.json")?;
    let private_key_data: PrivateKeyData = serde_json::from_str(&private_key_json)?;

    // Convert message string to GoldilocksField using ASCII values
    let message: Vec<GoldilocksField> = public_input_data
        .message
        .chars()
        .map(|c| GoldilocksField(c as u64))
        .collect();

    // circuit stuff
    //

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

    let mut output_file = File::create("proof.json")?;
    output_file.write_all(json.as_bytes())?;

    let test = public_input_data
        .public_keys
        .iter()
        .map(|v| v.clone())
        .collect::<Vec<_>>();
    println!("PUBLIC DATA: {:?}", test);

    Ok(())
}
