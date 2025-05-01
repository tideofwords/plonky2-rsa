use num::BigUint;
use num::FromPrimitive;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field64;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::generator::generate_partial_witness;
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_rsa::gadgets::biguint::{
    BigUintTarget, CircuitBuilderBiguint, CircuitBuilderBiguintFromField, WitnessBigUint,
};
use plonky2_rsa::gadgets::rsa::{create_ring_circuit, create_ring_proof};
use plonky2_rsa::gadgets::serialize::RSAGateSerializer;
use plonky2_rsa::rsa::{RSADigest, RSAKeypair, RSAPubkey};

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read, Write};

use base64::prelude::*;

#[derive(Serialize)]
struct CircuitExportData {
    verifier_circuit_data: String,
    circuit: String,
}

#[derive(Serialize)]
struct ProofExportData {
    proof: String,
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

fn read_file_to_string(file_path: &str) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn main() -> anyhow::Result<()> {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <public_input.json> <keypair.json>", args[0]);
        std::process::exit(1);
    }
    let public_input_path = &args[1];
    let keypair_path = &args[2];

    // Read public keys and message from the specified JSON file
    let public_input_json = read_file_to_string(public_input_path)?;
    let public_input_data: PublicInputData = serde_json::from_str(&public_input_json)?;

    // Read private key and its public key from the specified JSON file
    let private_key_json = read_file_to_string(keypair_path)?;
    let private_key_data: PrivateKeyData = serde_json::from_str(&private_key_json)?;

    // Convert message string to GoldilocksField using ASCII values
    let message: Vec<GoldilocksField> = public_input_data
        .message
        .chars()
        .map(|c| GoldilocksField(c as u64))
        .collect();

    // Convert public keys into RSAPubKey
    let public_keys = public_input_data
        .public_keys
        .iter()
        .map(|value| RSAPubkey::from_base64(value))
        .collect::<Vec<_>>();

    // Convert private key to RSAKeypair
    let private_key =
        RSAKeypair::from_base64(&private_key_data.public_key, &private_key_data.private_key);

    let circuit = create_ring_circuit(public_keys.len(), message.len());
    let proof = create_ring_proof(&circuit, &public_keys, &private_key, &message)?;

    let data = circuit.circuit;
    let gate_serializer = RSAGateSerializer;
    let verifier_only_bytes = data.verifier_only.to_bytes().unwrap();
    let common_data_bytes = data.common.to_bytes(&gate_serializer).unwrap();
    let proof_bytes = bincode::serialize(&proof).unwrap();

    // Create CircuitExportData and ProofExportData
    let circuit_export_data = CircuitExportData {
        verifier_circuit_data: BASE64_STANDARD.encode(&verifier_only_bytes),
        circuit: BASE64_STANDARD.encode(&common_data_bytes),
    };

    let proof_export_data = ProofExportData {
        proof: BASE64_STANDARD.encode(&proof_bytes),
    };

    // Write CircuitExportData to circuit.json
    let circuit_json = serde_json::to_string_pretty(&circuit_export_data).unwrap();
    let mut circuit_file = File::create("circuit.json")?;
    circuit_file.write_all(circuit_json.as_bytes())?;

    // Write ProofExportData to proof.json
    let proof_json = serde_json::to_string_pretty(&proof_export_data).unwrap();
    let mut proof_file = File::create("proof.json")?;
    proof_file.write_all(proof_json.as_bytes())?;

    Ok(())
}
