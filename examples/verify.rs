use base64::prelude::*;
use plonky2::field::types::Field;
use plonky2::plonk::circuit_data::{
    CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_rsa::gadgets::serialize::RSAGateSerializer;
use plonky2_rsa::rsa::RSAPubkey;
use serde_json::{Value, json};
use std::fs::File;
use std::io::Read;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "Usage: {} <circuit_file> <proof_file> <public_input_file>",
            args[0]
        );
        std::process::exit(1);
    }

    let circuit_file_path = &args[1];
    let proof_file_path = &args[2];
    let public_input_file_path = &args[3];

    // Read and parse the circuit file
    let mut circuit_file = File::open(circuit_file_path).unwrap_or_else(|_| {
        eprintln!("Failed to open circuit file: {}", circuit_file_path);
        std::process::exit(1);
    });
    let mut circuit_content = String::new();
    circuit_file
        .read_to_string(&mut circuit_content)
        .unwrap_or_else(|_| {
            eprintln!("Failed to read circuit file: {}", circuit_file_path);
            std::process::exit(1);
        });
    let circuit_data: Value = serde_json::from_str(&circuit_content).unwrap_or_else(|_| {
        eprintln!("Failed to parse circuit file as JSON");
        std::process::exit(1);
    });
    let verifier_circuit_data = circuit_data["verifier_circuit_data"]
        .as_str()
        .unwrap_or_else(|| {
            eprintln!("Missing 'verifier_circuit_data' field in circuit file");
            std::process::exit(1);
        });
    let circuit = circuit_data["circuit"].as_str().unwrap_or_else(|| {
        eprintln!("Missing 'circuit' field in circuit file");
        std::process::exit(1);
    });

    // Read and parse the proof file
    let mut proof_file = File::open(proof_file_path).unwrap_or_else(|_| {
        eprintln!("Failed to open proof file: {}", proof_file_path);
        std::process::exit(1);
    });
    let mut proof_content = String::new();
    proof_file
        .read_to_string(&mut proof_content)
        .unwrap_or_else(|_| {
            eprintln!("Failed to read proof file: {}", proof_file_path);
            std::process::exit(1);
        });
    let proof_data: Value = serde_json::from_str(&proof_content).unwrap_or_else(|_| {
        eprintln!("Failed to parse proof file as JSON");
        std::process::exit(1);
    });
    let proof = proof_data["proof"].as_str().unwrap_or_else(|| {
        eprintln!("Missing 'proof' field in proof file");
        std::process::exit(1);
    });

    // Read and parse the public input file
    let mut public_input_file = File::open(public_input_file_path).unwrap_or_else(|_| {
        eprintln!(
            "Failed to open public input file: {}",
            public_input_file_path
        );
        std::process::exit(1);
    });
    let mut public_input_content = String::new();
    public_input_file
        .read_to_string(&mut public_input_content)
        .unwrap_or_else(|_| {
            eprintln!(
                "Failed to read public input file: {}",
                public_input_file_path
            );
            std::process::exit(1);
        });
    let public_input_data: Value =
        serde_json::from_str(&public_input_content).unwrap_or_else(|_| {
            eprintln!("Failed to parse public input file as JSON");
            std::process::exit(1);
        });
    let message = public_input_data["message"].as_str().unwrap_or_else(|| {
        eprintln!("Missing 'message' field in public input file");
        std::process::exit(1);
    });
    let public_keys = public_input_data["public_keys"]
        .as_array()
        .unwrap_or_else(|| {
            eprintln!("Missing or invalid 'public_keys' field in public input file");
            std::process::exit(1);
        });
    // Convert public keys to a vector of strings
    let expected_public_keys: Vec<String> = public_keys
        .iter()
        .filter_map(|key| key.as_str().map(String::from))
        .collect();

    // Call the verification function
    match verify_plonky2_ring_rsa_proof(
        proof,
        verifier_circuit_data,
        circuit,
        message,
        expected_public_keys,
    ) {
        Ok(result) => println!("success"),
        Err(err) => {
            eprintln!("error: {}", err);
            std::process::exit(1);
        }
    }
}

// Mock implementation of the verification function
fn verify_plonky2_ring_rsa_proof(
    proof_base64: &str,
    verifier_only_base64: &str,
    common_data_base64: &str,
    expected_message: &str,
    expected_public_keys: Vec<String>,
) -> Result<bool, String> {
    // Decode base64 data
    let proof_bytes = BASE64_STANDARD
        .decode(proof_base64)
        .map_err(|_| String::from("Failed to decode proof from base64"))?;

    let verifier_only_bytes = BASE64_STANDARD
        .decode(verifier_only_base64)
        .map_err(|_| String::from("Failed to decode verifier-only data from base64"))?;

    let common_data_bytes = BASE64_STANDARD
        .decode(common_data_base64)
        .map_err(|_| String::from("Failed to decode common circuit data from base64"))?;

    // Deserialize proof
    let proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&proof_bytes)
        .map_err(|e| String::from(&format!("Failed to deserialize proof: {}", e)))?;

    // Use the default gate deserializer
    let gate_deserializer = RSAGateSerializer;

    // Deserialize verifier-only data
    let verifier_only: VerifierOnlyCircuitData<C, D> =
        VerifierOnlyCircuitData::from_bytes(verifier_only_bytes).map_err(|e| {
            String::from(&format!(
                "Failed to deserialize verifier-only data: {:?}",
                e
            ))
        })?;

    // Deserialize common circuit data
    let common_data: CommonCircuitData<F, D> =
        CommonCircuitData::from_bytes(common_data_bytes, &gate_deserializer).map_err(|e| {
            String::from(&format!(
                "Failed to deserialize common circuit data: {:?}",
                e
            ))
        })?;

    let verifier_data = VerifierCircuitData {
        verifier_only,
        common: common_data,
    };

    // Verify public inputs
    if !verify_public_inputs(&proof, expected_message, &expected_public_keys) {
        return Err(String::from(
            "Public key or message verification failed: Inputs don't match the proof's public inputs",
        ));
    }

    match verifier_data.verify(proof) {
        Ok(_) => Ok(true),
        Err(e) => Err(String::from(&format!("Proof verification failed: {:?}", e))),
    }
}

/// Helper function to verify public inputs against proof
fn verify_public_inputs(
    proof: &ProofWithPublicInputs<F, C, D>,
    expected_message: &str,
    expected_keys: &[String],
) -> bool {
    let mut input_index = 0;

    // Verify the expected message
    for byte in expected_message.as_bytes() {
        if input_index >= proof.public_inputs.len()
            || proof.public_inputs[input_index] != F::from_canonical_u32(*byte as u32)
        {
            return false;
        }
        input_index += 1;
    }

    // Convert expected inputs to RSAPubkey objects
    let mut pubkeys = Vec::new();
    for base64_str in expected_keys {
        let pubkey = RSAPubkey::from_base64(&base64_str);
        pubkeys.push(pubkey);
    }

    // Verify that each RSAPubkey's limbs match the public inputs
    for pubkey in pubkeys {
        for limb in pubkey.n.to_u32_digits() {
            if input_index >= proof.public_inputs.len()
                || proof.public_inputs[input_index] != F::from_canonical_u32(limb)
            {
                return false;
            }
            input_index += 1;
        }
    }

    // Ensure we checked all the inputs
    return proof.public_inputs.len() == input_index;
}
