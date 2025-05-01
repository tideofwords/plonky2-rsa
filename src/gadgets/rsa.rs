use super::biguint::{BigUintTarget, CircuitBuilderBiguint};
use super::biguint::{CircuitBuilderBiguintFromField, WitnessBigUint};
use crate::rsa::{RSADigest, RSAKeypair, RSAPubkey};
use num::BigUint;
use num::FromPrimitive;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field64;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::generator::generate_partial_witness;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::{
    circuit_builder::CircuitBuilder,
    config::{GenericConfig, PoseidonGoldilocksConfig},
};

pub struct RingSignatureCircuit {
    pub circuit: CircuitData<F, C, D>,
    // public input targets
    pub message_targets: Vec<Target>,
    pub pk_targets: Vec<BigUintTarget>,
    // witness targets
    pub sig_target: BigUintTarget,
    pub modulus_target: BigUintTarget,
}

pub fn rsa_sign(value: &BigUint, private_key: &BigUint, modulus: &BigUint) -> BigUint {
    value.modpow(private_key, modulus)
}

fn pow_65537(
    builder: &mut CircuitBuilder<F, D>,
    value: &BigUintTarget,
    modulus: &BigUintTarget,
) -> BigUintTarget {
    let mut v = value.clone();
    for _ in 0..16 {
        let tmp = builder.mul_biguint(&v, &v);
        v = builder.rem_biguint(&tmp, modulus);
    }
    let tmp = builder.mul_biguint(value, &v);
    builder.rem_biguint(&tmp, modulus)
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

/// Verify an RSA signature.  Assumes the public exponent is 65537.
pub fn verify_sig(
    builder: &mut CircuitBuilder<F, D>,
    hash: &BigUintTarget,
    sig: &BigUintTarget,
    modulus: &BigUintTarget,
) {
    let value = pow_65537(builder, sig, modulus);
    builder.connect_biguint(hash, &value);
}

pub fn includes(builder: &mut CircuitBuilder<F, D>, list: &[BigUintTarget], value: &BigUintTarget) {
    println!("LIST: {:?}", list);
    if list.is_empty() {
        //let f = builder.constant_bool(false);
        //builder.assert_bool(f);
        let zero = builder.zero();
        let one = builder.one();
        builder.connect(zero, one);
        return;
    }

    let mut result = builder.eq_biguint(&list[0], value);
    for l in &list[1..] {
        let l_equals_value = builder.eq_biguint(l, value);
        result = builder.or(result, l_equals_value);
    }

    let one = builder.one();
    builder.connect(result.target, one);
}

pub fn create_ring_circuit(num_pks: usize, message_len: usize) -> RingSignatureCircuit {
    let config = CircuitConfig::standard_recursion_zk_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Add circuit targets
    let message_targets = (0..message_len)
        .map(|_| builder.add_virtual_public_input())
        .collect::<Vec<_>>();

    // BEGIN SOLUTION
    // TODO: Add additional targets for the signature and public keys
    let sig_target = builder.add_virtual_biguint_target(64);
    let modulus_target = builder.add_virtual_biguint_target(64);
    let pk_targets = (0..num_pks)
        .map(|_| builder.add_virtual_public_biguint_target(64))
        .collect::<Vec<_>>();
    // END SOLUTION

    // compute a hash of the message inside the circuit
    let hash = hash(&mut builder, &message_targets);

    // BEGIN SOLUTION

    // TODO: Add circuit logic which checks the signer pk is in the pk list
    // check that the public key list includes our public key
    includes(&mut builder, &pk_targets, &modulus_target);
    // TODO: Add circuit logic which checks that the RSA signature is correct
    // verify the RSA signiture using our public key
    verify_sig(&mut builder, &hash, &sig_target, &modulus_target);
    // END SOLUTION

    let data = builder.build::<C>();

    return RingSignatureCircuit {
        circuit: data,
        message_targets: message_targets,
        pk_targets: pk_targets,
        sig_target: sig_target,
        modulus_target: modulus_target,
    };
}

/// Creates a ring signature proof where the signer proves they know a valid signature
/// for one of the public keys in the ring without revealing which one.
pub fn create_ring_proof(
    circuit: &RingSignatureCircuit,
    public_keys: &[RSAPubkey],   // Public keys as RSAPubkey objects
    private_key: &RSAKeypair,    // Private key as an RSAKeypair object
    message: &[GoldilocksField], // Message as a vector of field elements
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let digest = RSADigest {
        val: compute_hash(&message),
    };
    let sig_val = private_key.sign(&digest);
    let pk_val = private_key.get_pubkey();

    let n = public_keys.len();
    let mut pw = PartialWitness::new();

    // Set the witness values
    pw.set_target_arr(&circuit.message_targets, &message)?;

    // BEGIN SOLUTION
    // TODO: Set your additional targets in the partial witness
    pw.set_biguint_target(&circuit.modulus_target, &pk_val.n)?;
    pw.set_biguint_target(&circuit.sig_target, &sig_val.sig)?;
    circuit
        .pk_targets
        .iter()
        .zip(public_keys.iter())
        .map(|(target, pubkey)| pw.set_biguint_target(target, &pubkey.n))
        .collect::<Result<Vec<_>, _>>()?;
    // END SOLUTION

    let proof = circuit.circuit.prove(pw)?;
    // check that the proof verifies
    circuit.circuit.verify(proof.clone())?;
    Ok(proof)
}

// BEGIN SOLUTION
// No need to give the students all these tests though it might be nice
// to give them something
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    use crate::gadgets::biguint::{
        BigUintTarget, CircuitBuilderBiguint, CircuitBuilderBiguintFromField, WitnessBigUint,
    };
    use crate::rsa::{RSADigest, RSAKeypair};
    use num::{BigUint, FromPrimitive, Num};
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field64;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::generator::generate_partial_witness;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;

    const MODULUS_STR: &str = "a709e2f84ac0e21eb0caa018cf7f697f774e96f8115fc2359e9cf60b1dd8d4048d974cdf8422bef6be3c162b04b916f7ea2133f0e3e4e0eee164859bd9c1e0ef0357c142f4f633b4add4aab86c8f8895cd33fbf4e024d9a3ad6be6267570b4a72d2c34354e0139e74ada665a16a2611490debb8e131a6cffc7ef25e74240803dd71a4fcd953c988111b0aa9bbc4c57024fc5e8c4462ad9049c7f1abed859c63455fa6d58b5cc34a3d3206ff74b9e96c336dbacf0cdd18ed0c66796ce00ab07f36b24cbe3342523fd8215a8e77f89e86a08db911f237459388dee642dae7cb2644a03e71ed5c6fa5077cf4090fafa556048b536b879a88f628698f0c7b420c4b7";
    const PRIVATE_KEY_STR: &str = "10f22727e552e2c86ba06d7ed6de28326eef76d0128327cd64c5566368fdc1a9f740ad8dd221419a5550fc8c14b33fa9f058b9fa4044775aaf5c66a999a7da4d4fdb8141c25ee5294ea6a54331d045f25c9a5f7f47960acbae20fa27ab5669c80eaf235a1d0b1c22b8d750a191c0f0c9b3561aaa4934847101343920d84f24334d3af05fede0e355911c7db8b8de3bf435907c855c3d7eeede4f148df830b43dd360b43692239ac10e566f138fb4b30fb1af0603cfcf0cd8adf4349a0d0b93bf89804e7c2e24ca7615e51af66dccfdb71a1204e2107abbee4259f2cac917fafe3b029baf13c4dde7923c47ee3fec248390203a384b9eb773c154540c5196bce1";

    static MODULUS: LazyLock<BigUint> =
        LazyLock::new(|| BigUint::from_str_radix(MODULUS_STR, 16).unwrap());
    static PRIVATE_KEY: LazyLock<BigUint> =
        LazyLock::new(|| BigUint::from_str_radix(PRIVATE_KEY_STR, 16).unwrap());

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
            generate_partial_witness(PartialWitness::new(), &data.prover_only, &data.common)
                .unwrap();
        witness.get_biguint_target(hash_target)
    }

    fn generate_message() -> (Vec<GoldilocksField>, BigUint) {
        let mut msg = Vec::with_capacity(10);
        for i in 0..10 {
            msg.push(GoldilocksField(i));
        }
        let hash = compute_hash(&msg);
        let sig = super::rsa_sign(&hash, &PRIVATE_KEY, &MODULUS);
        (msg, sig)
    }

    #[test]
    fn test_rsa_verify() -> anyhow::Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let message = builder.add_virtual_targets(10);
        let hash = hash(&mut builder, &message);
        let sig = builder.add_virtual_biguint_target(64);
        let modulus = builder.constant_biguint(&*MODULUS);
        verify_sig(&mut builder, &hash, &sig, &modulus);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        let (msg, s) = generate_message();
        pw.set_target_arr(&message, &msg)?;
        pw.set_biguint_target(&sig, &s)?;
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_rsa_keygen_and_verify() -> anyhow::Result<()> {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut pw = PartialWitness::new();

        let keypair = RSAKeypair::new();
        let msg: Vec<GoldilocksField> = vec![12, 20, 23]
            .iter()
            .map(|x| GoldilocksField(*x))
            .collect();
        let digest = RSADigest {
            val: compute_hash(&msg),
        };
        let sig_val = keypair.sign(&digest);
        let pk = keypair.get_pubkey();

        let message = builder.add_virtual_targets(3);
        let hash = hash(&mut builder, &message);
        let sig = builder.add_virtual_biguint_target(64);
        let modulus = builder.constant_biguint(&pk.n);
        verify_sig(&mut builder, &hash, &sig, &modulus);

        let data = builder.build::<C>();

        pw.set_target_arr(&message, &msg)?;
        pw.set_biguint_target(&sig, &sig_val.sig)?;
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_rsa_keygen_and_verify_ring() -> anyhow::Result<()> {
        let N = 10;

        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut pw = PartialWitness::new();

        let keypairs: Vec<_> = (0..N).map(|_| RSAKeypair::new()).collect();
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
        let pks = (0..N)
            .map(|_| builder.constant_biguint(&keypairs[i].get_pubkey().n))
            .collect::<Vec<_>>();

        includes(&mut builder, &pks, &modulus);
        verify_sig(&mut builder, &hash, &sig, &modulus);

        let data = builder.build::<C>();

        pw.set_target_arr(&message, &msg)?;
        pw.set_biguint_target(&modulus, &pk_val.n)?;
        pw.set_biguint_target(&sig, &sig_val.sig)?;
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_rsa_keygen_and_verify_ring_function() -> anyhow::Result<()> {
        let N = 10;

        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut pw = PartialWitness::new();

        let keypairs: Vec<_> = (0..N).map(|_| RSAKeypair::new()).collect();
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
        let pks = (0..N)
            .map(|_| builder.constant_biguint(&keypairs[i].get_pubkey().n))
            .collect::<Vec<_>>();

        includes(&mut builder, &pks, &modulus);
        verify_sig(&mut builder, &hash, &sig, &modulus);

        let data = builder.build::<C>();

        pw.set_target_arr(&message, &msg)?;
        pw.set_biguint_target(&modulus, &pk_val.n)?;
        pw.set_biguint_target(&sig, &sig_val.sig)?;
        let proof = data.prove(pw)?;
        data.verify(proof)
    }
}
// END SOLUTION
