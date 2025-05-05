# Ring Signature Circuit Project

## Commands

### 1. `compile.rs`

This command compiles a ring signature circuit and outputs the prover and verifier circuit data.

#### Usage
```bash
cargo run --example compile --release -- [OPTIONS]
```

#### Options
- `-p, --prover-output <FILE>`: Path to the output file for the prover circuit (default: `circuit_prover.json`).
- `-v, --verifier-output <FILE>`: Path to the output file for the verifier circuit (default: `circuit_verifier.json`).

#### Example
```bash
cargo run --example compile --release -- -p prover.json -v verifier.json
```

---

### 2. `keygen.rs`

This command generates an RSA keypair and saves the public and private keys to JSON files.

#### Usage
```bash
cargo run --example keygen --release -- [OPTIONS]
```

#### Options
- `-p, --public-key-output <FILE>`: Path to the output file for the public key (default: `key.pub.json`).
- `-k, --private-key-output <FILE>`: Path to the output file for the private key (default: `key.json`).

#### Example
```bash
cargo run --example keygen --release -- -p my_public_key.json -k my_private_key.json
```

---

### 3. `prove.rs`

This command generates a ring signature proof using the provided circuit, public keys, message, and private key.

#### Usage
```bash
cargo run --example prove --release -- <PUBLIC_INPUT_PATH> <CIRCUIT_PATH> <PUBLIC_KEY_PATH> <PRIVATE_KEY_PATH> [OPTIONS]
```

#### Arguments
- `<PUBLIC_INPUT_PATH>`: Path to the JSON file specifying the public keys and message.
- `<CIRCUIT_PATH>`: Path to the JSON file containing the circuit prover data.
- `<PUBLIC_KEY_PATH>`: Path to the JSON file containing the public key of the signer.
- `<PRIVATE_KEY_PATH>`: Path to the JSON file containing the private key of the signer.

#### Options
- `-o, --output-path <FILE>`: Path to the output file for the proof (default: `proof.json`).

#### Example
```bash
cargo run --example prove --release -- public_input.json circuit_prover.json key.pub.json key.json -o my_proof.json
```

---

### 4. `verify.rs`

This command verifies a ring signature proof using the provided circuit, proof, and public input data.

#### Usage
```bash
cargo run --example verify --release -- <CIRCUIT_FILE> <PROOF_FILE> <PUBLIC_INPUT_FILE>
```

#### Arguments
- `<CIRCUIT_FILE>`: Path to the JSON file containing the circuit data.
- `<PROOF_FILE>`: Path to the JSON file containing the proof data.
- `<PUBLIC_INPUT_FILE>`: Path to the JSON file containing the public input data.

#### Example
```bash
cargo run --example verify --release -- circuit_verifier.json my_proof.json public_input.json
```

---

## Workflow Example

1. **Compile the Circuit**:
   ```bash
   cargo run --example compile --release -- -p circuit_prover.json -v circuit_verifier.json
   ```

2. **Generate RSA Keypair**:
   ```bash
   cargo run --example keygen --release -- -p key.pub.json -k key.json
   ```

3. **Create Public Input File**:
   Create a JSON file (e.g., `public_input.json`) with the following structure:
   ```json
   {
       "public_keys": ["<base64-encoded-public-key-1>", "<base64-encoded-public-key-2>"],
       "message": "Your message here"
   }
   ```

4. **Generate Proof**:
   ```bash
   cargo run --example prove --release -- public_input.json circuit_prover.json key.pub.json key.json -o proof.json
   ```

5. **Verify Proof**:
   ```bash
   cargo run --example verify --release -- circuit_verifier.json proof.json public_input.json
   ```
