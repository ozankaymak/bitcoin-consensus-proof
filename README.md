# Bitcoin Consensus Proof

## Description
This project aims to provide a Zero Knowledge (ZK) Proof for Bitcoin-related computations, utilizing the Risc0 zkVM (Zero-Knowledge Virtual Machine) (This may change in the future). The primary goal is to prove Bitcoin-related operations, such as transaction validation or proof of work, in a trustless and verifiable manner.

## Project Overview
The project begins by leveraging Risc0's zkVM to perform computations and generate Zero-Knowledge proofs. Risc0 is a powerful tool that allows executing general-purpose programs while generating a cryptographic proof that attests to the correctness of the computation. For this project, it is used to:

- Validate Bitcoin transactions.
- Validate block headers.
- Demonstrate the integration of Bitcoin's functionality into a Zero-Knowledge framework.

## Goals
While the initial focus proving Bitcoin related operations using Risc0 zkVM, the project envisions a broader application of Zero-Knowledge technology in the Bitcoin ecosystem. Planned future directions include:

- **Faster Node Syncing:** Anyone who wishes to run a Bitcoin node will be able to reach the current state of Bitcoin without downloading all the Bitcoin data (~637 GB as of February 10, 2025). And they will not have to validate this data as well. Only verifying the ZK Proof and downloading the UTXO set (~6.45 GB) will be enough.
- **Optimizing Proof Performance:** Improving the efficiency and speed of proof generation and verification.

## Getting Started
First, install `Risc0` toolchain. You can refer to [here](https://dev.risczero.com/api/zkvm/install). Next, build the guest program by running:
```bash
BITCOIN_NETWORK=<NETWORK_TYPE> REPR_GUEST_BUILD=1 cargo build --release -p bitcoin
```
where `NETWORK_TYPE` can be `mainnet`, `testnet4`, `signet`, or `regtest`. Then, build the host program by running:
```bash
BITCOIN_NETWORK=NETWORK_TYPE cargo build --release -p host
```
where `NETWORK_TYPE` matches to the one of the previous command. Finally, run:
```bash
./target/release/host None data/proofs/testnet4_first_9.bin 10
```
where
- The first argument is the previous proof file path (`None` if starting from genesis).
- The second argument is the output proof file path.
- The third argument is the number of headers to prove.

### Usage
- TBD


