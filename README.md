# Bitcoin Consensus Proof

## Description
This project aims to provide a Zero Knowledge (ZK) Proof for Bitcoin-related computations, utilizing Risc0 zkVM (Zero-Knowledge Virtual Machine). The primary goal is to prove Bitcoin-related operations, such as transaction validation or proof of work, in a trustless and verifiable manner.

## Project Overview
The project begins by leveraging Risc0's zkVM to perform computations and generate Zero-Knowledge proofs. Risc0 is a powerful tool that allows executing general-purpose programs while generating a cryptographic proof that attests to the correctness of the computation. For this project, it is used to:

- Validate block headers.
- Validate Bitcoin transactions.
- Validate Bitcoin Script execution (including ECDSA and Schnorr signature verification).
- Validate UTXO set changes.
- Demonstrate the integration of Bitcoin's functionality into a Zero-Knowledge framework.

## Goals
While the initial focus proving Bitcoin related operations using Risc0 zkVM, the project envisions a broader application of Zero-Knowledge technology in the Bitcoin ecosystem. Planned future directions include:

- **Faster Node Syncing:** Anyone who wishes to run a Bitcoin node will be able to reach the current state of Bitcoin without downloading all the Bitcoin data (~637 GB as of February 10, 2025). And they will not have to validate this data as well. Only verifying the ZK Proof and downloading the UTXO set (~6.45 GB) will be enough.
- **Optimizing Proof Performance:** When using a zkVM system in general, the time/proving cost correlates with total number of execution cycles. Therefore, reducing the number of cycles is of utmost importance. There are a couple of ways to achieve this:
    - Utilizing precompiles implemented by Risc0
    - Executing operations done multiple times in Bitcoin Core, only once
    - Implementing functionality that is mathematically equivalent to Bitcoin Core behavior, but with less operations/cycles.

## Getting Started (For Demonstration Purposes)
First, install `Risc0` toolchain. You can refer to [here](https://dev.risczero.com/api/zkvm/install). Also install Bitcoin.
Now, start the regtest server with the following command:
```bash
bitcoind -regtest -rpcuser=admin -rpcpassword=admin -rpcport=18443 -fallbackfee=0.00001 -wallet=admin -txindex=1
```
Create a wallet:
```bash
bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin -rpcport=18443 createwallet "admin"
```
Mine some blocks:
```bash
bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin -rpcport=18443 generatetoaddress 101 $(bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin -rpcport=18443 getnewaddress)
```
Now, to simulate continuous block mining, run:
```bash
#!/bin/bash
while true; do
  echo "Generating 1 blocks to a new address..."
  bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin -rpcport=18443 generatetoaddress 1 $(bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin -rpcport=18443 getnewaddress)
  echo "Command executed. Waiting for 30 seconds..."
  sleep 30
done
```
Now first run (for the server):
```bash
BITCOIN_NETWORK=regtest RISC0_DEV_MODE=1 cargo run --package host --bin server
```
Wait some time to allow the server to sync. Then, run the client:

```bash
BITCOIN_NETWORK=regtest RISC0_DEV_MODE=1 cargo run --package host --bin client
```

## Usage
- TBD


