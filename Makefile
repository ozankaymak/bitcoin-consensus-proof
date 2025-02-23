# Default Bitcoin network (can be overridden, e.g., make NETWORK=mainnet)
NETWORK ?= testnet4

.PHONY: all install-toolchain guest host host_mainnet host_testnet4 host_signet host_regtest run proof clean

# Generic target to build both guest and host programs
all: guest host

# Install Risc0 toolchain (refer to the provided URL for instructions)
install-toolchain:
	@echo "Please follow the instructions at <URL> to install the Risc0 toolchain."

# Build the guest program (uses REPR_GUEST_BUILD=1)
guest:
	@echo "Building guest program for $(NETWORK)..."
	BITCOIN_NETWORK=$(NETWORK) REPR_GUEST_BUILD=1 cargo build -p bitcoin

# Build the host program in release mode (default network)
host:
	@echo "Building host program for $(NETWORK)..."
	BITCOIN_NETWORK=$(NETWORK) cargo build --release -p host

# Dedicated targets for building host for specific networks
host_mainnet:
	@echo "Building host program for mainnet..."
	BITCOIN_NETWORK=mainnet cargo build --release -p host

host_testnet4:
	@echo "Building host program for testnet4..."
	BITCOIN_NETWORK=testnet4 cargo build --release -p host

host_signet:
	@echo "Building host program for signet..."
	BITCOIN_NETWORK=signet cargo build --release -p host

host_regtest:
	@echo "Building host program for regtest..."
	BITCOIN_NETWORK=regtest cargo build --release -p host

run: host
	@echo "Running host program for $(NETWORK)..."
	./target/release/host None proofs/$(NETWORK)_first_9.bin 10

# Create a proof by building both guest and host, then running the host program.
# This target will create the proof file.
proof: guest host
	@echo "Creating proof for $(NETWORK)..."
	./target/release/host None proofs/$(NETWORK)_first_9.bin 10

# Clean build artifacts
clean:
	cargo clean
