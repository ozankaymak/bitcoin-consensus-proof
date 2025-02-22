FROM risczero/risc0-guest-builder:r0.1.81.0 AS build

WORKDIR /src

# Copy the entire project structure
COPY bitcoin bitcoin
COPY core core

# Set compile-time environment variables
ENV CARGO_MANIFEST_PATH="bitcoin/guest/Cargo.toml"
ENV RUSTFLAGS="-C passes=loweratomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings"
ENV CARGO_TARGET_DIR="bitcoin/guest/target"
ENV CC_riscv32im_risc0_zkvm_elf="/root/.local/share/cargo-risczero/cpp/bin/riscv32-unknown-elf-gcc"
ENV CFLAGS_riscv32im_risc0_zkvm_elf="-march=rv32im -nostdlib"

# Set network environment variable
ARG BITCOIN_NETWORK=testnet4
ENV BITCOIN_NETWORK=${BITCOIN_NETWORK}

# Only run the build once with the environment variable set
RUN echo "Building for network: ${BITCOIN_NETWORK}" && \
    cargo +risc0 fetch --target riscv32im-risc0-zkvm-elf --manifest-path ${CARGO_MANIFEST_PATH} && \
    cargo +risc0 build --release --target riscv32im-risc0-zkvm-elf --manifest-path ${CARGO_MANIFEST_PATH}

FROM scratch AS export
ARG BITCOIN_NETWORK
COPY --from=build /src/bitcoin/guest/target/riscv32im-risc0-zkvm-elf/release ../target/riscv-guest/riscv32im-risc0-zkvm-elf/docker/bitcoin-guest
COPY --from=build /src/bitcoin/guest/target/riscv32im-risc0-zkvm-elf/release/bitcoin-guest elfs/${BITCOIN_NETWORK}-bitcoin-guest