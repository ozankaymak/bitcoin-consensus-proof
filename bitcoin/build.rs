use risc0_build::{embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder};
use std::{collections::HashMap, env, fs, path::Path};

fn main() {
    // Build environment variables
    println!("cargo:rerun-if-env-changed=SKIP_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=REPR_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=OUT_DIR");

    // Compile time constant environment variables
    println!("cargo:rerun-if-env-changed=BITCOIN_NETWORK");
    println!("cargo:rerun-if-env-changed=TEST_SKIP_GUEST_BUILD");

    // Check if we should skip the guest build for tests
    if let Ok("1" | "true") = env::var("TEST_SKIP_GUEST_BUILD").as_deref() {
        println!("cargo:warning=Skipping guest build in test. Exiting");
        return;
    }

    let network = env::var("BITCOIN_NETWORK").unwrap_or_else(|_| {
        println!("cargo:warning=BITCOIN_NETWORK not set, defaulting to 'mainnet'");
        "mainnet".to_string()
    });
    println!("cargo:warning=Building for Bitcoin network: {}", network);

    // Check if we should skip the guest build
    match env::var("SKIP_GUEST_BUILD") {
        Ok(value) => match value.as_str() {
            "1" | "true" => {
                println!("cargo:warning=Skipping guest build");
                let out_dir = env::var_os("OUT_DIR").unwrap();
                let out_dir = Path::new(&out_dir);
                let methods_path = out_dir.join("methods.rs");
                // Write empty ELF data for mock implementation
                let elf = r#"
                pub const HEADER_CHAIN_ELF: &[u8] = &[];
                pub const HEADER_CHAIN_ID: [u32; 8] = [0u32; 8];
                "#;
                return fs::write(methods_path, elf)
                    .expect("Failed to write mock header chain elf");
            }
            "0" | "false" => {
                println!("cargo:warning=Performing guest build");
            }
            _ => {
                println!("cargo:warning=Invalid value for SKIP_GUEST_BUILD: '{}'. Expected '0', '1', 'true', or 'false'. Defaulting to performing guest build.", value);
            }
        },
        Err(env::VarError::NotPresent) => {
            println!(
                "cargo:warning=SKIP_GUEST_BUILD not set. Defaulting to performing guest build."
            );
        }
        Err(env::VarError::NotUnicode(_)) => {
            println!("cargo:warning=SKIP_GUEST_BUILD contains invalid Unicode. Defaulting to performing guest build.");
        }
    }

    // Use embed_methods_with_options with our custom options
    let (guest_pkg_to_options, if_repr) = get_guest_options(network.clone());
    embed_methods_with_options(guest_pkg_to_options);

    // After the build is complete, copy the generated file to the elfs folder
    copy_binary_to_elfs_folder(network, if_repr);
}

fn get_guest_options(network: String) -> (HashMap<&'static str, risc0_build::GuestOptions>, bool) {
    let mut guest_pkg_to_options = HashMap::new();

    let (opts, is_repr) = if env::var("REPR_GUEST_BUILD").is_ok()
        && env::var("REPR_GUEST_BUILD").unwrap() == "1"
    {
        let this_package_dir = env::var("CARGO_MANIFEST_DIR").expect("Failed to get manifest dir");
        let root_dir = format!("{this_package_dir}/../");

        println!(
            "cargo:warning=Using Docker for guest build with root dir: {}",
            root_dir
        );

        let docker_opts = DockerOptionsBuilder::default()
            .root_dir(root_dir)
            .env(vec![("BITCOIN_NETWORK".to_string(), network.clone())])
            .build()
            .unwrap();

        (
            GuestOptionsBuilder::default()
                // .features(features)
                .use_docker(docker_opts)
                .build()
                .unwrap(),
            true,
        )
    } else {
        println!("cargo:warning=Guest code is not built in docker");
        (
            GuestOptionsBuilder::default()
                // .features(features)
                .build()
                .unwrap(),
            false,
        )
    };

    guest_pkg_to_options.insert("bitcoin-guest", opts);
    (guest_pkg_to_options, is_repr)
}

fn copy_binary_to_elfs_folder(network: String, is_repr: bool) {
    // Get manifest directory
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("Failed to get manifest dir");
    let base_dir = Path::new(&manifest_dir);

    // Determine target directory based on is_repr flag
    let target_dir_name = if is_repr { "../elfs" } else { "../test-elfs" };

    // Create target directory if it doesn't exist
    let target_dir = base_dir.join(target_dir_name);
    if !target_dir.exists() {
        fs::create_dir_all(&target_dir)
            .expect(&format!("Failed to create {} directory", target_dir_name));
        println!(
            "cargo:warning=Created {} directory at {:?}",
            target_dir_name, target_dir
        );
    }

    // Build source path
    let src_path = base_dir.join("../target/riscv-guest/bitcoin/bitcoin-guest/riscv32im-risc0-zkvm-elf/docker/bitcoin-guest.bin");
    if !src_path.exists() {
        println!(
            "cargo:warning=Source binary not found at {:?}, skipping copy",
            src_path
        );
        return;
    }

    // Build destination path with network prefix
    let dest_filename = format!("{}-bitcoin-guest.bin", network.to_lowercase());
    let dest_path = target_dir.join(&dest_filename);

    // Copy the file
    match fs::copy(&src_path, &dest_path) {
        Ok(_) => println!(
            "cargo:warning=Successfully copied binary to {:?}",
            dest_path
        ),
        Err(e) => println!("cargo:warning=Failed to copy binary: {}", e),
    }
}
