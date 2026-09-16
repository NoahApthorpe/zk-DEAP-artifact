# zk-DEAP: A Zero-Knowledge Decentralized Encrypted Aggregation Protocol

Artifact for the NDSS 2027 paper of the same title. Figshare DOI: https://doi.org/10.6084/m9.figshare.33411562

You can run the artifact using Docker, which needs nothing
installed but Docker, or with a native build. Both approaches are described below. 

## Contents

    src/lib.rs                     crate root
    src/common/                    FROST DKG, threshold decryption, Chaum-Pedersen
                                   proofs, Lagrange interpolation, BSGS extraction,
                                   rate limiting
    src/bulletproof/               Bulletproof variant
    src/snark/                     zk-SNARK variant
    src/stark/                     zk-STARK variant
    src/bin/examples/              the three protocol demonstrations (E1)
    src/bin/security_tests/        the four attack demonstrations (E2)
    src/bin/azureTestingScripts/
                                   benchmark harness and its fixture server (E3), zk-SNARK parameter setup
    src/bin/utils/                 KZG parameter inspection

    run_all.sh                     runs the entire artifact
    analyze.py                     produces the tables and figures from the benchmark output
    results/                       created by run_all.sh: raw measurements, table CSVs, Figure 5
    trusted_setup/                 KZG parameters for the zk-SNARK variant
    Cargo.toml, Cargo.lock         dependencies
    Dockerfile                     Docker configuration
    LICENSE                        MIT license

## Docker

    docker build -t zk-deap .
    docker run --rm zk-deap

The image pins the whole environment, and its default command is `run_all.sh`, so
those two lines run the entire artifact. 

`docker run --rm zk-deap` prints every result but discards the container's
`results/` files on exit. To keep the CSV tables and `figure5.png`, run without `--rm` and
copy them out:

    docker run --name zk-deap-run zk-deap
    docker cp zk-deap-run:/zk-deap/results ./results
    docker rm zk-deap-run

## Native build

A native build requires Linux or macOS, x86-64 or arm64, and Rust 1.88 or newer.

Debian or Ubuntu:

    sudo apt-get install -y build-essential pkg-config libssl-dev git python3-venv
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    . "$HOME/.cargo/env"

macOS:

    xcode-select --install
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    . "$HOME/.cargo/env"

Then, from the repository root:

    cargo build --release --locked
    python3 -m venv .venv && ./.venv/bin/pip install matplotlib
    ./run_all.sh

## Expected Output

`run_all.sh` runs all three variants of zk-DEAP (E1), all 60 attack tests (E2), and the
proof size and timing benchmarks (E3). It then creates Tables II to V and Figure 5 from
the results. This should take no longer than 10 minutes. 

`run_all.sh` should output

- `sum=3/5` from every device, in all three variants
- `RESULTS: n passed, 0 failed` from every attack test
- a 100.0% success rate from the benchmark harness
- tables II-V with proof size and timing values from the benchmarks

It will also save CSV versions of tables II--V, as well as a Figure 5 PNG, in the 
`results/` directory. 

The absolute times measured by these benchmarks will differ based on hardware and from
run to run. Proof sizes do not depend on the hardware: the Bulletproof and zk-SNARK
packages come to exactly 924 and 1,981 bytes every time. The zk-STARK samples randomly, so
every proof it produces is a different size, and each variant is measured thirty times, so
the tables report the mean of thirty zk-STARK proofs. That mean moves by a few hundred
bytes from one run to the next.

The following sections describe each of E1--E3 in more detail.

### Protocol demonstrations (E1)

The three example binaries each run a five-participant deployment: FROST
distributed key generation, then
each participant encrypts an input and proves it satisfies the constraint, then
proofs are exchanged and verified, then a threshold of participants decrypt. The
inputs are 1, 0, 1, 1, 0, so every participant should independently arrive at
`sum=3/5`. A wrong sum, or any participant failing to reach one, is a failure.

### Attack demonstrations (E2)

The four test binaries divide 60 cases between them. Each case mounts one attack on
zk-DEAP from Section IV and asserts it is rejected:
substitution of a ciphertext under a valid proof, breaking the Schnorr link,
forging a signature, replaying a nonce, submitting an expired or future
timestamp, decrypting with fewer than a threshold of shares, and so on. Each
binary ends with `RESULTS: n passed, 0 failed`. Any failure means an attack
succeeded. These are the demonstrations referred to in Section IV-B.

### Proof size and timing benchmarks

By default the benchmarks cover deployments of 5, 10, 20, 50 and 100 participants,
with the decryption threshold at half the participants. For the full range of 
participant numbers shown in the paper's Figure 5, run

    ZKDEAP_SIZES=5,10,20,50,100,250,500 ZKDEAP_RATIOS=0.25,0.5,0.67,0.75 ./run_all.sh

Key material is generated for every combination
before any measurement starts, and that cost grows with roughly the cube of the
participant count, so running the benchmark with up to 500 participants may take several
hours. 

Proving is deliberately limited to one core, as in the paper. Raw measurements are stored in
`results/local.jsonl`, regenerated from scratch on every run, where some fields are null or zero
by design. `ProofGen` and `ProofVerify` are measured once, at five participants,
because proof cost does not depend on the participant count; Tables III and V therefore carry a
proof timing measured at n=5 under an n=100 heading, exactly as the paper composes them.

## KZG parameters

`trusted_setup/kzg_bn254_8.params` is the structured reference string needed by the
zk-SNARK variant for the Halo2 trusted setup.

    size    33028 bytes
    k       8, a maximum polynomial degree of 256
    sha256  4b67ff25b9c00ffc5557f907d0c22cbfe6f4a75a41e5a16cffe199fb50105664

The file comes from the Hermez / Privacy and Scaling Explorations perpetual
powers-of-tau ceremony for BN254, reference [80] of the paper. It is included in the
repository, byte-identical to the copy here, and cannot be re-fetched independently:
the download URL printed by `src/bin/utils/param_gen.rs` now returns HTTP 403. The
hash above confirms you have the same bytes the measurements used.

## License

MIT, see `LICENSE`.
