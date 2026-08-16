# zk-DEAP: A Zero-Knowledge Decentralized Encrypted Aggregation Protocol

Artifact for the NDSS 2027 paper of the same title. If the artifact is accepted, we will
add a Zenodo DOI here.

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

Please read the "Artifact outputs versus tables/figures in paper"
section at the end of this readme when comparing the produced tables and figures against the ones in the
paper. Preparing this artifact fixed a small number of bugs and made several changes so
that it runs outside the original Azure environment. Some measured values change as a
result, but none of the paper's conclusions do.

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
by design (fixes 4 and 10). `ProofGen` and `ProofVerify` are measured once, at five participants,
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

## This artifact versus the anonymous repository linked in the paper

This artifact replicates the code used for the accepted version of the paper, as published
in the anonymous repository linked in the paper's introduction, with a few bugs fixed and
a few changes made so that it runs outside the original Azure environment. Four files
changed:

    src/bin/azureTestingScripts/test_harness.rs
    src/bin/azureTestingScripts/fixture_server.rs
    src/bin/azureTestingScripts/snark_setup.rs
    Cargo.toml

The other thirteen files in `src/` are identical, so the zk-DEAP protocol implementation
itself is unchanged.
Each change is marked in the source with an `AE-FIX (n)` comment matching this list.
Items tagged **[bug]** are defects in the code as published. **[artifact]** marks changes
made so this package builds and runs on a reviewer's machine rather than on the original
Azure VMs, and **[added]** marks a measurement the harness did not previously take.

1. **[bug]** The harness's zk-SNARK check tested for `kzg_bn254_5.params`, but the code 
   actually loads `kzg_bn254_8.params`. The check is now removed, and
   only `kzg_bn254_8.params` is needed and included.
2. **[bug]** The timer started before the harness fetched its inputs from the fixture
   server, so time spent waiting on the network was counted as cryptographic work. Each
   operation now times only the call marked `//MEASURED OPERATION`.
3. **[bug]** Each participant's signing key was built from its own public key by mistake,
   so the harness's signatures could never verify. Nothing checked them, so no measurement
   was affected. The fixture server now supplies the Ed25519 seed of the key it generated.
4. **[bug]** Eight recorded fields did not measure the per-operation work being timed. The two
   CPU-time fields were whole-process totals and are now a real before-and-after difference. The
   other six were derived or cumulative values (CPU cycles, energy, peak and delta memory, and
   disk I/O). Rather than report a misleading number, these are now left empty (`null`), as
   `instructions` and `cache_misses` already were. No table or figure uses these fields.
5. **[artifact]** Converting CPU ticks to microseconds assumed 100 ticks per second, the
   usual Linux default and correct on every machine the paper used, but not guaranteed. It
   is now read from the system.
6. **[artifact]** The benchmark always ran all 28 combinations of participant count and
   threshold before reporting anything. `ZKDEAP_SIZES` and `ZKDEAP_RATIOS` now select a
   subset. Unset, they reproduce the original sweep exactly.
7. **[bug]** The paper's Acknowledgments name three files as containing AI-generated code
   and say all such files open with a disclaimer. `fixture_server.rs` and
   `azureVMLogs/vmLogAnalysis.py` had one. `test_harness.rs` did not. Added.
8. **[artifact]** The command description and startup banner displayed `ZK-DISPHASIA`, a
   former name for this work. Now `zk-DEAP`.
9. **[bug]** A dependency on `halo2_gadgets` stopped a clean checkout building at all: both
   released versions were withdrawn from crates.io. No source file used it, so it is
   commented out, and `Cargo.lock` is now included.
10. **[artifact]** A memory or CPU counter that could not be read aborted the measurement
    itself. On the Linux Azure VMs the original targeted these always succeeded, but on a
    host without `/proc` (macOS) every test failed, writing no result. Those fields now
    report zero.
11. **[added]** Table III compares zk-DEAP against a baseline that runs the protocol
    without the input-validity proofs, but nothing in the harness measured such a round. A `BaselineRound`
    operation now does.
12. **[bug]** The original harness recorded only the total size of a proof message, not its
    individual components. This artifact measures each of Table IV's four components from the
    proof itself, and the timer stops before the message is packed for sending.
13. **[artifact]** `snark_setup.rs` now targets `k=8` / `kzg_bn254_8.params`,
    matching what `setup_halo2()` loads and what is included in this artifact. 
    Not run by `run_all.sh`, so no measurement is affected.

`run_all.sh`, `Dockerfile` and `Cargo.lock` were written for this artifact and have no
counterpart in the anonymous repository, and `analyze.py` replaces
`azureVMLogs/vmLogAnalysis.py`. In keeping with the generative AI disclosure statement in
the paper, Claude AI was used to draft these new scripts, all of which were manually
verified before inclusion.

The anonymous repository exists only for peer review. If this artifact is accepted, the
camera-ready version of the paper will link this artifact in its place, so that the code
the paper references has these bug fixes applied.

### Artifact outputs versus tables/figures in paper

Running `run_all.sh` produces some values that differ from the paper, either from the bug
fixes above or because timing varies by hardware. None of the differences change the paper's
conclusions, and the camera-ready will use the corrected measurements.

- **Verification and round times in Tables II, III, and V are lower.** Fix 2 stopped counting
  the wait for the fixture server as cryptographic work. That wait dominated the fastest
  operations, so the paper's per-operation times were upper bounds. Table II reports Bulletproof
  verification at 3.58 ms, for example, where the cryptographic work alone is about 0.4 ms here.
- **zk-SNARK and zk-STARK proofs in Tables I to IV are larger.** The `omega` witness the paper
  adds for cross-field binding came after the Section V measurements and makes the proofs bigger.
  The zk-SNARK numbers also count different things. The paper's package total is 1,676 bytes
  (Table IV), and its 1,248-byte figure (Table II) is the proof alone. This artifact's package is
  1,981 bytes. The zk-STARK averages a little over 18,600 bytes and varies by a few hundred bytes
  per run because its sampling is randomized. The Bulletproof size (924 bytes) is unchanged.
- **Table III's Baseline column is now measured.** The original harness never measured an
  unverified round. This artifact adds a direct measurement for the paper's 103 ms cell, and the
  camera-ready will use it.
- **Some of Table IV's byte counts differ.** This artifact measures each proof component directly
  and counts the full message as sent, so the Schnorr, ZKP, and package-total rows differ from the
  paper's. The network and partial-phase totals come out smaller because the packages are smaller.
  The camera-ready will use the measured values.
- **Table V lists four rows where the paper's has seven crypto rows.** The harness measures only
  single-threaded runs, so this artifact drops the paper's two eight-thread rows. It also merges
  the `Secure aggregation` row into `Result recovery`, because the measured `compute_aggregate`
  step covers both. The paper's ~4% per-round overhead uses the single-thread total and is
  unchanged.
- **`PartialGen` is flat in Figure 5 where the paper's rises.** In the paper's Figure 5 this curve
  climbs with the participant count, but that growth was mostly the fixture fetch that Fix 2
  removed. Generating a partial decryption is fixed-size work, so here it stays flat at about
  0.1 ms. Figure 5's main conclusion holds: `DKG3` is still by far the steepest curve, growing
  about 300-fold from 5 to 100 participants.

Wall time and output size are the only genuinely per-operation quantities, and every table and
figure in the paper uses one of them.

## Deprecating multi-VM measurements & Figure 7

The measurements in the accepted paper were taken on six Azure VMs in two clock-speed
tiers. However, six machines were only required for 
Figure 7, which essentially just showed that 2.6 GHz processors were faster than
2.1 GHz processors (as expected). No other measurements in the paper
require multiple machines, so this artifact was configured to run all 
measurements on the same machine. 

This choice has a few implications:

1. We do not need to maintain live Azure instances for artifact evaluation, since all measurements can now be performed
on the artifact reviewers' local hardware.
2. Figure 7 and Appendix G will be removed from the camera-ready version of the paper, as they provide no
meaningful value. Figure 7 is therefore not produced by `run_all.sh`.
3. The timing measurements will likely differ, since the 2.1-2.6 GHz Xeon processors used for
the original measurements are unlikely to match the reviewers' own hardware. 

## License

MIT, see `LICENSE`.
