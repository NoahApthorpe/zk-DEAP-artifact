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
those two lines run the entire artifact. To get a shell in the same environment:

    docker run --rm -it zk-deap bash

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

Please read the "This artifact versus the anonymous repository linked in the paper"
section at the end of this readme when comparing the produced tables and figures against the ones in the
paper. Preparing this artifact fixed a small number of bugs and made several changes so
that it runs outside the original Azure environment. Some measured values change as a
result; none of the paper's conclusions do.

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
in the anonymous repository linked in the paper's introduction, with a small number of
bugs fixed and a few changes made so that it runs outside the original Azure environment.
Specifically, three files changed:

    src/bin/azureTestingScripts/test_harness.rs
    src/bin/azureTestingScripts/fixture_server.rs
    Cargo.toml

The other fourteen source files in `src/` are identical to those in the anonymous repository.
Importantly, the zk-DEAP protocol implementation itself is unchanged.
Each change is marked in the source with an `AE-FIX (n)` comment matching this list.
Items tagged **[bug]** are defects in the code as published; **[artifact]** marks changes
made so this package builds and runs on a reviewer's machine rather than on the original
Azure VMs; **[added]** marks a measurement the harness did not previously take. Only the
**[bug]** items affect any number in the paper.

1. **[bug]** Before running any zk-SNARK test the harness checked for
   `kzg_bn254_5.params` — the file `src/bin/azureTestingScripts/snark_setup.rs` writes —
   while the file it actually loaded was `kzg_bn254_8.params`. Both were present on the
   machines that produced the paper's measurements, so the check passed there. This
   artifact distributes only `kzg_bn254_8.params`, under which the check fails and every
   zk-SNARK measurement records `FAILED`. The harness now simply attempts the load and
   reports the library's own error, so the two filenames cannot drift apart again.
2. **[bug]** The timer started before the harness fetched its inputs from the fixture
   server, so time spent waiting on the network was counted as cryptographic work. Each
   operation now times only the call marked `//MEASURED OPERATION`.
3. **[bug]** Each participant's signing key was built from its own public key by mistake,
   so the signatures the harness produced could never verify against the peer key map.
   Nothing in the harness checked them, so no measurement was affected. The fixture server
   now supplies the Ed25519 seed of the key it actually generated, and the harness rebuilds
   the same key from it.
4. **[bug]** Eight recorded fields were not measurements. `cpu_time_user_us` and
   `cpu_time_system_us` were totals for the whole process rather than the cost of one
   operation, and are now a before-and-after difference. `cycles` was CPU time times
   a fixed 2.5 GHz, a compile-time constant selected by architecture rather than read from
   the machine, and `energy_estimate_joules` came from it. `peak_rss_kb` read `VmHWM`, a
   high-water mark for the whole process, so by the last test it reported the largest
   allocation of any earlier one; `delta_rss_kb` subtracted the current RSS from it,
   mixing the two; and `disk_read_kb` and `disk_write_kb` were cumulative
   `/proc/self/io` byte counts, which rose monotonically as the harness appended to its
   own output file. All six are now `null`, as `instructions` and `cache_misses` always
   were. No table or figure in the paper uses any of them, but Section V's list of
   collected metrics names CPU cycles, energy, peak memory and disk I/O, and the
   camera-ready will drop them from that list. What remains is `initial_rss_kb`, an honest
   point-in-time reading taken before the operation. The corrected `cpu_time_*` fields are
   read at the system clock-tick resolution of 10 ms and span the harness's fixture fetches
   as well as the measured operation, so they too should not be read as per-operation
   figures.
5. **[artifact]** Converting CPU ticks to microseconds assumed 100 ticks per second. That
   is the usual Linux default, and was correct on every machine the paper used, but it is
   not guaranteed, so it is now read from the system using the correct `_SC_CLK_TCK` value
   for the platform.
6. **[artifact]** The benchmark always ran all 28 combinations of participant count and
   threshold before reporting anything. `ZKDEAP_SIZES` and `ZKDEAP_RATIOS` now select a
   subset; unset, they reproduce the original sweep exactly.
7. **[bug]** The paper's Acknowledgments name three files as containing AI-generated code
   and say all such files open with a disclaimer. `fixture_server.rs` and
   `azureVMLogs/vmLogAnalysis.py` had one; `test_harness.rs` did not. Added.
8. **[artifact]** The command description and startup banner displayed `ZK-DISPHASIA`, a
   former name for this work. Now `zk-DEAP`.
9. **[bug]** A dependency on `halo2_gadgets` stopped a clean checkout building at all: both
   released versions were withdrawn from crates.io. No source file used it, so it is
   commented out, and `Cargo.lock` is now included.
10. **[artifact]** A memory or CPU counter that could not be read aborted the measurement
    itself. The original ran on Linux Azure VMs, where these always succeeded; on a host
    without `/proc` (macOS) every test failed instead, writing no result at all. Those
    fields now report zero.
11. **[added]** Table III compares zk-DEAP against a baseline that runs the protocol
    without proofs, but nothing in the harness measured such a round. A `BaselineRound`
    operation now does: encryption, threshold decryption, and recovery of the sum,
    with no proof generated or verified.
12. **[bug]** Only the total size of a proof message was recorded, so the four component
    sizes in Table IV had nothing measured behind them. Each is now measured from the proof
    itself, and the timer stops before the message is packed for sending.

`run_all.sh`, `Dockerfile`, and `Cargo.lock` were written for this artifact and
have no counterpart in the anonymous repository. `analyze.py` takes the
place of `azureVMLogs/vmLogAnalysis.py` from the anonymous repository and simplifies
the benchmark output analysis. In keeping with the generative AI disclosure statement
in the paper, Claude AI was used to draft these new scripts, but all were manually
verified before inclusion in this artifact. 

The anonymous repository exists only for peer review. If this artifact is accepted,
the camera-ready version of the paper will link this artifact in its place, so that
the code the paper references has these bug fixes applied.

### Artifact outputs versus tables/figures in paper

Comparing the outputs of running this artifact (with `run_all.sh`) will
highlight some differences from the values in the accepted paper. 
Some of these differences are due to the bug fixes described above, while 
others are due to the inherent variability in timing measurements. 

Importantly, none of the differences described below affect the conclusions of the paper, and 
all measurements corrected by the bug fixes above will be incorporated into the 
camera-ready version. 

- **Verification and round times in Tables II, III and V are lower on comparable
  hardware.** Fix 2 removed the wait for the fixture server, which did not depend on how
  much cryptographic work followed it, and so dominated the quickest operations while
  being a smaller share of the slowest. `PartialVerify` at five participants was logged
  at 3.38 ms, where the cryptographic work alone measures under 0.2 ms. The published
  per-operation figures were therefore upper bounds, making the paper's overhead claims
  conservative. The two proving times in the next bullet are the exception.
- **zk-SNARK and zk-STARK proofs in Tables I to IV are larger, and slower to produce.**
  `omega`, the extra witness value the paper introduces for cross-field binding, was
  added to both circuits after the Section V measurements were taken, and made them
  bigger. This code produces a 1,981-byte zk-SNARK package where Tables I to IV gave
  1,248, and zk-STARK packages averaging a little over 18,600 bytes against 16,855, with
  individual proofs ranging from roughly 16,700 to 20,000 bytes, the spread
  coming from its randomized sampling. The archived logs from the paper's own runs record
  a 1,500-byte zk-SNARK package, not the 1,248 bytes printed in Tables I, II and IV; we
  have not been able to reconcile the two, and the camera-ready will use the measured
  value. The Bulletproof (924 B) and zk-STARK (16,855 B) figures in those tables do
  reproduce exactly from the same logs. Bigger circuits also take longer to prove, so
  `ProofGen` for these two is the one place this artifact prints a higher number than the
  paper. Table II gave 31.5 ms and 33.45 ms; this artifact prints more than that even on
  a fast machine, and the zk-STARK figure varies widely from run to run. Verification is
  barely affected, and the Bulletproof variant binds a different way, was unaffected, and
  still comes to exactly 924 bytes.
- **Table III's Baseline column is now measured.** Nothing in the original harness
  measured an unverified round, so the paper's 103 ms for this cell has no counterpart in
  the archived logs; the camera-ready will use a measured value. `BaselineRound` times one
  participant's round with no proof generated or verified: lifted-ElGamal encryption of its
  own input, its own partial decryption, verification of a threshold of peer partials, and
  combination with recovery of the sum. On the machine used to prepare this artifact it
  runs in about 1.4 ms at five participants and about 31 ms at one hundred.
- **Table IV counted bytes two ways.** Component rows counted each component alone.
  Package rows counted the whole message as sent, which is 92 bytes larger for a proof
  and 40 for a partial decryption. Three of its rows therefore differ from the ones
  this artifact prints. Its ZKP row gave 924 bytes for Bulletproof, which was a whole
  packaged proof rather than the range proof alone, where this artifact prints 480.
  Its `Partial decryption pkg` gave ~204 bytes, a component count, where this artifact
  prints 244. Its package totals of 1,228, 1,676 and 17,236 were the sums of its own
  component rows, which counts the smaller components twice because the ZKP row
  already held the finished package, where this artifact prints 924, 1,981 and about
  18,800.
- **Table IV's Schnorr row does not match.** The paper gave 176, 300 and 253 bytes for
  the three variants. This artifact prints 224, 289 and 241. The camera-ready will use
  the updated values.
- **Table IV's totals count the messages the protocol actually sends.** Every
  participant sends a proof to the other n-1, giving n(n-1) proofs, and each of the t
  threshold participants sends a partial decryption, giving t(n-1). This artifact
  prints about 9.1 MB for the network total and 1.21 MB for the partial phase, against
  the published 11.9 MB and 1.93 MB. Nearly all of that difference comes from the
  smaller package sizes above rather than from the message counts.
- **Table V reports only what is measured, so it has four rows where the paper's has
  six.** The paper also gives peer verification and a round total at eight threads.
  Nothing in the harness measures a multi-threaded run: those figures divide the
  single-thread cost by eight, which assumes perfect linear speedup. This artifact prints
  the measured single-thread figures alone. The paper's ~4% relative overhead against a
  10 s federated-learning round comes from its single-thread total and is unaffected; the
  camera-ready will either measure the parallel case or drop those two rows as this
  artifact does.
- **`PartialGen` is flat in Figure 5 where the paper's rises.** The paper plots it
  growing from 2.19 ms at five participants to 5.22 ms at one hundred. Almost all of that
  was fix 2's fixture fetch, which grows with the number of ciphertexts requested rather
  than with any cryptographic work. Generating a partial decryption is near-constant in
  the participant count: summing n curve points is negligible beside the one scalar
  multiplication, Schnorr proof and Ed25519 signature that dominate it. On the machine
  used to prepare this artifact it measures about 0.11 ms at five participants and about
  0.12 ms at one hundred, so the curve is essentially horizontal. The conclusion drawn
  from Figure 5 is unchanged — `DKG3` is
  still by far the steepest curve, growing about 300-fold from five participants to one
  hundred.

Wall time and output size were, and remain, the only genuinely per-operation
quantities, and every table and figure in the paper uses one of them.

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
