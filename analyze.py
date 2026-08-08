#!/usr/bin/env python3
"""Regenerate the tables and figures of Section V from JSONL benchmark output.

  ./analyze.py --logs results
"""

import argparse
import csv
import json
import statistics as st
from collections import defaultdict
from pathlib import Path

ZKPS = ["Bulletproof", "SNARK", "STARK"]

FUNC_PROOF_GEN = "ProofGen"
FUNC_PROOF_VERIFY = "ProofVerify"
FUNC_PARTIAL_GEN = "PartialGen"
FUNC_AGG_COMPUTE = "AggCompute"
FUNC_BASELINE_ROUND = "BaselineRound"

NET_OPS = ["DKG1", "DKG2", "DKG3", FUNC_PARTIAL_GEN, FUNC_AGG_COMPUTE]

# Row labels as the paper prints them.
ROWS_III = ["Prove (ms)", "Verify (ms)", "Per-peer overhead (ms)", "Proof size (bytes)",
            "Round time, n=100 (ms)", "Verifiable", "Anti-substitution"]
ROWS_IV = ["ElGamal ciphertext", "Schnorr proof + binding data", "ZKP",
           "Ed25519 signature", "Proof package total", "Per-participant sent",
           "Network total", "Partial decryption pkg", "Partial phase total"]


def load_records(logdir, hosts):
    """Read every JSONL log in logdir, keeping only SUCCESS records for the requested hosts."""
    records, failed, profiles_seen = [], 0, set()
    for log_file in sorted(Path(logdir).glob("*.jsonl")):
        for line in open(log_file):
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            profiles_seen.add(record["vm_profile"])
            if hosts and record["vm_profile"] not in hosts:
                continue
            if record["status"] != "SUCCESS":
                failed += 1
                continue
            records.append(record)
    if not records:
        raise SystemExit(f"no successful records in {logdir} for hosts={hosts or 'all'}")
    # A run with failures still yields tables, built from whatever survived, and
    # they look perfectly normal. Say so rather than letting it pass unremarked.
    if failed:
        print(f"WARNING: {failed} FAILED records excluded; tables below use "
              f"{len(records)} of {failed + len(records)} measurements")
    missing = [h for h in hosts if h not in profiles_seen]
    if missing:
        print(f"WARNING: --hosts named {', '.join(missing)}, absent from {logdir}")
    return records


def group_by_config(records):
    """Bucket records by (function, zkp_type, n, t), collecting each metric as a list."""
    measurements = defaultdict(lambda: {"wall_time_ms": [], "output_size_bytes": [], "proof_components": []})
    for record in records:
        config = record["test_config"]
        key = (config["function"], config.get("zkp_type"), config["n"], config["t"])
        measurements[key]["wall_time_ms"].append(record["wall_time_us"] / 1000.0)
        if record["output_size_bytes"] is not None:
            measurements[key]["output_size_bytes"].append(record["output_size_bytes"])
        if record.get("proof_components"):
            measurements[key]["proof_components"].append(record["proof_components"])
    return measurements


def select_measurements(measurements, function, zkp=None, n=None, t=None):
    """Collapse over unspecified dimensions."""
    times_ms, sizes_bytes = [], []
    for (key_function, key_zkp, key_n, key_t), stats in measurements.items():
        if key_function != function or key_zkp != zkp:
            continue
        if n is not None and key_n != n:
            continue
        if t is not None and key_t != t:
            continue
        times_ms += stats["wall_time_ms"]
        sizes_bytes += stats["output_size_bytes"]
    return times_ms, sizes_bytes


def components(measurements, zkp):
    """The four Table IV component sizes, as measured on the proofs generated.

    Averaged over every proof, not taken from one sample: the zk-STARK proof
    varies in size run to run, so a single sample's component would not be
    consistent with the mean package total reported beside it.
    """
    component_samples = []
    for (key_function, key_zkp, _, _), stats in measurements.items():
        if key_function == FUNC_PROOF_GEN and key_zkp == zkp:
            component_samples += stats["proof_components"]
    if not component_samples:
        return None
    return tuple(round(st.mean([sample[field] for sample in component_samples])) for field in
                 ("elgamal_bytes", "schnorr_bytes", "zkp_bytes", "signature_bytes"))


def write_csv(path, header, rows):
    """Write a CSV file with the given header and rows."""
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def table_ii(measurements, out_dir):
    """TABLE II: per-variant ZKP prove/verify time and proof size."""
    COLUMN_WIDTH = 18
    print("\nTABLE II  ZKP time and size")
    print(f"{'variant':<12}" + "".join(f"{h:>{COLUMN_WIDTH}}" for h in
          ("ProofGen (ms)", "ProofVerify (ms)", "size (B)")))
    rows = []
    for zkp in ZKPS:
        # compute
        gen_ms, gen_sizes = select_measurements(measurements, FUNC_PROOF_GEN, zkp)
        ver_ms, _ = select_measurements(measurements, FUNC_PROOF_VERIFY, zkp)
        if not gen_ms or not ver_ms:
            print(f"{zkp:<12}no data")
            continue
        gen_mean, gen_stdev = st.mean(gen_ms), st.stdev(gen_ms) if len(gen_ms) > 1 else 0.0
        ver_mean, ver_stdev = st.mean(ver_ms), st.stdev(ver_ms) if len(ver_ms) > 1 else 0.0
        size_bytes = round(st.mean(gen_sizes)) if gen_sizes else None
        # print
        cells = [f"{gen_mean:.2f}±{gen_stdev:.2f}", f"{ver_mean:.2f}±{ver_stdev:.2f}",
                 str(size_bytes) if size_bytes is not None else "-"]
        print(f"{zkp:<12}" + "".join(f"{c:>{COLUMN_WIDTH}}" for c in cells))
        rows.append([zkp, round(gen_mean, 2), round(gen_stdev, 2),
                     round(ver_mean, 2), round(ver_stdev, 2), size_bytes])
    # write csv
    write_csv(out_dir / "table2.csv",
              ["variant", "gen_ms", "gen_sd", "ver_ms", "ver_sd", "size_b"], rows)


def table_iii(measurements, out_dir, n, t):
    """Overhead of verifiability, in the row and column layout of the paper."""
    COLUMN_WIDTH = 14
    # compute
    prove_ms_by_zkp, verify_ms_by_zkp, size_by_zkp = {}, {}, {}
    for zkp in ZKPS:
        gen_ms, gen_sizes = select_measurements(measurements, FUNC_PROOF_GEN, zkp)
        ver_ms, _ = select_measurements(measurements, FUNC_PROOF_VERIFY, zkp)
        prove_ms_by_zkp[zkp] = st.mean(gen_ms) if gen_ms else None
        verify_ms_by_zkp[zkp] = st.mean(ver_ms) if ver_ms else None
        size_by_zkp[zkp] = round(st.mean(gen_sizes)) if gen_sizes else None

    def format_ms(x):
        return "-" if x is None else f"{x:.2f}"

    # Round time is the unverified-aggregation baseline plus this variant's own
    # prove and n-1 verifies, which is how the paper composes it.
    baseline_ms, _ = select_measurements(measurements, FUNC_BASELINE_ROUND, None, n)
    baseline_mean = st.mean(baseline_ms) if baseline_ms else None
    round_time_cells = []
    for zkp in ZKPS:
        prove_ms = prove_ms_by_zkp[zkp]
        verify_ms = verify_ms_by_zkp[zkp]
        if baseline_mean is None or prove_ms is None or verify_ms is None:
            round_time_cells.append("-")
        else:
            round_time_cells.append(f"{baseline_mean + prove_ms + (n - 1) * verify_ms:.2f}")

    def print_block(title, baseline_row, zkp_columns):
        print(f"\n{title}")
        print(f"{'metric':<24}{'Baseline':>10}" + "".join(f"{zkp:>{COLUMN_WIDTH}}" for zkp in ZKPS))
        for label, baseline_cell, cells in zip(ROWS_III, baseline_row, zkp_columns):
            print(f"{label:<24}{baseline_cell:>10}" + "".join(f"{c:>{COLUMN_WIDTH}}" for c in cells))

    # print
    print_block(f"TABLE III  overhead of verifiability, n={n}",
                ["0.00", "0.00", "0.00", "0", format_ms(baseline_mean), "no", "no"],
                [[format_ms(prove_ms_by_zkp[zkp]) for zkp in ZKPS],
                 [format_ms(verify_ms_by_zkp[zkp]) for zkp in ZKPS],
                 [format_ms((prove_ms_by_zkp[zkp] or 0) + (verify_ms_by_zkp[zkp] or 0)) for zkp in ZKPS],
                 [str(size_by_zkp[zkp]) if size_by_zkp[zkp] else "-" for zkp in ZKPS],
                 round_time_cells,
                 ["yes"] * 3,
                 ["yes"] * 3])

    # write csv
    write_csv(out_dir / "table3.csv", ["variant", "prove_ms", "verify_ms", "per_peer_ms", "size_b"],
              [[zkp, round(prove_ms_by_zkp[zkp] or 0, 2), round(verify_ms_by_zkp[zkp] or 0, 2),
                round((prove_ms_by_zkp[zkp] or 0) + (verify_ms_by_zkp[zkp] or 0), 2), size_by_zkp[zkp]]
               for zkp in ZKPS])


def table_iv(measurements, out_dir, n, t):
    """Communication overhead, in the row and column layout of the paper."""
    COLUMN_WIDTH = 14
    # compute
    pkg_size_by_zkp = {}
    for zkp in ZKPS:
        _, gen_sizes = select_measurements(measurements, FUNC_PROOF_GEN, zkp)
        pkg_size_by_zkp[zkp] = round(st.mean(gen_sizes)) if gen_sizes else None
    _, partial_sizes = select_measurements(measurements, FUNC_PARTIAL_GEN, None, n)
    partial_pkg_size = round(st.mean(partial_sizes)) if partial_sizes else None

    def print_block(title, zkp_columns):
        print(f"\n{title}")
        print(f"{'component':<30}" + "".join(f"{zkp:>{COLUMN_WIDTH}}" for zkp in ZKPS))
        for label, cells in zip(ROWS_IV, zkp_columns):
            print(f"{label:<30}" + "".join(f"{c:>{COLUMN_WIDTH}}" for c in cells))

    components_by_zkp = {zkp: components(measurements, zkp) for zkp in ZKPS}
    sent_kb_by_zkp = {zkp: pkg_size_by_zkp[zkp] * (n - 1) / 1000 if pkg_size_by_zkp[zkp] else None
                      for zkp in ZKPS}
    network_mb_by_zkp = {zkp: pkg_size_by_zkp[zkp] * n * (n - 1) / 1e6 if pkg_size_by_zkp[zkp] else None
                         for zkp in ZKPS}
    # t participants each broadcast a partial to the other n-1, so t(n-1)
    # messages, not the n(n-1) of the proof-broadcast phase.
    partial_phase_mb = partial_pkg_size * t * (n - 1) / 1e6 if partial_pkg_size else None
    # print
    print_block(f"TABLE IV  communication, n={n}, t={t}",
                [[f"{components_by_zkp[zkp][0]} B" if components_by_zkp[zkp] else "-" for zkp in ZKPS],
                 [f"{components_by_zkp[zkp][1]} B" if components_by_zkp[zkp] else "-" for zkp in ZKPS],
                 [f"{components_by_zkp[zkp][2]} B" if components_by_zkp[zkp] else "-" for zkp in ZKPS],
                 [f"{components_by_zkp[zkp][3]} B" if components_by_zkp[zkp] else "-" for zkp in ZKPS],
                 [f"{pkg_size_by_zkp[zkp]} B" if pkg_size_by_zkp[zkp] else "-" for zkp in ZKPS],
                 [f"{sent_kb_by_zkp[zkp]:.1f} KB" if sent_kb_by_zkp[zkp] else "-" for zkp in ZKPS],
                 [f"{network_mb_by_zkp[zkp]:.1f} MB" if network_mb_by_zkp[zkp] else "-" for zkp in ZKPS],
                 [f"{partial_pkg_size} B" if partial_pkg_size else "-"] * 3,
                 [f"{partial_phase_mb:.2f} MB" if partial_phase_mb else "-"] * 3])

    # write csv
    write_csv(out_dir / "table4.csv", ["variant", "pkg_b", "sent_kb", "net_mb"],
              [[zkp, pkg_size_by_zkp[zkp], round(sent_kb_by_zkp[zkp], 1), round(network_mb_by_zkp[zkp], 1)]
               for zkp in ZKPS if pkg_size_by_zkp[zkp]])


def table_v(measurements, out_dir, n, threads=8):
    """TABLE V: benchmark operations mapped onto phases of a federated-learning round."""
    print(f"\nTABLE V  mapped to an FL round, n={n}, Bulletproof")
    # compute
    gen_ms, _ = select_measurements(measurements, FUNC_PROOF_GEN, "Bulletproof")
    verify_ms, _ = select_measurements(measurements, FUNC_PROOF_VERIFY, "Bulletproof")
    partial_gen_ms, _ = select_measurements(measurements, FUNC_PARTIAL_GEN, None, n)
    agg_compute_ms, _ = select_measurements(measurements, FUNC_AGG_COMPUTE, None, n)
    if not (gen_ms and verify_ms and partial_gen_ms and agg_compute_ms):
        print("  insufficient data")
        return
    submit_ms = st.mean(gen_ms)
    peer_verify_1_thread_ms = (n - 1) * st.mean(verify_ms)
    peer_verify_n_threads_ms = peer_verify_1_thread_ms / threads
    recovery_ms = st.mean(partial_gen_ms) + st.mean(agg_compute_ms)
    rows = [
        ("Input submission", submit_ms),
        (f"Peer verification x{n-1}, 1 thread", peer_verify_1_thread_ms),
        (f"Peer verification x{n-1}, {threads} threads", peer_verify_n_threads_ms),
        ("Result recovery", recovery_ms),
        ("Total, 1 thread", submit_ms + peer_verify_1_thread_ms + recovery_ms),
        (f"Total, {threads} threads", submit_ms + peer_verify_n_threads_ms + recovery_ms),
    ]
    # print
    print(f"{'phase':<38}{'ms':>10}")
    for label, ms in rows:
        print(f"{label:<38}{ms:>10.1f}")
    # Relative overhead against the 10-60 s FL round cited from ref [32].
    total_1_thread_ms = submit_ms + peer_verify_1_thread_ms + recovery_ms
    total_n_threads_ms = submit_ms + peer_verify_n_threads_ms + recovery_ms
    print(f"\n  overhead of a 10 s FL round: {100*total_1_thread_ms/10000:.2f}% (1 thread)"
          f"   {100*total_n_threads_ms/10000:.2f}% ({threads} threads)")
    print(f"  overhead of a 60 s FL round: {100*total_1_thread_ms/60000:.2f}% (1 thread)"
          f"   {100*total_n_threads_ms/60000:.2f}% ({threads} threads)")
    # write csv
    write_csv(out_dir / "table5.csv", ["phase", "ms"],
              [[label, round(ms, 1)] for label, ms in rows])


def figures(measurements, out_dir):
    """Figure 5: network-dependent operations plotted against participant count."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\nmatplotlib not installed, skipping figures")
        return

    plt.figure(figsize=(7, 5))
    for function in NET_OPS:
        # collapse the threshold dimension: one point per n, not per (n,t)
        wall_times_by_n = defaultdict(list)
        for (key_function, _, key_n, _), stats in measurements.items():
            if key_function == function:
                wall_times_by_n[key_n] += stats["wall_time_ms"]
        points = sorted((key_n, st.mean(times)) for key_n, times in wall_times_by_n.items())
        if points:
            plt.plot([p[0] for p in points], [p[1] for p in points], marker="o", label=function)
    plt.xscale("log")
    plt.yscale("log")
    plt.xlabel("network size (n)")
    plt.ylabel("wall time (ms)")
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_dir / "figure5.png", dpi=200)
    plt.close()
    print(f"\nwrote figure5.png to {out_dir}")


def main():
    """Parse CLI args, load the logs, and regenerate every table and figure."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--logs", default="results")
    parser.add_argument("--hosts", default="", help="comma-separated subset, e.g. VM3,VM7,VM8")
    parser.add_argument("--out", default="output")
    parser.add_argument("--n", type=int, default=100)
    parser.add_argument("--t", type=int, default=50)
    args = parser.parse_args()

    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    records = load_records(args.logs, hosts)
    measurements = group_by_config(records)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not any(r["test_config"]["n"] == args.n for r in records):
        ns = sorted({r["test_config"]["n"] for r in records})
        print(f"WARNING: no records at n={args.n}; Tables III-V will be mostly empty. "
              f"Sizes present: {ns}. Pass --n to pick one.")

    hosts_used = sorted({r["vm_profile"] for r in records})
    print(f"logs   : {args.logs}")
    print(f"hosts  : {', '.join(hosts_used)}" + ("" if hosts else "   (all; pass --hosts to restrict)"))
    print(f"records: {len(records)}")

    table_ii(measurements, out_dir)
    table_iii(measurements, out_dir, args.n, args.t)
    table_iv(measurements, out_dir, args.n, args.t)
    table_v(measurements, out_dir, args.n)
    figures(measurements, out_dir)
    print(f"\ncsv written to {out_dir}")


if __name__ == "__main__":
    main()
