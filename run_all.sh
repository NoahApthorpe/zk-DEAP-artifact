#!/bin/bash
# This was made with AI Assistance
# Run everything, in order, on one machine. Each part prints its own output:
# the examples should report sum=3/5, the attack demonstrations 0 failed, and
# the harness a 100% success rate.
set -e

test -f ~/.cargo/env && . ~/.cargo/env

cargo build --release --locked

echo
echo "== KZG parameters (expect 4b67ff25...5664)"
shasum -a 256 trusted_setup/kzg_bn254_8.params 2>/dev/null \
  || sha256sum trusted_setup/kzg_bn254_8.params

echo
echo "== protocol, all three variants: every device should report sum=3/5"
for v in bullet snark stark; do
  echo "-- $v"
  ./target/release/${v}_examples | grep sum=
done

echo
echo "== attack demonstrations: every binary should report 0 failed, 60 cases total"
for t in common bullet snark stark; do
  printf '%-16s %s\n' "$t" "$(./target/release/${t}_penTest | grep '^RESULTS:')"
done

echo
echo "== benchmark on this machine: expect a 100.0% success rate"
# Both processes must agree on the sweep, so export rather than prefixing one of
# them: the harness asks the fixture server for whatever (n,t) it is configured
# to measure, and gets a 404 for anything the server did not precompute.
# defaults, but honour anything already set so the sweep can be widened
export ZKDEAP_SIZES=${ZKDEAP_SIZES:-5,10,20,50,100}
export ZKDEAP_RATIOS=${ZKDEAP_RATIOS:-0.5}
rm -rf results && mkdir results

# Refuse to run against someone else's server: a stale one from an interrupted
# run may hold a different sweep, and the measurements would look fine.
if curl -sf localhost:8080/health >/dev/null 2>&1; then
  echo "something is already serving on port 8080; stop it and re-run"
  exit 1
fi

./target/release/fixture_server >/tmp/zkdeap-fx.log 2>&1 &
fx=$!
# preserve the script's own exit status; 'wait' on a killed job returns 143
trap 'rc=$?; kill $fx 2>/dev/null; wait $fx 2>/dev/null; exit $rc' EXIT

# No fixed timeout: it precomputes every (n,t) up front, which is seconds at
# n<=100 but minutes at n=250 and longer still at n=500. Wait as long as the
# process is alive, and give up only if it dies.
echo -n "generating fixtures"
until curl -sf localhost:8080/health >/dev/null 2>&1; do
  kill -0 $fx 2>/dev/null || { echo; echo "fixture server exited; see /tmp/zkdeap-fx.log"; exit 1; }
  echo -n .
  sleep 2
done
echo " ready"
RAYON_NUM_THREADS=1 ./target/release/test_harness \
  --fixture-server http://localhost:8080 \
  --vm-profile local --device-id 1 --output results/local.jsonl | tail -7

if [ ! -x .venv/bin/python ]; then
  echo
  echo "== analysis skipped: python3 -m venv .venv && ./.venv/bin/pip install matplotlib"
  exit 0
fi

echo
echo "== Tables II-V as measured on this machine; see README.md before comparing"
echo "   them with the paper"
.venv/bin/python analyze.py --logs results --out results
