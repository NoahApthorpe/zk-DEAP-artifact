# Build and check the artifact in a fixed environment.
#
#   docker build -t zk-deap .
#   docker run --rm zk-deap
#
# The default command runs run_all.sh. For anything else, e.g.
#   docker run --rm -it zk-deap bash

FROM rust:1.97-bookworm

# git for the halo2 dependency, curl for the fixture server health check,
# python3 for the analysis script.
RUN apt-get update && apt-get install -y --no-install-recommends \
      git curl python3 python3-venv ca-certificates pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /zk-deap
COPY . .

# --locked so the committed Cargo.lock is used exactly as given.
RUN cargo build --release --locked

RUN python3 -m venv .venv \
 && .venv/bin/pip install --quiet matplotlib

CMD ["./run_all.sh"]
