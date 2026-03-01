# ── Stage 1: Builder ─────────────────────────────────────────────
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/.cargo/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 \
    python3.12-dev \
    python3-pip \
    build-essential \
    curl \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

WORKDIR /rtosploit
COPY . .

# Build Python package
RUN pip3 install --break-system-packages -e .

# Build Rust crates (release)
RUN cargo build --release

# ── Stage 2: Runtime ────────────────────────────────────────────
FROM ubuntu:24.04

LABEL description="RTOSploit — RTOS Exploitation & Bare-Metal Fuzzing Framework"
LABEL version="0.1.0"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 \
    python3-pip \
    qemu-system-arm \
    qemu-system-misc \
    gdb-multiarch \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /rtosploit

# Copy Python site-packages (installed dependencies + rtosploit egg-link)
COPY --from=builder /usr/lib/python3/dist-packages /usr/lib/python3/dist-packages
COPY --from=builder /usr/local/lib/python3.12/dist-packages /usr/local/lib/python3.12/dist-packages
COPY --from=builder /usr/local/bin/rtosploit /usr/local/bin/rtosploit

# Copy Rust release binaries
COPY --from=builder /rtosploit/target/release/svd-gen /usr/local/bin/svd-gen

# Copy project source, configs, and bundled firmware
COPY rtosploit/ ./rtosploit/
COPY configs/ ./configs/
COPY vulnrange/ ./vulnrange/
COPY pyproject.toml ./

# Expose GDB stub and serial/UART ports
EXPOSE 1234 4444

ENTRYPOINT ["rtosploit"]
CMD ["--help"]
