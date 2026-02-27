FROM ubuntu:24.04

LABEL description="RTOSploit — RTOS Exploitation & Bare-Metal Fuzzing Framework"
LABEL version="0.1.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/.cargo/bin:$PATH"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 \
    python3.12-venv \
    python3-pip \
    qemu-system-arm \
    gdb-multiarch \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

# Set working directory
WORKDIR /rtosploit

# Copy source
COPY . .

# Install Python package
RUN pip3 install --break-system-packages -e .

# Build Rust crates
RUN . ~/.cargo/env && cargo build --release

ENTRYPOINT ["rtosploit"]
CMD ["--help"]
