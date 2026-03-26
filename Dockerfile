FROM ubuntu:24.04

LABEL description="RTOSploit — RTOS Exploitation & Bare-Metal Fuzzing Framework"
LABEL version="2.6.0"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 \
    python3-pip \
    qemu-system-arm \
    qemu-system-misc \
    gdb-multiarch \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /rtosploit
COPY . .

RUN pip3 install --break-system-packages -e . unicorn

EXPOSE 1234 4444

ENTRYPOINT ["rtosploit"]
CMD ["--help"]
