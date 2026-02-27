# Quickstart Guide

Get up and running with RTOSploit in 5 minutes.

## 1. Install

```bash
pip install rtosploit
rtosploit --version
```

## 2. Emulate a Firmware

```bash
rtosploit emulate --firmware firmware.bin --machine mps2-an385
```

## 3. Analyze a Firmware

```bash
rtosploit analyze --firmware firmware.bin --all
```

## 4. List Exploit Modules

```bash
rtosploit exploit list
```

## 5. Run an Exploit Check

```bash
rtosploit exploit check freertos/mpu_bypass \
  --firmware firmware.bin \
  --machine mps2-an385
```

## 6. Use the Interactive Console

```bash
rtosploit console
```

Then in the console:
```
rtosploit> search freertos
rtosploit> use freertos/mpu_bypass
rtosploit(freertos/mpu_bypass)> show options
rtosploit(freertos/mpu_bypass)> set firmware firmware.bin
rtosploit(freertos/mpu_bypass)> set machine mps2-an385
rtosploit(freertos/mpu_bypass)> check
rtosploit(freertos/mpu_bypass)> exploit
```

## 7. Try a VulnRange Challenge

```bash
rtosploit vulnrange list
rtosploit vulnrange start CVE-2021-43997
rtosploit vulnrange hint CVE-2021-43997
rtosploit vulnrange writeup CVE-2021-43997
```
