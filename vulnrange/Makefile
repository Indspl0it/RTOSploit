# RTOSploit VulnRange -- Vulnerable Firmware Build System
#
# Requirements:
#   arm-none-eabi-gcc (>= 12.0)
#   arm-none-eabi-objcopy
#   cmake (>= 3.20)
#
# Usage:
#   make all               - Build all vulnerable firmware images
#   make CVE-2018-16525    - Build specific range
#   make clean             - Remove build artifacts
#   make list              - List all ranges and build status

CROSS_CC = arm-none-eabi-gcc
OBJCOPY  = arm-none-eabi-objcopy

CFLAGS = -mcpu=cortex-m3 -mthumb -mfloat-abi=soft \
         -O0 -g -fno-stack-protector -fno-pie \
         -Wall -Wno-unused-variable

LDFLAGS = -T mps2-an385.ld -nostartfiles -nostdlib

RANGES = CVE-2018-16525 CVE-2021-43997 CVE-2024-28115 CVE-2018-16528 KOM-ThreadX

.PHONY: all clean list $(RANGES)

all: $(RANGES)

$(RANGES):
	@echo "[BUILD] Building $@..."
	@$(MAKE) -C $@ firmware.bin CROSS_CC=$(CROSS_CC) OBJCOPY=$(OBJCOPY) CFLAGS="$(CFLAGS)" || \
		echo "[WARN] $@ build failed -- check arm-none-eabi-gcc is installed"

list:
	@echo "VulnRange Firmware Status:"
	@for d in $(RANGES); do \
		if [ -f $$d/firmware.bin ] && [ "$$(wc -c < $$d/firmware.bin)" -gt 256 ]; then \
			echo "  [REAL]        $$d"; \
		elif [ -f $$d/firmware.bin ]; then \
			echo "  [PLACEHOLDER] $$d"; \
		else \
			echo "  [MISSING]     $$d"; \
		fi; \
	done

clean:
	@for d in $(RANGES); do rm -f $$d/firmware.bin; done
	@echo "Cleaned."
