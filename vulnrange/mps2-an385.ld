/* RTOSploit VulnRange -- MPS2-AN385 Linker Script
 * ARM Cortex-M3, MPS2 AN385 board memory layout.
 *
 * MPS2-AN385 Memory Map:
 *   FLASH: 0x00000000 - 0x003FFFFF (4 MiB, read-only code)
 *   SRAM:  0x20000000 - 0x203FFFFF (4 MiB, read-write data/stack/heap)
 */

MEMORY {
  FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 4M
  SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 4M
}

SECTIONS {
  /* Vector table must be at flash origin */
  .vectors : {
    KEEP(*(.vectors))
  } > FLASH

  /* Code */
  .text : {
    *(.text .text.*)
    *(.glue_7)
    *(.glue_7t)
    . = ALIGN(4);
  } > FLASH

  /* Read-only data */
  .rodata : {
    *(.rodata .rodata.*)
    . = ALIGN(4);
  } > FLASH

  /* ARM exception unwinding (required for C++) */
  .ARM.extab : { *(.ARM.extab*) } > FLASH
  .ARM.exidx : { *(.ARM.exidx*) } > FLASH

  /* Initialized data (loaded from flash, runs in SRAM) */
  _sidata = LOADADDR(.data);
  .data : {
    . = ALIGN(4);
    _sdata = .;
    *(.data .data.*)
    . = ALIGN(4);
    _edata = .;
  } > SRAM AT > FLASH

  /* Zero-initialized data */
  .bss : {
    . = ALIGN(4);
    _sbss = .;
    *(.bss .bss.*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > SRAM

  /* Heap region (used by pvPortMalloc / heap_4.c) */
  .heap : {
    . = ALIGN(8);
    PROVIDE(_heap_start = .);
    . += 0x10000;  /* 64 KiB heap */
    PROVIDE(_heap_end = .);
  } > SRAM

  /* Stack region */
  .stack : {
    . = ALIGN(8);
    . += 0x2000;   /* 8 KiB main stack */
    PROVIDE(_stack_top = .);
  } > SRAM
}

/* End of SRAM for stack overflow detection */
PROVIDE(_sram_end = ORIGIN(SRAM) + LENGTH(SRAM));
