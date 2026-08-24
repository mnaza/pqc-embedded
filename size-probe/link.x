/* Minimal script: enough to link and measure, not enough to boot anything. */
MEMORY
{
  FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 1024K
  RAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 256K
}

ENTRY(_start)

SECTIONS
{
  .text : {
    *(.text._start)
    *(.text .text.*)
    *(.rodata .rodata.*)
  } > FLASH

  .data : { *(.data .data.*) } > RAM
  .bss  : { *(.bss .bss.*) *(COMMON) } > RAM

  /DISCARD/ : {
    *(.ARM.exidx*)
    *(.ARM.extab*)
    *(.eh_frame*)
    *(.comment)
  }
}
