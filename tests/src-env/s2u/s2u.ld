OUTPUT_ARCH("riscv")
ENTRY(_start)

SECTIONS {
    . = 0x80000000;

    .tohost : ALIGN(0x1000) {
        *(.tohost)
    }

    . += 0x1000;

    .text : ALIGN(0x1000) {
        __TEXT_START__ = .;
        *(.stext .stext.*)
        __TEXT_END__ = .;
    }

    .rodata : ALIGN(8) {
        *(.srodata .srodata.*)
    }

    .data : ALIGN(8) {
        *(.sdata .sdata.*)
    }

    .bss : ALIGN(0x1000) {
        __SBSS_START__ = .;
        *(.sbss .sbss.*)
        __SBSS_END__ = .;
    }

    ASSERT(. <= 0x80010000,
           "S 组段超出 0x8000_FFFF: 页表只把 0x8000_0000 起的 16 页映射为 S 模式可执行")

    . = 0x80010000;

    .utext : ALIGN(0x1000) {
        __UTEXT_START__ = .;
        *(.utext .utext.*)
        __UTEXT_END__ = .;
    }

    .urodata : ALIGN(8) {
        *(.urodata .urodata.*)
    }

    .udata : ALIGN(8) {
        *(.udata .udata.*)
    }

    .ubss : ALIGN(8) {
        __UBSS_START__ = .;
        *(.ubss .ubss.*)
        __UBSS_END__ = .;
    }

    ASSERT(. <= 0x80012000,
           "U 组段超出 0x8001_1FFF: 页表只把 0x8001_0000 起的 2 页映射为 U 模式可访问")

    _end = .;
}
