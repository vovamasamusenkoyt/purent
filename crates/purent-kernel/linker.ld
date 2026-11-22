ENTRY(KiSystemStartup)

SECTIONS {
    . = 0xFFFFF80000200000;

    .text : {
        *(.text.KiSystemStartup)
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
    }

    /DISCARD/ : {
        *(.eh_frame)
        *(.note .note.*)
    }
}
