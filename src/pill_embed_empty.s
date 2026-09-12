// Empty PILL stub for I3_HOST. The jam is at PILL_BASE from the firmware
// loader (initramfs), never from this image.

    .section .rodata
    .balign 8
    .global _pill_embed_start
_pill_embed_start:
    .global _pill_embed_end
_pill_embed_end:
