    .section .rodata
    .balign 8
    .global _m21_sink_embed_start
_m21_sink_embed_start:
#ifdef M21_SINK_EMBED
    .incbin "m21_sink.pill"
#else
    /* Ordinary historical builds do not carry an M21 second PILL. */
    .byte 0
#endif
    .global _m21_sink_embed_end
_m21_sink_embed_end:
