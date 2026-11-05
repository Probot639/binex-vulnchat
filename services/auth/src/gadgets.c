/* gadgets.c -- ROP gadgets planted in authd for the mprotect chain.
 *
 * This is deliberate, part of the lab's exploit design (see README /
 * Makefile): NX forces a return-oriented chain, and the intended path is
 * to resolve mprotect at runtime from an already-resolved libc GOT entry
 * rather than leaking libc directly.
 *
 *   pop eax ; ret                 -> load &got[<known libc fn>] into eax
 *   pop ecx ; ret                 -> load (mprotect - <that fn>) delta into ecx
 *   mov eax,[eax] ; add eax,ecx   -> deref GOT, add delta -> &mprotect
 *   jmp eax                       -> dispatch into mprotect
 *
 * Emitted as a file-scope asm block so the exact bytes land in .text with
 * no compiler prologue/epilogue in the way. The object is linked
 * unconditionally into authd (see Makefile SRVOBJ), so the symbol is
 * present even though nothing calls it. 32-bit only, to match -m32.
 */

#if defined(__i386__)

__asm__(
    ".text\n"
    ".globl rop_gadgets\n"
    ".type  rop_gadgets, @function\n"
"rop_gadgets:\n"
    "    pop  %eax\n"          /* 58          pop eax            */
    "    ret\n"                /* c3          ret                */
    "    pop  %ecx\n"          /* 59          pop ecx            */
    "    ret\n"                /* c3          ret                */
    "    mov  (%eax), %eax\n"  /* 8b 00       mov eax,[eax]      */
    "    add  %ecx, %eax\n"    /* 01 c8       add eax,ecx        */
    "    jmp  *%eax\n"         /* ff e0       jmp eax            */
    ".size  rop_gadgets, .-rop_gadgets\n"
);

#else
#warning "gadgets.c: ROP gadgets are 32-bit only; build with -m32 (see Makefile)"
#endif
