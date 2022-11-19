#include <Windows.h>
#include <winnt.h>
#include <minwindef.h>

#include <stdio.h>
#include <string.h>

#define BUF_SIZE (1 << 20)

char target[100];
unsigned char buf[BUF_SIZE];

int main(int argc, char *argv[]) {
    if(argc != 2) return 1;
    FILE *fp;
    fp = fopen(argv[1], "rb");
    fread(buf, 1, 1 << 20, fp);
    int n = BUF_SIZE;
    while(buf[n - 1] == 0) n--;
    // output
    printf("#define CODE_SIZE %d\n", n);
    printf("unsigned char shellCode[CODE_SIZE] = ");
    printf("{");
    for(int i = 0; i < n; i++) {
        printf("%#02x", buf[i]);
        if(i != n - 1) printf(", ");
    }
    printf("};\n");
    return 0;
}