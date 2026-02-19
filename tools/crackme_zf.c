// crackme_zf.c — Simple ZF-based password crackme
// Compile: cl /Od /Zi crackme_zf.c   (MSVC, no optimizations)
//      or: gcc -O0 -o crackme_zf.exe crackme_zf.c
//
// How to crack with DioProcess:
// 1. Run this program
// 2. In Memory Scanner, set PID to this process
// 3. Find the "test eax, eax" instruction after strcmp
//    (disassemble around the check_password function)
// 4. Right-click address -> "Change Register at This Address"
// 5. Select ZF -> Set (1) -> Install
// 6. Enter any wrong password — access granted!

#include <stdio.h>
#include <string.h>

// Mark volatile so the compiler doesn't optimize away the comparison
volatile const char* SECRET = "DioProcess2025!";

int check_password(const char* input) {
    // strcmp returns 0 when equal -> test eax, eax -> ZF=1 -> je taken
    // If you set ZF=1 at the test instruction, any password works
    int result = strcmp(input, (const char*)SECRET);
    return result == 0;  // compiler generates: test eax, eax / sete al
}

int main(void) {
    char buffer[256];

    printf("=== DioProcess ZF CrackMe ===\n");
    printf("Hint: set ZF=1 at the 'test eax,eax' after strcmp\n\n");

    while (1) {
        printf("Enter password (or 'quit'): ");
        fflush(stdout);

        if (!fgets(buffer, sizeof(buffer), stdin))
            break;

        // Strip newline
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n')
            buffer[len - 1] = '\0';

        if (strcmp(buffer, "quit") == 0)
            break;

        if (check_password(buffer)) {
            printf("[+] ACCESS GRANTED! Welcome in.\n\n");
        } else {
            printf("[-] Wrong password. Try again.\n\n");
        }
    }

    printf("Bye!\n");
    return 0;
}
