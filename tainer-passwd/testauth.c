#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tainer-auth.h"

// PoC of 'password login'

int main(void) {
    char *password;

    password = getpass("Password: ");
    if (!password) {
        puts("Failed to read password input.");
        return EXIT_FAILURE;
    }

    if (tainer_auth("tainer", password)) {
        puts("Password is OK");
    } else {
        puts("Invalid password.");
    }
}
