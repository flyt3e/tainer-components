
/** Utility for setting new password **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tainer-auth.h"

static void erase_ptr(void *ptr, unsigned int len) {
    volatile char *p = ptr;

    if (ptr == NULL) {
        return;
    }

    while (len--) {
        *p++ = 0x0;
    }
}

static char *read_password(const char *prompt) {
    char *password;

    password = strdup(getpass(prompt));

    if (!password) {
        fprintf(stderr, "Failed to read password input.\n");
        return NULL;
    }

    if (strlen(password) == 0) {
        fprintf(stderr, "Password cannot be empty.\n");
        return NULL;
    }

    return password;
}

int main(void) {
    char *password;
    char *password_confirmation;
    int ret = EXIT_FAILURE;

    password = read_password("New password: ");
    if (!password) {
        return ret;
    }

    password_confirmation = read_password("Retype new password: ");
    if (!password_confirmation) {
        return ret;
    }

    if(strcmp(password, password_confirmation) != 0) {
        erase_ptr(password, strlen(password));
        erase_ptr(password_confirmation, strlen(password_confirmation));
        free(password);
        free(password_confirmation);

        puts("Sorry, passwords do not match.");

        return ret;
    }

    if (tainer_change_passwd(password)) {
        puts("New password was successfully set.");
        ret = EXIT_SUCCESS;
    } else {
        puts("Failed to set new password.");
    }

    erase_ptr(password, strlen(password));
    erase_ptr(password_confirmation, strlen(password_confirmation));
    free(password);
    free(password_confirmation);

    return EXIT_SUCCESS;
}
