#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "tainer-auth.h"

char *get_shell() {
    char *shell = NULL;
    
    //fprintf(stderr, "Warning: failed to detect login shell, using the /system/bin/sh instead.\n");
    shell = "/system/bin/sh";

    setenv("SHELL", shell, 1);

    return strdup(shell);
}


void init_login() {
    char *shell = get_shell();
    char *shell_name = basename(shell);
    execl(shell, shell_name, "-l", NULL);
    free(shell);
    exit(1);
}

int main(int argc, char **argv) {
    //chdir(tainer_HOME);

    if (access(AUTH_HASH_FILE_PATH, R_OK) != 0) {
        fprintf(stderr, "Error: password is not set.\n");
    }

    for (int attempt=0; attempt<3; attempt++) {
        char *password = getpass("password: ");

        if (!password) {
            puts("Failed to read password input.");
            continue;
        }

        if (tainer_auth("tainer", password)) {
            init_login();
        } else {
            puts("Invalid password.");
        }
    }

    return EXIT_FAILURE;
}
