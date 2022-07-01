
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

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

// Hash password using PBKDF function.
// Returns digest (in binary form) or NULL if failed.
unsigned char *tainer_passwd_hash(const char *password) {
    const unsigned char *salt = (const unsigned char *) "tainer!";
    unsigned char *pbkdf_digest;

    if ((pbkdf_digest = (unsigned char *) malloc(SHA_DIGEST_LENGTH * sizeof(unsigned char))) == NULL) {
        fprintf(stderr, "%s(): failed to allocate memory.\n", __func__);
        return NULL;
    }

    if (!PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt,
        strlen((const char *)salt), 65536, SHA_DIGEST_LENGTH, pbkdf_digest)) {
        return NULL;
    }

    return pbkdf_digest;
}

// Update file that stores password hash
// Return true on success, false otherwise.
bool tainer_change_passwd(const char *new_password) {
    FILE *tainer_auth_file;
    bool is_password_changed = false;

    unsigned char *hashed_password = tainer_passwd_hash(new_password);
    if (!hashed_password) {
        return false;
    }

    if ((tainer_auth_file = fopen(AUTH_HASH_FILE_PATH, "w")) != NULL) {
        int n = fwrite(hashed_password, sizeof(unsigned char), SHA_DIGEST_LENGTH, tainer_auth_file);
        fflush(tainer_auth_file);
        fclose(tainer_auth_file);

        erase_ptr(hashed_password, n);

        if (n == SHA_DIGEST_LENGTH) {
            is_password_changed = true;
        } else {
            fprintf(stderr, "%s(): password hash is truncated.\n", __func__);
        }
    }

    free(hashed_password);

    return is_password_changed;
}

// Check validity of password (user name is ignored).
// Return true if password is ok, otherwise return false.
bool tainer_auth(const char *user, const char *password) {
    FILE *tainer_auth_file;
    unsigned char *auth_info;
    unsigned char *hashed_password;
    bool is_authenticated = false;

    if ((auth_info = (unsigned char *)malloc(SHA_DIGEST_LENGTH * sizeof(unsigned char))) == NULL) {
        fprintf(stderr, "%s(): failed to allocate memory.\n", __func__);
        return false;
    }

    if ((hashed_password = tainer_passwd_hash(password)) == NULL) {
        free(auth_info);
        return false;
    }

    if ((tainer_auth_file = fopen(AUTH_HASH_FILE_PATH, "rb")) != NULL) {
        int n = fread(auth_info, sizeof(unsigned char), SHA_DIGEST_LENGTH, tainer_auth_file);
        fclose(tainer_auth_file);

        if (n == SHA_DIGEST_LENGTH) {
            if (memcmp(auth_info, hashed_password, SHA_DIGEST_LENGTH) == 0) {
                is_authenticated = true;
            }
        } else {
            fprintf(stderr, "%s(): password hash is truncated.\n", __func__);
        }
    }

    erase_ptr(auth_info, SHA_DIGEST_LENGTH);
    erase_ptr(hashed_password, SHA_DIGEST_LENGTH);
    free(auth_info);
    free(hashed_password);

    return is_authenticated;
}
