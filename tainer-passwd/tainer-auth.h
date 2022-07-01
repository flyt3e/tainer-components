#ifndef TAINER_AUTH_H
#define TAINER_AUTH_H

#include <stdbool.h>

# define AUTH_HASH_FILE_PATH "/data/data/me.flytree.tainer/access_hash"

#ifdef  __cplusplus
extern "C" {
#endif

// Hash password using PBKDF function.
// Returns digest (in binary form) or NULL if failed.
unsigned char *tainer_passwd_hash(const char *password);

// Update file that stores password hash
// Return true on success, false otherwise.
bool tainer_change_passwd(const char *new_password);

// Check validity of password (user name is ignored).
// Return true if password is ok, otherwise return false.
bool tainer_auth(const char *user, const char *password);

#ifdef  __cplusplus
}
#endif

#endif
