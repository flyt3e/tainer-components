/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

/* Validates a user password */

#include "includes.h"
#include "session.h"
#include "buffer.h"
#include "dbutil.h"
#include "auth.h"
#include "runopts.h"

#if DROPBEAR_SVR_PASSWORD_AUTH

#include <termux-auth.h>
/* Process a password auth request, sending success or failure messages as
 * appropriate */
void svr_auth_password(int valid_user) {
	
	char *password;
	unsigned int changepw, passwordlen;
 

	/* check if client wants to change password */
	changepw = buf_getbool(ses.payload);
	if (changepw) {
		/* not implemented by this server */
		send_msg_userauth_failure(0, 1);
		return;
	}

	password = buf_getstring(ses.payload, &passwordlen);
/* check if password is valid */
	if (tainer_auth(ses.authstate.pw_name, password)) {
		if (!ses.authstate.pw_name) {
			dropbear_log(LOG_WARNING, "Login name is NULL");
			send_msg_userauth_failure(0, 1);
			return;
		}
		/* successful authentication */
		dropbear_log(LOG_NOTICE, 
				"Password auth succeeded for '%s' from %s",
				ses.authstate.pw_name,
				svr_ses.addrstring);
		send_msg_userauth_success();
	} else {
		dropbear_log(LOG_WARNING,
				"Bad password attempt for '%s' from %s",
				ses.authstate.pw_name,
				svr_ses.addrstring);
		send_msg_userauth_failure(0, 1);
	}
}

#endif
