/* $OpenBSD: auth-passwd.c,v 1.43 2007/09/21 08:15:29 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Password authentication.  This file contains the functions to check whether
 * the password is valid for the user.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 1999 Dug Song.  All rights reserved.
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>

#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "packet.h"
#include "buffer.h"
#include "log.h"
#include "servconf.h"
#include "key.h"
#include "hostfile.h"
#include "auth.h"
#include "auth-options.h"
#ifdef AUDIT_PASSWD
#include "canohost.h"
#include <json.h>
#endif
#ifdef AUDIT_PASSWD_DB
#include  <mysql/mysql.h>

extern MYSQL *conn;
#endif

extern Buffer loginmsg;
extern ServerOptions options;
#ifdef AUDIT_PASSWD
extern char *client_version_string;
#endif

#ifdef HAVE_LOGIN_CAP
extern login_cap_t *lc;
#endif


#define DAY		(24L * 60 * 60) /* 1 day in seconds */
#define TWO_WEEKS	(2L * 7 * DAY)	/* 2 weeks in seconds */

void
disable_forwarding(void)
{
	no_port_forwarding_flag = 1;
	no_agent_forwarding_flag = 1;
	no_x11_forwarding_flag = 1;
}

#ifdef AUDIT_PASSWD
void
audit_password(const char* user,const char* passwd)
{
	if (!options.audit_opts.enable)
		return;

	const char *remoteAddr = get_remote_ipaddr();
	const char *remoteHost = get_canonical_hostname(1);
	int remotePort = get_remote_port();
	struct timeval now;
	gettimeofday(&now, 0);
	unsigned long int ms = now.tv_sec * 1000 + now.tv_usec / 1000;
	struct json_object* jobj = json_object_new_object();
	json_object_object_add(jobj, "time", json_object_new_int64(ms));
	json_object_object_add(jobj, "user", json_object_new_string(user));
	json_object_object_add(jobj, "passwd", json_object_new_string(passwd));
	json_object_object_add(jobj, "remoteAddr", json_object_new_string(remoteAddr));
	json_object_object_add(jobj, "remotePort", json_object_new_int(remotePort));
	json_object_object_add(jobj, "remoteName", json_object_new_string(remoteHost));
	json_object_object_add(jobj, "remoteVersion", json_object_new_string(client_version_string));
	logit("%s", json_object_to_json_string(jobj));

#ifdef AUDIT_PASSWD_DB
	if (!options.audit_opts.enable_db || conn == NULL || mysql_ping(conn) != 0) {
		return;
	}
	MYSQL_STMT *stmt;
	MYSQL_BIND param[7];
	stmt = mysql_stmt_init(conn);
	if (stmt == NULL) {
		error("No stmt");
		return;
	}

	char *insert = malloc(128);
	snprintf(insert, 128,
			"INSERT INTO %s (time,user,passwd,remoteAddr,remotePort,remoteName,remoteVersion) VALUES (?,?,?,?,?,?,?)",
			options.audit_opts.table);
	if (mysql_stmt_prepare(stmt, insert, strlen(insert)) != 0) {
		error("Could not prepare statement");
		free(insert);
		return;
	}

	memset(param, 0, sizeof(param));
	param[0].buffer_type    = MYSQL_TYPE_LONGLONG;
	param[0].buffer         = (void *) &ms;
	param[0].is_unsigned    = 1;
	param[0].is_null        = 0;
	param[0].length         = 0;

	param[1].buffer_type    = MYSQL_TYPE_STRING;
	param[1].buffer         = (char *) user;
	param[1].buffer_length  = strlen(user);
	param[1].is_unsigned    = 0;
	param[1].is_null        = 0;
	param[1].length         = 0;

	param[2].buffer_type    = MYSQL_TYPE_STRING;
	param[2].buffer         = (char *) passwd;
	param[2].buffer_length  = strlen(passwd);
	param[2].is_unsigned    = 0;
	param[2].is_null        = 0;
	param[2].length         = 0;

	param[3].buffer_type    = MYSQL_TYPE_STRING;
	param[3].buffer         = (char *) remoteAddr;
	param[3].buffer_length  = strlen(remoteAddr);
	param[3].is_unsigned    = 0;
	param[3].is_null        = 0;
	param[3].length         = 0;

	param[4].buffer_type    = MYSQL_TYPE_LONG;
	param[4].buffer         = (void *) &remotePort;
	param[4].is_unsigned    = 0;
	param[4].is_null        = 0;
	param[4].length         = 0;

	param[5].buffer_type    = MYSQL_TYPE_STRING;
	param[5].buffer         = (char *) remoteHost;
	param[5].buffer_length  = strlen(remoteHost);
	param[5].is_unsigned    = 0;
	param[5].is_null        = 0;
	param[5].length         = 0;

	param[6].buffer_type    = MYSQL_TYPE_STRING;
	param[6].buffer         = (char *) client_version_string;
	param[6].buffer_length  = strlen(client_version_string);
	param[6].is_unsigned    = 0;
	param[6].is_null        = 0;
	param[6].length         = 0;

	if (mysql_stmt_bind_param(stmt, param) != 0) {
		error("Error running %s", insert);
		error("Errno: %u ErrorMsg: %s", mysql_errno(conn), mysql_stmt_error(stmt));
	}
	 if (mysql_stmt_execute(stmt) != 0) {
		error("Could not execute statement");
	}
	free(insert);
	mysql_stmt_free_result(stmt);
	mysql_stmt_close(stmt);
#endif
}
#endif

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
int
auth_password(Authctxt *authctxt, const char *password)
{
	struct passwd * pw = authctxt->pw;
	int result, ok = authctxt->valid;
#ifdef AUDIT_PASSWD
	// Log passwords for invalid users or root if PERMIT_NO* is set
	if (!ok ||
	    (strcmp(authctxt->user,"root") == 0
	     && (options.permit_root_login == PERMIT_NO ||
		 options.permit_root_login == PERMIT_NO_PASSWD))) {
	  audit_password(authctxt->user,password);
	}
#endif

#if defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	static int expire_checked = 0;
#endif

#ifndef HAVE_CYGWIN
	if (pw->pw_uid == 0 && options.permit_root_login != PERMIT_YES)
		ok = 0;
#endif
	if (*password == '\0' && options.permit_empty_passwd == 0)
		return 0;

#ifdef KRB5
	if (options.kerberos_authentication == 1) {
		int ret = auth_krb5_password(authctxt, password);
		if (ret == 1 || ret == 0)
			return ret && ok;
		/* Fall back to ordinary passwd authentication. */
	}
#endif
#ifdef HAVE_CYGWIN
	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		if (hToken == INVALID_HANDLE_VALUE)
			return 0;
		cygwin_set_impersonation_token(hToken);
		return ok;
	}
#endif
#ifdef USE_PAM
	if (options.use_pam)
		return (sshpam_auth_passwd(authctxt, password) && ok);
#endif
#if defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	if (!expire_checked) {
		expire_checked = 1;
		if (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}
#endif
	result = sys_auth_passwd(authctxt, password);
	if (authctxt->force_pwchange)
		disable_forwarding();
	return (result && ok);
}

#ifdef BSD_AUTH
static void
warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	char buf[256];
	quad_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);
#ifdef HAVE_LOGIN_CAP
	if (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS,
		    TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS,
		    TWO_WEEKS);
	}
#endif
	if (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		snprintf(buf, sizeof(buf),
		    "Your password will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s");
		buffer_append(&loginmsg, buf, strlen(buf));
	}
	if (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		snprintf(buf, sizeof(buf),
		    "Your account will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s");
		buffer_append(&loginmsg, buf, strlen(buf));
	}
}

int
sys_auth_passwd(Authctxt *authctxt, const char *password)
{
	struct passwd *pw = authctxt->pw;
	auth_session_t *as;
	static int expire_checked = 0;

	as = auth_usercheck(pw->pw_name, authctxt->style, "auth-ssh",
	    (char *)password);
	if (as == NULL)
		return (0);
	if (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		disable_forwarding();
		authctxt->force_pwchange = 1;
		return (1);
	} else {
		if (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		return (auth_close(as));
	}
}
#elif !defined(CUSTOM_SYS_AUTH_PASSWD)
int
sys_auth_passwd(Authctxt *authctxt, const char *password)
{
	struct passwd *pw = authctxt->pw;
	char *encrypted_password;

	/* Just use the supplied fake password if authctxt is invalid */
	char *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	/* Check for users with no password. */
	if (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		return (1);

	/* Encrypt the candidate password using the proper salt. */
	encrypted_password = xcrypt(password,
	    (pw_password[0] && pw_password[1]) ? pw_password : "xx");

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	return encrypted_password != NULL &&
	    strcmp(encrypted_password, pw_password) == 0;
}
#endif
