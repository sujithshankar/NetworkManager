/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2004 - 2014 Red Hat, Inc.
 * Copyright 2005 - 2008 Novell, Inc.
 */

#include "config.h"

#include <glib.h>
#include <gio/gio.h>
#include <glib/gi18n.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <resolv.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/if.h>
#include <linux/if_infiniband.h>

#include "NetworkManagerUtils.h"
#include "nm-platform.h"
#include "nm-utils.h"
#include "nm-core-internal.h"
#include "nm-logging.h"
#include "nm-device.h"
#include "nm-setting-connection.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-auth-utils.h"
#include "nm-posix-signals.h"
#include "nm-dbus-glib-types.h"

/*
 * Some toolchains (E.G. uClibc 0.9.33 and earlier) don't export
 * CLOCK_BOOTTIME even though the kernel supports it, so provide a
 * local definition
 */
#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif

/*
 * nm_ethernet_address_is_valid:
 * @addr: pointer to a binary or ASCII Ethernet address
 * @len: length of @addr, or -1 if @addr is ASCII
 *
 * Compares an Ethernet address against known invalid addresses.

 * Returns: %TRUE if @addr is a valid Ethernet address, %FALSE if it is not.
 */
gboolean
nm_ethernet_address_is_valid (gconstpointer addr, gssize len)
{
	guint8 invalid_addr1[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	guint8 invalid_addr2[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	guint8 invalid_addr3[ETH_ALEN] = {0x44, 0x44, 0x44, 0x44, 0x44, 0x44};
	guint8 invalid_addr4[ETH_ALEN] = {0x00, 0x30, 0xb4, 0x00, 0x00, 0x00}; /* prism54 dummy MAC */
	guchar first_octet;

	g_return_val_if_fail (addr != NULL, FALSE);
	g_return_val_if_fail (len == ETH_ALEN || len == -1, FALSE);

	/* Compare the AP address the card has with invalid ethernet MAC addresses. */
	if (nm_utils_hwaddr_matches (addr, len, invalid_addr1, ETH_ALEN))
		return FALSE;

	if (nm_utils_hwaddr_matches (addr, len, invalid_addr2, ETH_ALEN))
		return FALSE;

	if (nm_utils_hwaddr_matches (addr, len, invalid_addr3, ETH_ALEN))
		return FALSE;

	if (nm_utils_hwaddr_matches (addr, len, invalid_addr4, ETH_ALEN))
		return FALSE;

	/* Check for multicast address */
	if (len == -1)
		first_octet = strtoul (addr, NULL, 16);
	else
		first_octet = ((guint8 *)addr)[0];
	if (first_octet & 0x01)
			return FALSE;
	
	return TRUE;
}


/* nm_utils_ip4_address_clear_host_address:
 * @addr: source ip6 address
 * @plen: prefix length of network
 *
 * returns: the input address, with the host address set to 0.
 */
in_addr_t
nm_utils_ip4_address_clear_host_address (in_addr_t addr, guint8 plen)
{
	return addr & nm_utils_ip4_prefix_to_netmask (plen);
}

/* nm_utils_ip6_address_clear_host_address:
 * @dst: destination output buffer, will contain the network part of the @src address
 * @src: source ip6 address
 * @plen: prefix length of network
 *
 * Note: this function is self assignment safe, to update @src inplace, set both
 * @dst and @src to the same destination.
 */
const struct in6_addr *
nm_utils_ip6_address_clear_host_address (struct in6_addr *dst, const struct in6_addr *src, guint8 plen)
{
	g_return_val_if_fail (plen <= 128, NULL);
	g_return_val_if_fail (src, NULL);
	g_return_val_if_fail (dst, NULL);

	if (plen < 128) {
		guint nbytes = plen / 8;
		guint nbits = plen % 8;

		if (nbytes && dst != src)
			memcpy (dst, src, nbytes);
		if (nbits) {
			dst->s6_addr[nbytes] = (src->s6_addr[nbytes] & (0xFF << (8 - nbits)));
			nbytes++;
		}
		if (nbytes <= 15)
			memset (&dst->s6_addr[nbytes], 0, 16 - nbytes);
	} else if (src != dst)
		*dst = *src;

	return dst;
}


int
nm_spawn_process (const char *args)
{
	gint num_args;
	char **argv = NULL;
	int status = -1;
	GError *error = NULL;

	g_return_val_if_fail (args != NULL, -1);

	if (!g_shell_parse_argv (args, &num_args, &argv, &error)) {
		nm_log_warn (LOGD_CORE, "could not parse arguments for '%s': %s", args, error->message);
		g_error_free (error);
		return -1;
	}

	if (!g_spawn_sync ("/", argv, NULL, 0, nm_unblock_posix_signals, NULL, NULL, NULL, &status, &error)) {
		nm_log_warn (LOGD_CORE, "could not spawn process '%s': %s", args, error->message);
		g_error_free (error);
	}

	g_strfreev (argv);
	return status;
}

/**
 * nm_utils_get_start_time_for_pid:
 * @pid: the process identifier
 *
 * Originally copied from polkit source (src/polkit/polkitunixprocess.c)
 * and adjusted.
 *
 * Returns: the timestamp when the process started (by parsing /proc/$PID/stat).
 * If an error occurs (e.g. the process does not exist), 0 is returned.
 *
 * The returned start time counts since boot, in the unit HZ (with HZ usually being (1/100) seconds)
 **/
guint64
nm_utils_get_start_time_for_pid (pid_t pid)
{
	guint64 start_time;
	gchar *filename;
	gchar *contents;
	size_t length;
	gchar **tokens;
	guint num_tokens;
	gchar *p;
	gchar *endp;

	start_time = 0;
	contents = NULL;

	g_return_val_if_fail (pid > 0, 0);

	filename = g_strdup_printf ("/proc/%"G_GUINT64_FORMAT"/stat", (guint64) pid);

	if (!g_file_get_contents (filename, &contents, &length, NULL))
		goto out;

	/* start time is the token at index 19 after the '(process name)' entry - since only this
	 * field can contain the ')' character, search backwards for this to avoid malicious
	 * processes trying to fool us
	 */
	p = strrchr (contents, ')');
	if (p == NULL)
		goto out;
	p += 2; /* skip ') ' */
	if (p - contents >= (int) length)
		goto out;

	tokens = g_strsplit (p, " ", 0);

	num_tokens = g_strv_length (tokens);

	if (num_tokens < 20)
		goto out;

	start_time = strtoull (tokens[19], &endp, 10);
	if (endp == tokens[19])
		goto out;

	g_strfreev (tokens);

 out:
	g_free (filename);
	g_free (contents);

	return start_time;
}

/******************************************************************************************/

typedef struct {
	pid_t pid;
	guint64 log_domain;
	union {
		struct {
			gint64 wait_start_us;
			guint source_timeout_kill_id;
		} async;
		struct {
			gboolean success;
			int child_status;
		} sync;
	};
	NMUtilsKillChildAsyncCb callback;
	void *user_data;

	char log_name[1]; /* variable-length object, must be last element!! */
} KillChildAsyncData;

#define LOG_NAME_FMT "kill child process '%s' (%ld)"
#define LOG_NAME_PROCESS_FMT "kill process '%s' (%ld)"
#define LOG_NAME_ARGS log_name,(long)pid

static KillChildAsyncData *
_kc_async_data_alloc (pid_t pid, guint64 log_domain, const char *log_name, NMUtilsKillChildAsyncCb callback, void *user_data)
{
	KillChildAsyncData *data;
	size_t log_name_len;

	/* append the name at the end of our KillChildAsyncData. */
	log_name_len = strlen (LOG_NAME_FMT) + 20 + strlen (log_name);
	data = g_malloc (sizeof (KillChildAsyncData) - 1 + log_name_len);
	g_snprintf (data->log_name, log_name_len, LOG_NAME_FMT, LOG_NAME_ARGS);

	data->pid = pid;
	data->user_data = user_data;
	data->callback = callback;
	data->log_domain = log_domain;

	return data;
}

#define KC_EXIT_TO_STRING_BUF_SIZE 128
static const char *
_kc_exit_to_string (char *buf, int exit)
#define _kc_exit_to_string(buf, exit) ( G_STATIC_ASSERT_EXPR(sizeof (buf) == KC_EXIT_TO_STRING_BUF_SIZE && sizeof ((buf)[0]) == 1), _kc_exit_to_string (buf, exit) )
{
	if (WIFEXITED (exit))
		g_snprintf (buf, KC_EXIT_TO_STRING_BUF_SIZE, "normally with status %d", WEXITSTATUS (exit));
	else if (WIFSIGNALED (exit))
		g_snprintf (buf, KC_EXIT_TO_STRING_BUF_SIZE, "by signal %d", WTERMSIG (exit));
	else
		g_snprintf (buf, KC_EXIT_TO_STRING_BUF_SIZE, "with unexpected status %d", exit);
	return buf;
}

static const char *
_kc_signal_to_string (int sig)
{
	switch (sig) {
	case 0:  return "no signal (0)";
	case SIGKILL:  return "SIGKILL (" G_STRINGIFY (SIGKILL) ")";
	case SIGTERM:  return "SIGTERM (" G_STRINGIFY (SIGTERM) ")";
	default:
		return "Unexpected signal";
	}
}

#define KC_WAITED_TO_STRING 100
static const char *
_kc_waited_to_string (char *buf, gint64 wait_start_us)
#define _kc_waited_to_string(buf, wait_start_us) ( G_STATIC_ASSERT_EXPR(sizeof (buf) == KC_WAITED_TO_STRING && sizeof ((buf)[0]) == 1), _kc_waited_to_string (buf, wait_start_us) )
{
	g_snprintf (buf, KC_WAITED_TO_STRING, " (%ld usec elapsed)", (long) (nm_utils_get_monotonic_timestamp_us () - wait_start_us));
	return buf;
}

static void
_kc_cb_watch_child (GPid pid, gint status, gpointer user_data)
{
	KillChildAsyncData *data = user_data;
	char buf_exit[KC_EXIT_TO_STRING_BUF_SIZE], buf_wait[KC_WAITED_TO_STRING];

	if (data->async.source_timeout_kill_id)
		g_source_remove (data->async.source_timeout_kill_id);

	nm_log_dbg (data->log_domain, "%s: terminated %s%s",
	            data->log_name, _kc_exit_to_string (buf_exit, status),
	            _kc_waited_to_string (buf_wait, data->async.wait_start_us));

	if (data->callback)
		data->callback (pid, TRUE, status, data->user_data);

	g_free (data);
}

static gboolean
_kc_cb_timeout_grace_period (void *user_data)
{
	KillChildAsyncData *data = user_data;
	int ret, errsv;

	data->async.source_timeout_kill_id = 0;

	if ((ret = kill (data->pid, SIGKILL)) != 0) {
		errsv = errno;
		/* ESRCH means, process does not exist or is already a zombie. */
		if (errsv != ESRCH) {
			nm_log_err (LOGD_CORE | data->log_domain, "%s: kill(SIGKILL) returned unexpected return value %d: (%s, %d)",
			            data->log_name, ret, strerror (errsv), errsv);
		}
	} else {
		nm_log_dbg (data->log_domain, "%s: process not terminated after %ld usec. Sending SIGKILL signal",
		            data->log_name, (long) (nm_utils_get_monotonic_timestamp_us () - data->async.wait_start_us));
	}

	return G_SOURCE_REMOVE;
}

static gboolean
_kc_invoke_callback_idle (gpointer user_data)
{
	KillChildAsyncData *data = user_data;

	if (data->sync.success) {
		char buf_exit[KC_EXIT_TO_STRING_BUF_SIZE];

		nm_log_dbg (data->log_domain, "%s: invoke callback: terminated %s",
		            data->log_name, _kc_exit_to_string (buf_exit, data->sync.child_status));
	} else
		nm_log_dbg (data->log_domain, "%s: invoke callback: killing child failed", data->log_name);

	data->callback (data->pid, data->sync.success, data->sync.child_status, data->user_data);
	g_free (data);

	return G_SOURCE_REMOVE;
}

static void
_kc_invoke_callback (pid_t pid, guint64 log_domain, const char *log_name, NMUtilsKillChildAsyncCb callback, void *user_data, gboolean success, int child_status)
{
	KillChildAsyncData *data;

	if (!callback)
		return;

	data = _kc_async_data_alloc (pid, log_domain, log_name, callback, user_data);
	data->sync.success = success;
	data->sync.child_status = child_status;

	g_idle_add (_kc_invoke_callback_idle, data);
}

/* nm_utils_kill_child_async:
 * @pid: the process id of the process to kill
 * @sig: signal to send initially. Set to 0 to send not signal.
 * @log_domain: the logging domain used for logging (LOGD_NONE to suppress logging)
 * @log_name: for logging, the name of the processes to kill
 * @wait_before_kill_msec: Waittime in milliseconds before sending %SIGKILL signal. Set this value
 * to zero, not to send %SIGKILL. If @sig is already %SIGKILL, this parameter is ignored.
 * @callback: (allow-none): callback after the child terminated. This function will always
 *   be invoked asynchronously.
 * @user_data: passed on to callback
 *
 * Uses g_child_watch_add(), so note the glib comment: if you obtain pid from g_spawn_async() or
 * g_spawn_async_with_pipes() you will need to pass %G_SPAWN_DO_NOT_REAP_CHILD as flag to the spawn
 * function for the child watching to work.
 * Also note, that you must g_source_remove() any other child watchers for @pid because glib
 * supports only one watcher per child.
 **/
void
nm_utils_kill_child_async (pid_t pid, int sig, guint64 log_domain,
                           const char *log_name, guint32 wait_before_kill_msec,
                           NMUtilsKillChildAsyncCb callback, void *user_data)
{
	int status = 0, errsv;
	pid_t ret;
	KillChildAsyncData *data;
	char buf_exit[KC_EXIT_TO_STRING_BUF_SIZE];

	g_return_if_fail (pid > 0);
	g_return_if_fail (log_name != NULL);

	/* let's see if the child already terminated... */
	ret = waitpid (pid, &status, WNOHANG);
	if (ret > 0) {
		nm_log_dbg (log_domain, LOG_NAME_FMT ": process %ld already terminated %s",
		            LOG_NAME_ARGS, (long) ret, _kc_exit_to_string (buf_exit, status));
		_kc_invoke_callback (pid, log_domain, log_name, callback, user_data, TRUE, status);
		return;
	} else if (ret != 0) {
		errsv = errno;
		/* ECHILD means, the process is not a child/does not exist or it has SIGCHILD blocked. */
		if (errsv != ECHILD) {
			nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": unexpected error while waitpid: %s (%d)",
			            LOG_NAME_ARGS, strerror (errsv), errsv);
			_kc_invoke_callback (pid, log_domain, log_name, callback, user_data, FALSE, -1);
			return;
		}
	}

	/* send the first signal. */
	if (kill (pid, sig) != 0) {
		errsv = errno;
		/* ESRCH means, process does not exist or is already a zombie. */
		if (errsv != ESRCH) {
			nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": unexpected error sending %s: %s (%d)",
			            LOG_NAME_ARGS, _kc_signal_to_string (sig), strerror (errsv), errsv);
			_kc_invoke_callback (pid, log_domain, log_name, callback, user_data, FALSE, -1);
			return;
		}

		/* let's try again with waitpid, probably there was a race... */
		ret = waitpid (pid, &status, 0);
		if (ret > 0) {
			nm_log_dbg (log_domain, LOG_NAME_FMT ": process %ld already terminated %s",
			            LOG_NAME_ARGS, (long) ret, _kc_exit_to_string (buf_exit, status));
			_kc_invoke_callback (pid, log_domain, log_name, callback, user_data, TRUE, status);
		} else {
			errsv = errno;
			nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": failed due to unexpected return value %ld by waitpid (%s, %d) after sending %s",
			            LOG_NAME_ARGS, (long) ret, strerror (errsv), errsv, _kc_signal_to_string (sig));
			_kc_invoke_callback (pid, log_domain, log_name, callback, user_data, FALSE, -1);
		}
		return;
	}

	data = _kc_async_data_alloc (pid, log_domain, log_name, callback, user_data);
	data->async.wait_start_us = nm_utils_get_monotonic_timestamp_us ();

	if (sig != SIGKILL && wait_before_kill_msec > 0) {
		data->async.source_timeout_kill_id = g_timeout_add (wait_before_kill_msec, _kc_cb_timeout_grace_period, data);
		nm_log_dbg (log_domain, "%s: wait for process to terminate after sending %s (send SIGKILL in %ld milliseconds)...",
		            data->log_name,  _kc_signal_to_string (sig), (long) wait_before_kill_msec);
	} else {
		data->async.source_timeout_kill_id = 0;
		nm_log_dbg (log_domain, "%s: wait for process to terminate after sending %s...",
		            data->log_name, _kc_signal_to_string (sig));
	}

	g_child_watch_add (pid, _kc_cb_watch_child, data);
}

static inline gulong
_sleep_duration_convert_ms_to_us (guint32 sleep_duration_msec)
{
	if (sleep_duration_msec > 0) {
		guint64 x = (gint64) sleep_duration_msec * (guint64) 1000L;

		return x < G_MAXULONG ? (gulong) x : G_MAXULONG;
	}
	return G_USEC_PER_SEC / 20;
}

/* nm_utils_kill_child_sync:
 * @pid: process id to kill
 * @sig: signal to sent initially. If 0, no signal is sent. If %SIGKILL, the
 * second %SIGKILL signal is not sent after @wait_before_kill_msec milliseconds.
 * @log_domain: log debug information for this domain. Errors and warnings are logged both
 * as %LOGD_CORE and @log_domain.
 * @log_name: name of the process to kill for logging.
 * @child_status: (out) (allow-none): return the exit status of the child, if no error occured.
 * @wait_before_kill_msec: Waittime in milliseconds before sending %SIGKILL signal. Set this value
 * to zero, not to send %SIGKILL. If @sig is already %SIGKILL, this parameter has not effect.
 * @sleep_duration_msec: the synchronous function sleeps repeatedly waiting for the child to terminate.
 * Set to zero, to use the default (meaning 20 wakeups per seconds).
 *
 * Kill a child process synchronously and wait. The function first checks if the child already terminated
 * and if it did, return the exit status. Otherwise send one @sig signal. @sig  will always be
 * sent unless the child already exited. If the child does not exit within @wait_before_kill_msec milliseconds,
 * the function will send %SIGKILL and waits for the child indefinitly. If @wait_before_kill_msec is zero, no
 * %SIGKILL signal will be sent.
 **/
gboolean
nm_utils_kill_child_sync (pid_t pid, int sig, guint64 log_domain, const char *log_name,
                          int *child_status, guint32 wait_before_kill_msec,
                          guint32 sleep_duration_msec)
{
	int status = 0, errsv;
	pid_t ret;
	gboolean success = FALSE;
	gboolean was_waiting = FALSE, send_kill = FALSE;
	char buf_exit[KC_EXIT_TO_STRING_BUF_SIZE];
	char buf_wait[KC_WAITED_TO_STRING];
	gint64 wait_start_us;

	g_return_val_if_fail (pid > 0, FALSE);
	g_return_val_if_fail (log_name != NULL, FALSE);

	/* check if the child process already terminated... */
	ret = waitpid (pid, &status, WNOHANG);
	if (ret > 0) {
		nm_log_dbg (log_domain, LOG_NAME_FMT ": process %ld already terminated %s",
		            LOG_NAME_ARGS, (long) ret, _kc_exit_to_string (buf_exit, status));
		success = TRUE;
		goto out;
	} else if (ret != 0) {
		errsv = errno;
		/* ECHILD means, the process is not a child/does not exist or it has SIGCHILD blocked. */
		if (errsv != ECHILD) {
			nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": unexpected error while waitpid: %s (%d)",
			            LOG_NAME_ARGS, strerror (errsv), errsv);
			goto out;
		}
	}

	/* send first signal @sig */
	if (kill (pid, sig) != 0) {
		errsv = errno;
		/* ESRCH means, process does not exist or is already a zombie. */
		if (errsv != ESRCH) {
			nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": failed to send %s: %s (%d)",
			            LOG_NAME_ARGS, _kc_signal_to_string (sig), strerror (errsv), errsv);
		} else {
			/* let's try again with waitpid, probably there was a race... */
			ret = waitpid (pid, &status, 0);
			if (ret > 0) {
				nm_log_dbg (log_domain, LOG_NAME_FMT ": process %ld already terminated %s",
				            LOG_NAME_ARGS, (long) ret, _kc_exit_to_string (buf_exit, status));
				success = TRUE;
			} else {
				errsv = errno;
				nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": failed due to unexpected return value %ld by waitpid (%s, %d) after sending %s",
				            LOG_NAME_ARGS, (long) ret, strerror (errsv), errsv, _kc_signal_to_string (sig));
			}
		}
		goto out;
	}

	wait_start_us = nm_utils_get_monotonic_timestamp_us ();

	/* wait for the process to terminated... */
	if (sig != SIGKILL) {
		gint64 wait_until, now;
		gulong sleep_time, sleep_duration_usec;
		int loop_count = 0;

		sleep_duration_usec = _sleep_duration_convert_ms_to_us (sleep_duration_msec);
		wait_until = wait_before_kill_msec <= 0 ? 0 : wait_start_us + (((gint64) wait_before_kill_msec) * 1000L);

		while (TRUE) {
			ret = waitpid (pid, &status, WNOHANG);
			if (ret > 0) {
				nm_log_dbg (log_domain, LOG_NAME_FMT ": after sending %s, process %ld exited %s%s",
				            LOG_NAME_ARGS, _kc_signal_to_string (sig), (long) ret, _kc_exit_to_string (buf_exit, status),
				            was_waiting ? _kc_waited_to_string (buf_wait, wait_start_us) : "");
				success = TRUE;
				goto out;
			}
			if (ret == -1) {
				errsv = errno;
				/* ECHILD means, the process is not a child/does not exist or it has SIGCHILD blocked. */
				if (errsv != ECHILD) {
					nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": after sending %s, waitpid failed with %s (%d)%s",
					            LOG_NAME_ARGS, _kc_signal_to_string (sig), strerror (errsv), errsv,
					           was_waiting ? _kc_waited_to_string (buf_wait, wait_start_us) : "");
					goto out;
				}
			}

			if (!wait_until)
				break;

			now = nm_utils_get_monotonic_timestamp_us ();
			if (now >= wait_until)
				break;

			if (!was_waiting) {
				nm_log_dbg (log_domain, LOG_NAME_FMT ": waiting up to %ld milliseconds for process to terminate normally after sending %s...",
				            LOG_NAME_ARGS, (long) MAX (wait_before_kill_msec, 0), _kc_signal_to_string (sig));
				was_waiting = TRUE;
			}

			sleep_time = MIN (wait_until - now, sleep_duration_usec);
			if (loop_count < 20) {
				/* At the beginning we expect the process to die fast.
				 * Limit the sleep time, the limit doubles with every iteration. */
				sleep_time = MIN (sleep_time, (((guint64) 1) << loop_count) * G_USEC_PER_SEC / 2000);
				loop_count++;
			}
			g_usleep (sleep_time);
		}

		/* send SIGKILL, if called with @wait_before_kill_msec > 0 */
		if (wait_until) {
			nm_log_dbg (log_domain, LOG_NAME_FMT ": sending SIGKILL...", LOG_NAME_ARGS);

			send_kill = TRUE;
			if (kill (pid, SIGKILL) != 0) {
				errsv = errno;
				/* ESRCH means, process does not exist or is already a zombie. */
				if (errsv != ESRCH) {
					nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": failed to send SIGKILL (after sending %s), %s (%d)",
								LOG_NAME_ARGS, _kc_signal_to_string (sig), strerror (errsv), errsv);
					goto out;
				}
			}
		}
	}

	if (!was_waiting) {
		nm_log_dbg (log_domain, LOG_NAME_FMT ": waiting for process to terminate after sending %s%s...",
		            LOG_NAME_ARGS, _kc_signal_to_string (sig), send_kill ? " and SIGKILL" : "");
	}

	/* block until the child terminates. */
	while ((ret = waitpid (pid, &status, 0)) <= 0) {
		errsv = errno;

		if (errsv != EINTR) {
			nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": after sending %s%s, waitpid failed with %s (%d)%s",
			            LOG_NAME_ARGS, _kc_signal_to_string (sig), send_kill ? " and SIGKILL" : "", strerror (errsv), errsv,
			            _kc_waited_to_string (buf_wait, wait_start_us));
			goto out;
		}
	}

	nm_log_dbg (log_domain, LOG_NAME_FMT ": after sending %s%s, process %ld exited %s%s",
	            LOG_NAME_ARGS, _kc_signal_to_string (sig), send_kill ? " and SIGKILL" : "", (long) ret,
	            _kc_exit_to_string (buf_exit, status), _kc_waited_to_string (buf_wait, wait_start_us));
	success = TRUE;
out:
	if (child_status)
		*child_status = success ? status : -1;
	return success;
}

/* nm_utils_kill_process_sync:
 * @pid: process id to kill
 * @start_time: the start time of the process to kill (as obtained by nm_utils_get_start_time_for_pid()).
 *   This is an optional argument, to avoid (somewhat) killing the wrong process as @pid
 *   might get recycled. You can pass 0, to not provide this parameter.
 * @sig: signal to sent initially. If 0, no signal is sent. If %SIGKILL, the
 *   second %SIGKILL signal is not sent after @wait_before_kill_msec milliseconds.
 * @log_domain: log debug information for this domain. Errors and warnings are logged both
 *   as %LOGD_CORE and @log_domain.
 * @log_name: name of the process to kill for logging.
 * @wait_before_kill_msec: Waittime in milliseconds before sending %SIGKILL signal. Set this value
 *   to zero, not to send %SIGKILL. If @sig is already %SIGKILL, this parameter has no effect.
 * @sleep_duration_msec: the synchronous function sleeps repeatedly waiting for the child to terminate.
 *   Set to zero, to use the default (meaning 20 wakeups per seconds).
 *
 * Kill a non-child process synchronously and wait. This function will not return before the
 * process with PID @pid is gone.
 **/
void
nm_utils_kill_process_sync (pid_t pid, guint64 start_time, int sig, guint64 log_domain,
                            const char *log_name, guint32 wait_before_kill_msec,
                            guint32 sleep_duration_msec)
{
	int errsv;
	guint64 start_time0;
	gint64 wait_until, now, wait_start_us;
	gulong sleep_time, sleep_duration_usec;
	int loop_count = 0;
	gboolean was_waiting = FALSE;
	char buf_wait[KC_WAITED_TO_STRING];

	g_return_if_fail (pid > 0);
	g_return_if_fail (log_name != NULL);
	g_return_if_fail (wait_before_kill_msec > 0);

	start_time0 = nm_utils_get_start_time_for_pid (pid);
	if (start_time0 == 0) {
		nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": cannot kill process %ld because it seems already gone",
		            LOG_NAME_ARGS, (long int) pid);
		return;
	}
	if (start_time != 0 && start_time != start_time0) {
		nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": don't kill process %ld because the start_time is unexpectedly %lu instead of %ld",
		            LOG_NAME_ARGS, (long int) pid, (long unsigned) start_time0, (long unsigned) start_time);
		return;
	}

	if (kill (pid, sig) != 0) {
		errsv = errno;
		/* ESRCH means, process does not exist or is already a zombie. */
		if (errsv == ESRCH) {
			nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": failed to send %s because process seems gone",
			            LOG_NAME_ARGS, _kc_signal_to_string (sig));
		} else {
			nm_log_warn (LOGD_CORE | log_domain, LOG_NAME_PROCESS_FMT ": failed to send %s: %s (%d)",
			             LOG_NAME_ARGS, _kc_signal_to_string (sig), strerror (errsv), errsv);
		}
		return;
	}

	/* wait for the process to terminated... */

	wait_start_us = nm_utils_get_monotonic_timestamp_us ();

	sleep_duration_usec = _sleep_duration_convert_ms_to_us (sleep_duration_msec);
	wait_until = wait_start_us + (((gint64) wait_before_kill_msec) * 1000L);

	while (TRUE) {
		start_time = nm_utils_get_start_time_for_pid (pid);

		if (start_time != start_time0) {
			nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": process is gone after sending signal %s%s",
			            LOG_NAME_ARGS, _kc_signal_to_string (sig),
			            was_waiting ? _kc_waited_to_string (buf_wait, wait_start_us) : "");
			return;
		}

		if (kill (pid, 0) != 0) {
			errsv = errno;
			/* ESRCH means, process does not exist or is already a zombie. */
			if (errsv == ESRCH) {
				nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": process is gone or a zombie after sending signal %s%s",
				            LOG_NAME_ARGS, _kc_signal_to_string (sig),
				            was_waiting ? _kc_waited_to_string (buf_wait, wait_start_us) : "");
			} else {
				nm_log_warn (LOGD_CORE | log_domain, LOG_NAME_PROCESS_FMT ": failed to kill(%ld, 0): %s (%d)%s",
				             LOG_NAME_ARGS, (long int) pid, strerror (errsv), errsv,
				             was_waiting ? _kc_waited_to_string (buf_wait, wait_start_us) : "");
			}
			return;
		}

		sleep_time = sleep_duration_usec;
		if (wait_until != 0) {
			now = nm_utils_get_monotonic_timestamp_us ();
			if (sig != SIGKILL && now >= wait_until) {
				/* Still not dead. SIGKILL now... */
				nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": sending SIGKILL", LOG_NAME_ARGS);
				if (kill (pid, SIGKILL) != 0) {
					errsv = errno;
					/* ESRCH means, process does not exist or is already a zombie. */
					if (errsv != ESRCH) {
						nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": process is gone or a zombie%s",
						            LOG_NAME_ARGS, _kc_waited_to_string (buf_wait, wait_start_us));
					} else {
						nm_log_warn (LOGD_CORE | log_domain, LOG_NAME_PROCESS_FMT ": failed to send SIGKILL (after sending %s), %s (%d)%s",
						             LOG_NAME_ARGS, _kc_signal_to_string (sig), strerror (errsv), errsv,
						             _kc_waited_to_string (buf_wait, wait_start_us));
					}
					return;
				}
				sig = SIGKILL;
				was_waiting = TRUE;
				wait_until = 0;
				loop_count = 0; /* reset the loop_count. Now we really expect the process to die quickly. */
			} else {
				if (!was_waiting) {
					nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": waiting up to %ld milliseconds for process to disappear after sending %s...",
					            LOG_NAME_ARGS, (long) wait_before_kill_msec, _kc_signal_to_string (sig));
					was_waiting = TRUE;
				}
				sleep_time = MIN (wait_until - now, sleep_duration_usec);
			}
		}

		if (loop_count < 20) {
			/* At the beginning we expect the process to die fast.
			 * Limit the sleep time, the limit doubles with every iteration. */
			sleep_time = MIN (sleep_time, (((guint64) 1) << loop_count) * G_USEC_PER_SEC / 2000);
			loop_count++;
		}
		g_usleep (sleep_time);
	}
}
#undef LOG_NAME_FMT
#undef LOG_NAME_PROCESS_FMT
#undef LOG_NAME_ARGS

const char *const NM_PATHS_DEFAULT[] = {
	PREFIX "/sbin/",
	PREFIX "/bin/",
	"/sbin/",
	"/usr/sbin/",
	"/usr/local/sbin/",
	"/bin/",
	"/usr/bin/",
	"/usr/local/bin/",
	NULL,
};

const char *
nm_utils_find_helper(const char *progname, const char *try_first, GError **error)
{
	return nm_utils_file_search_in_paths (progname, try_first, NM_PATHS_DEFAULT, G_FILE_TEST_IS_EXECUTABLE, NULL, NULL, error);
}

/******************************************************************************************/

gboolean
nm_match_spec_string (const GSList *specs, const char *match)
{
	const GSList *iter;

	for (iter = specs; iter; iter = g_slist_next (iter)) {
		if (!g_ascii_strcasecmp ((const char *) iter->data, match))
			return TRUE;
	}

	return FALSE;
}

gboolean
nm_match_spec_hwaddr (const GSList *specs, const char *hwaddr)
{
	const GSList *iter;

	g_return_val_if_fail (hwaddr != NULL, FALSE);

	for (iter = specs; iter; iter = g_slist_next (iter)) {
		const char *spec_str = iter->data;

		if (   !g_ascii_strncasecmp (spec_str, "mac:", 4)
		    && nm_utils_hwaddr_matches (spec_str + 4, -1, hwaddr, -1))
			return TRUE;

		if (nm_utils_hwaddr_matches (spec_str, -1, hwaddr, -1))
			return TRUE;
	}

	return FALSE;
}

gboolean
nm_match_spec_interface_name (const GSList *specs, const char *interface_name)
{
	char *iface_match;
	gboolean matched;

	g_return_val_if_fail (interface_name != NULL, FALSE);

	if (nm_match_spec_string (specs, interface_name))
		return TRUE;

	iface_match = g_strdup_printf ("interface-name:%s", interface_name);
	matched = nm_match_spec_string (specs, iface_match);
	g_free (iface_match);
	return matched;
}

#define BUFSIZE 10

static gboolean
parse_subchannels (const char *subchannels, guint32 *a, guint32 *b, guint32 *c)
{
	long unsigned int tmp;
	char buf[BUFSIZE + 1];
	const char *p = subchannels;
	int i = 0;
	char *pa = NULL, *pb = NULL, *pc = NULL;

	g_return_val_if_fail (subchannels != NULL, FALSE);
	g_return_val_if_fail (a != NULL, FALSE);
	g_return_val_if_fail (*a == 0, FALSE);
	g_return_val_if_fail (b != NULL, FALSE);
	g_return_val_if_fail (*b == 0, FALSE);
	g_return_val_if_fail (c != NULL, FALSE);
	g_return_val_if_fail (*c == 0, FALSE);

	/* sanity check */
	if (!g_ascii_isxdigit (subchannels[0]))
		return FALSE;

	/* Get the first channel */
	while (*p && (*p != ',')) {
		if (!g_ascii_isxdigit (*p) && (*p != '.'))
			return FALSE;  /* Invalid chars */
		if (i >= BUFSIZE)
			return FALSE;  /* Too long to be a subchannel */
		buf[i++] = *p++;
	}
	buf[i] = '\0';

	/* and grab each of its elements, there should be 3 */
	pa = &buf[0];
	pb = strchr (buf, '.');
	if (pb)
		pc = strchr (pb + 1, '.');
	if (!pa || !pb || !pc)
		return FALSE;

	/* Split the string */
	*pb++ = '\0';
	*pc++ = '\0';

	errno = 0;
	tmp = strtoul (pa, NULL, 16);
	if (errno)
		return FALSE;
	*a = (guint32) tmp;

	errno = 0;
	tmp = strtoul (pb, NULL, 16);
	if (errno)
		return FALSE;
	*b = (guint32) tmp;

	errno = 0;
	tmp = strtoul (pc, NULL, 16);
	if (errno)
		return FALSE;
	*c = (guint32) tmp;

	return TRUE;
}

#define SUBCHAN_TAG "s390-subchannels:"

gboolean
nm_match_spec_s390_subchannels (const GSList *specs, const char *subchannels)
{
	const GSList *iter;
	guint32 a = 0, b = 0, c = 0;
	guint32 spec_a = 0, spec_b = 0, spec_c = 0;

	g_return_val_if_fail (subchannels != NULL, FALSE);

	if (!parse_subchannels (subchannels, &a, &b, &c))
		return FALSE;

	for (iter = specs; iter; iter = g_slist_next (iter)) {
		const char *spec = iter->data;

		if (!strncmp (spec, SUBCHAN_TAG, strlen (SUBCHAN_TAG))) {
			spec += strlen (SUBCHAN_TAG);
			if (parse_subchannels (spec, &spec_a, &spec_b, &spec_c)) {
				if (a == spec_a && b == spec_b && c == spec_c)
					return TRUE;
			}
		}
	}

	return FALSE;
}

const char *
nm_utils_get_shared_wifi_permission (NMConnection *connection)
{
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	const char *method = NULL;

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED) != 0)
		return NULL;  /* Not shared */

	s_wifi = nm_connection_get_setting_wireless (connection);
	if (s_wifi) {
		s_wsec = nm_connection_get_setting_wireless_security (connection);
		if (s_wsec)
			return NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED;
		else
			return NM_AUTH_PERMISSION_WIFI_SHARE_OPEN;
	}

	return NULL;
}

/*********************************/

static void
nm_gvalue_destroy (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

GHashTable *
value_hash_create (void)
{
	return g_hash_table_new_full (g_str_hash, g_str_equal, g_free, nm_gvalue_destroy);
}

void
value_hash_add (GHashTable *hash,
				const char *key,
				GValue *value)
{
	g_hash_table_insert (hash, g_strdup (key), value);
}

void
value_hash_add_str (GHashTable *hash,
					const char *key,
					const char *str)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_STRING);
	g_value_set_string (value, str);

	value_hash_add (hash, key, value);
}

void
value_hash_add_object_path (GHashTable *hash,
							const char *key,
							const char *op)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, DBUS_TYPE_G_OBJECT_PATH);
	g_value_set_boxed (value, op);

	value_hash_add (hash, key, value);
}

void
value_hash_add_uint (GHashTable *hash,
					 const char *key,
					 guint32 val)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_UINT);
	g_value_set_uint (value, val);

	value_hash_add (hash, key, value);
}

void
value_hash_add_bool (GHashTable *hash,
					 const char *key,
					 gboolean val)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_BOOLEAN);
	g_value_set_boolean (value, val);

	value_hash_add (hash, key, value);
}

void
value_hash_add_object_property (GHashTable *hash,
                                const char *key,
                                GObject *object,
                                const char *prop,
                                GType val_type)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, val_type);
	g_object_get_property (object, prop, value);
	value_hash_add (hash, key, value);
}


static char *
get_new_connection_name (const GSList *existing,
                         const char *preferred,
                         const char *fallback_prefix)
{
	GSList *names = NULL;
	const GSList *iter;
	char *cname = NULL;
	int i = 0;
	gboolean preferred_found = FALSE;

	g_assert (fallback_prefix);

	for (iter = existing; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = NM_CONNECTION (iter->data);
		const char *id;

		id = nm_connection_get_id (candidate);
		g_assert (id);
		names = g_slist_append (names, (gpointer) id);

		if (preferred && !preferred_found && (strcmp (preferred, id) == 0))
			preferred_found = TRUE;
	}

	/* Return the preferred name if it was unique */
	if (preferred && !preferred_found) {
		g_slist_free (names);
		return g_strdup (preferred);
	}

	/* Otherwise find the next available unique connection name using the given
	 * connection name template.
	 */
	while (!cname && (i++ < 10000)) {
		char *temp;
		gboolean found = FALSE;

		/* Translators: the first %s is a prefix for the connection id, such
		 * as "Wired Connection" or "VPN Connection". The %d is a number
		 * that is combined with the first argument to create a unique
		 * connection id. */
		temp = g_strdup_printf (C_("connection id fallback", "%s %d"),
		                        fallback_prefix, i);
		for (iter = names; iter; iter = g_slist_next (iter)) {
			if (!strcmp (iter->data, temp)) {
				found = TRUE;
				break;
			}
		}
		if (!found)
			cname = temp;
		else
			g_free (temp);
	}

	g_slist_free (names);
	return cname;
}

static char *
get_new_connection_ifname (const GSList *existing,
                           const char *prefix)
{
	int i;
	char *name;
	const GSList *iter;
	gboolean found;

	for (i = 0; i < 500; i++) {
		name = g_strdup_printf ("%s%d", prefix, i);

		if (nm_platform_link_exists (name))
			goto next;

		for (iter = existing, found = FALSE; iter; iter = g_slist_next (iter)) {
			NMConnection *candidate = iter->data;

			if (g_strcmp0 (nm_connection_get_interface_name (candidate), name) == 0) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			return name;

	next:
		g_free (name);
	}

	return NULL;
}

const char *
nm_utils_get_ip_config_method (NMConnection *connection,
                               GType         ip_setting_type)
{
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4, *s_ip6;
	const char *method;

	s_con = nm_connection_get_setting_connection (connection);

	if (ip_setting_type == NM_TYPE_SETTING_IP4_CONFIG) {
		g_return_val_if_fail (s_con != NULL, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

		if (nm_setting_connection_get_master (s_con))
			return NM_SETTING_IP4_CONFIG_METHOD_DISABLED;
		else {
			s_ip4 = nm_connection_get_setting_ip4_config (connection);
			g_return_val_if_fail (s_ip4 != NULL, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
			method = nm_setting_ip_config_get_method (s_ip4);
			g_return_val_if_fail (method != NULL, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

			return method;
		}

	} else if (ip_setting_type == NM_TYPE_SETTING_IP6_CONFIG) {
		g_return_val_if_fail (s_con != NULL, NM_SETTING_IP6_CONFIG_METHOD_AUTO);

		if (nm_setting_connection_get_master (s_con))
			return NM_SETTING_IP6_CONFIG_METHOD_IGNORE;
		else {
			s_ip6 = nm_connection_get_setting_ip6_config (connection);
			g_return_val_if_fail (s_ip6 != NULL, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
			method = nm_setting_ip_config_get_method (s_ip6);
			g_return_val_if_fail (method != NULL, NM_SETTING_IP6_CONFIG_METHOD_AUTO);

			return method;
		}

	} else
		g_assert_not_reached ();
}

void
nm_utils_complete_generic (NMConnection *connection,
                           const char *ctype,
                           const GSList *existing,
                           const char *preferred_id,
                           const char *fallback_id_prefix,
                           const char *ifname_prefix,
                           gboolean default_enable_ipv6)
{
	NMSettingConnection *s_con;
	char *id, *uuid, *ifname;
	GHashTable *parameters;

	g_assert (fallback_id_prefix);

	s_con = nm_connection_get_setting_connection (connection);
	if (!s_con) {
		s_con = (NMSettingConnection *) nm_setting_connection_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_con));
	}
	g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_TYPE, ctype, NULL);

	if (!nm_setting_connection_get_uuid (s_con)) {
		uuid = nm_utils_uuid_generate ();
		g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_UUID, uuid, NULL);
		g_free (uuid);
	}

	/* Add a connection ID if absent */
	if (!nm_setting_connection_get_id (s_con)) {
		id = get_new_connection_name (existing, preferred_id, fallback_id_prefix);
		g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_ID, id, NULL);
		g_free (id);
	}

	/* Add an interface name, if requested */
	if (ifname_prefix && !nm_setting_connection_get_interface_name (s_con)) {
		ifname = get_new_connection_ifname (existing, ifname_prefix);
		g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_INTERFACE_NAME, ifname, NULL);
		g_free (ifname);
	}

	/* Normalize */
	parameters = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (parameters, NM_CONNECTION_NORMALIZE_PARAM_IP6_CONFIG_METHOD,
	                     default_enable_ipv6 ? NM_SETTING_IP6_CONFIG_METHOD_AUTO : NM_SETTING_IP6_CONFIG_METHOD_IGNORE);
	nm_connection_normalize (connection, parameters, NULL, NULL);
	g_hash_table_destroy (parameters);
}

char *
nm_utils_new_vlan_name (const char *parent_iface, guint32 vlan_id)
{
	/* Basically VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD */
	return g_strdup_printf ("%s.%d", parent_iface, vlan_id);
}

/**
 * nm_utils_read_resolv_conf_nameservers():
 * @rc_contents: contents of a resolv.conf; or %NULL to read /etc/resolv.conf
 *
 * Reads all nameservers out of @rc_contents or /etc/resolv.conf and returns
 * them.
 *
 * Returns: a #GPtrArray of 'char *' elements of each nameserver line from
 * @contents or resolv.conf
 */
GPtrArray *
nm_utils_read_resolv_conf_nameservers (const char *rc_contents)
{
	GPtrArray *nameservers = NULL;
	char *contents = NULL;
	char **lines, **iter;
	char *p;

	if (rc_contents)
		contents = g_strdup (rc_contents);
	else {
		if (!g_file_get_contents (_PATH_RESCONF, &contents, NULL, NULL))
			return NULL;
	}

	nameservers = g_ptr_array_new_full (3, g_free);

	lines = g_strsplit_set (contents, "\r\n", -1);
	for (iter = lines; *iter; iter++) {
		if (!g_str_has_prefix (*iter, "nameserver"))
			continue;
		p = *iter + strlen ("nameserver");
		if (!g_ascii_isspace (*p++))
			continue;
		/* Skip intermediate whitespace */
		while (g_ascii_isspace (*p))
			p++;
		g_strchomp (p);

		g_ptr_array_add (nameservers, g_strdup (p));
	}
	g_strfreev (lines);
	g_free (contents);

	return nameservers;
}

static GHashTable *
check_property_in_hash (GHashTable *hash,
                        const char *s_name,
                        const char *p_name)
{
	GHashTable *props;

	props = g_hash_table_lookup (hash, s_name);
	if (   !props
	    || !g_hash_table_lookup (props, p_name)) {
		return NULL;
	}
	return props;
}

static void
remove_from_hash (GHashTable *s_hash,
                  GHashTable *p_hash,
                  const char *s_name,
                  const char *p_name)
{
	g_hash_table_remove (p_hash, p_name);
	if (g_hash_table_size (p_hash) == 0)
		g_hash_table_remove (s_hash, s_name);
}

static gboolean
check_ip6_method (NMConnection *orig,
                  NMConnection *candidate,
                  GHashTable *settings)
{
	GHashTable *props;
	const char *orig_ip6_method, *candidate_ip6_method;
	NMSettingIPConfig *candidate_ip6;
	gboolean allow = FALSE;

	props = check_property_in_hash (settings,
	                                NM_SETTING_IP6_CONFIG_SETTING_NAME,
	                                NM_SETTING_IP_CONFIG_METHOD);
	if (!props)
		return TRUE;

	/* If the generated connection is 'link-local' and the candidate is both 'auto'
	 * and may-fail=TRUE, then the candidate is OK to use.  may-fail is included
	 * in the decision because if the candidate is 'auto' but may-fail=FALSE, then
	 * the connection could not possibly have been previously activated on the
	 * device if the device has no non-link-local IPv6 address.
	 */
	orig_ip6_method = nm_utils_get_ip_config_method (orig, NM_TYPE_SETTING_IP6_CONFIG);
	candidate_ip6_method = nm_utils_get_ip_config_method (candidate, NM_TYPE_SETTING_IP6_CONFIG);
	candidate_ip6 = nm_connection_get_setting_ip6_config (candidate);

	if (   strcmp (orig_ip6_method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0
	    && strcmp (candidate_ip6_method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0
	    && (!candidate_ip6 || nm_setting_ip_config_get_may_fail (candidate_ip6))) {
		allow = TRUE;
	}

	/* If the generated connection method is 'link-local' or 'auto' and the candidate
	 * method is 'ignore' we can take the connection, because NM didn't simply take care
	 * of IPv6.
	 */
	if (  (   strcmp (orig_ip6_method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0
	       || strcmp (orig_ip6_method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0)
	    && strcmp (candidate_ip6_method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) == 0) {
		allow = TRUE;
	}

	if (allow) {
		remove_from_hash (settings, props,
		                  NM_SETTING_IP6_CONFIG_SETTING_NAME,
		                  NM_SETTING_IP_CONFIG_METHOD);
	}
	return allow;
}

static gboolean
check_ip4_method (NMConnection *orig,
                  NMConnection *candidate,
                  GHashTable *settings,
                  gboolean device_has_carrier)
{
	GHashTable *props;
	const char *orig_ip4_method, *candidate_ip4_method;
	NMSettingIPConfig *candidate_ip4;

	props = check_property_in_hash (settings,
	                                NM_SETTING_IP4_CONFIG_SETTING_NAME,
	                                NM_SETTING_IP_CONFIG_METHOD);
	if (!props)
		return TRUE;

	/* If the generated connection is 'disabled' (device had no IP addresses)
	 * but it has no carrier, that most likely means that IP addressing could
	 * not complete and thus no IP addresses were assigned.  In that case, allow
	 * matching to the "auto" method.
	 */
	orig_ip4_method = nm_utils_get_ip_config_method (orig, NM_TYPE_SETTING_IP4_CONFIG);
	candidate_ip4_method = nm_utils_get_ip_config_method (candidate, NM_TYPE_SETTING_IP4_CONFIG);
	candidate_ip4 = nm_connection_get_setting_ip4_config (candidate);

	if (   strcmp (orig_ip4_method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0
	    && strcmp (candidate_ip4_method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0
	    && (!candidate_ip4 || nm_setting_ip_config_get_may_fail (candidate_ip4))
	    && (device_has_carrier == FALSE)) {
		remove_from_hash (settings, props,
		                  NM_SETTING_IP4_CONFIG_SETTING_NAME,
		                  NM_SETTING_IP_CONFIG_METHOD);
		return TRUE;
	}
	return FALSE;
}

static gboolean
check_connection_interface_name (NMConnection *orig,
                                 NMConnection *candidate,
                                 GHashTable *settings)
{
	GHashTable *props;
	const char *orig_ifname, *cand_ifname;
	NMSettingConnection *s_con_orig, *s_con_cand;

	props = check_property_in_hash (settings,
	                                NM_SETTING_CONNECTION_SETTING_NAME,
	                                NM_SETTING_CONNECTION_INTERFACE_NAME);
	if (!props)
		return TRUE;

	/* If one of the interface names is NULL, we accept that connection */
	s_con_orig = nm_connection_get_setting_connection (orig);
	s_con_cand = nm_connection_get_setting_connection (candidate);
	orig_ifname = nm_setting_connection_get_interface_name (s_con_orig);
	cand_ifname = nm_setting_connection_get_interface_name (s_con_cand);

	if (!orig_ifname || !cand_ifname) {
		remove_from_hash (settings, props,
		                  NM_SETTING_CONNECTION_SETTING_NAME,
		                  NM_SETTING_CONNECTION_INTERFACE_NAME);
		return TRUE;
	}
	return FALSE;
}

static gboolean
check_connection_mac_address (NMConnection *orig,
                              NMConnection *candidate,
                              GHashTable *settings)
{
	GHashTable *props;
	const char *orig_mac = NULL, *cand_mac = NULL;
	NMSettingWired *s_wired_orig, *s_wired_cand;

	props = check_property_in_hash (settings,
	                                NM_SETTING_WIRED_SETTING_NAME,
	                                NM_SETTING_WIRED_MAC_ADDRESS);
	if (!props)
		return TRUE;

	/* If one of the MAC addresses is NULL, we accept that connection */
	s_wired_orig = nm_connection_get_setting_wired (orig);
	if (s_wired_orig)
		orig_mac = nm_setting_wired_get_mac_address (s_wired_orig);

	s_wired_cand = nm_connection_get_setting_wired (candidate);
	if (s_wired_cand)
		cand_mac = nm_setting_wired_get_mac_address (s_wired_cand);

	if (!orig_mac || !cand_mac) {
		remove_from_hash (settings, props,
		                  NM_SETTING_WIRED_SETTING_NAME,
		                  NM_SETTING_WIRED_MAC_ADDRESS);
		return TRUE;
	}
	return FALSE;
}

static NMConnection *
check_possible_match (NMConnection *orig,
                      NMConnection *candidate,
                      GHashTable *settings,
                      gboolean device_has_carrier)
{
	g_return_val_if_fail (settings != NULL, NULL);

	if (!check_ip6_method (orig, candidate, settings))
		return NULL;

	if (!check_ip4_method (orig, candidate, settings, device_has_carrier))
		return NULL;

	if (!check_connection_interface_name (orig, candidate, settings))
		return NULL;

	if (!check_connection_mac_address (orig, candidate, settings))
		return NULL;

	if (g_hash_table_size (settings) == 0)
		return candidate;
	else
		return NULL;
}

/**
 * nm_utils_match_connection:
 * @connections: a (optionally pre-sorted) list of connections from which to
 * find a matching connection to @original based on "inferrable" properties
 * @original: the #NMConnection to find a match for from @connections
 * @device_has_carrier: pass %TRUE if the device that generated @original has
 * a carrier, %FALSE if not
 * @match_filter_func: a function to check whether each connection from @connections
 * should be considered for matching.  This function should return %TRUE if the
 * connection should be considered, %FALSE if the connection should be ignored
 * @match_compat_data: data pointer passed to @match_filter_func
 *
 * Checks each connection from @connections until a matching connection is found
 * considering only setting properties marked with %NM_SETTING_PARAM_INFERRABLE
 * and checking a few other characteristics like IPv6 method.  If the caller
 * desires some priority order of the connections, @connections should be
 * sorted before calling this function.
 *
 * Returns: the best #NMConnection matching @original, or %NULL if no connection
 * matches well enough.
 */
NMConnection *
nm_utils_match_connection (GSList *connections,
                           NMConnection *original,
                           gboolean device_has_carrier,
                           NMUtilsMatchFilterFunc match_filter_func,
                           gpointer match_filter_data)
{
	NMConnection *best_match = NULL;
	GSList *iter;

	for (iter = connections; iter; iter = iter->next) {
		NMConnection *candidate = NM_CONNECTION (iter->data);
		GHashTable *diffs = NULL;

		if (match_filter_func) {
			if (!match_filter_func (candidate, match_filter_data))
				continue;
		}

		if (!nm_connection_diff (original, candidate, NM_SETTING_COMPARE_FLAG_INFERRABLE, &diffs)) {
			if (!best_match)
				best_match = check_possible_match (original, candidate, diffs, device_has_carrier);

			if (!best_match && nm_logging_enabled (LOGL_DEBUG, LOGD_CORE)) {
				GString *diff_string;
				GHashTableIter s_iter, p_iter;
				gpointer setting_name, setting;
				gpointer property_name, value;

				diff_string = g_string_new (NULL);
				g_hash_table_iter_init (&s_iter, diffs);
				while (g_hash_table_iter_next (&s_iter, &setting_name, &setting)) {
					g_hash_table_iter_init (&p_iter, setting);
					while (g_hash_table_iter_next (&p_iter, &property_name, &value)) {
						if (diff_string->len)
							g_string_append (diff_string, ", ");
						g_string_append_printf (diff_string, "%s.%s",
						                        (char *) setting_name,
						                        (char *) property_name);
					}
				}

				nm_log_dbg (LOGD_CORE, "Connection '%s' differs from candidate '%s' in %s",
				            nm_connection_get_id (original),
				            nm_connection_get_id (candidate),
				            diff_string->str);
				g_string_free (diff_string, TRUE);
			}

			g_hash_table_unref (diffs);
			continue;
		}

		/* Exact match */
		return candidate;
	}

	/* Best match (if any) */
	return best_match;
}

int
nm_utils_cmp_connection_by_autoconnect_priority (NMConnection **a, NMConnection **b)
{
	NMSettingConnection *a_s_con, *b_s_con;
	gboolean a_ac, b_ac;
	gint a_ap, b_ap;

	a_s_con = nm_connection_get_setting_connection (*a);
	b_s_con = nm_connection_get_setting_connection (*b);

	a_ac = !!nm_setting_connection_get_autoconnect (a_s_con);
	b_ac = !!nm_setting_connection_get_autoconnect (b_s_con);
	if (a_ac != b_ac)
		return ((int) b_ac) - ((int) a_ac);
	if (!a_ac)
		return 0;

	a_ap = nm_setting_connection_get_autoconnect_priority (a_s_con);
	b_ap = nm_setting_connection_get_autoconnect_priority (b_s_con);
	if (a_ap != b_ap)
		return (a_ap > b_ap) ? -1 : 1;

	return 0;
}

/* nm_utils_ascii_str_to_int64:
 *
 * A wrapper for g_ascii_strtoll, that checks whether the whole string
 * can be successfully converted to a number and is within a given
 * range. On any error, @fallback will be returned and %errno will be set
 * to a non-zero value. On success, %errno will be set to zero, check %errno
 * for errors. Any trailing or leading (ascii) white space is ignored and the
 * functions is locale independent.
 *
 * The function is guaranteed to return a value between @min and @max
 * (inclusive) or @fallback. Also, the parsing is rather strict, it does
 * not allow for any unrecognized characters, except leading and trailing
 * white space.
 **/
gint64
nm_utils_ascii_str_to_int64 (const char *str, guint base, gint64 min, gint64 max, gint64 fallback)
{
	gint64 v;
	size_t len;
	char buf[64], *s, *str_free = NULL;

	if (str) {
		while (g_ascii_isspace (str[0]))
			str++;
	}
	if (!str || !str[0]) {
		errno = EINVAL;
		return fallback;
	}

	len = strlen (str);
	if (g_ascii_isspace (str[--len])) {
		/* backward search the first non-ws character.
		 * We already know that str[0] is non-ws. */
		while (g_ascii_isspace (str[--len]))
			;

		/* str[len] is now the last non-ws character... */
		len++;

		if (len >= sizeof (buf))
			s = str_free = g_malloc (len + 1);
		else
			s = buf;

		memcpy (s, str, len);
		s[len] = 0;

		/*
		g_assert (len > 0 && len < strlen (str) && len == strlen (s));
		g_assert (!g_ascii_isspace (str[len-1]) && g_ascii_isspace (str[len]));
		g_assert (strncmp (str, s, len) == 0);
		*/

		str = s;
	}

	errno = 0;
	v = g_ascii_strtoll (str, &s, base);

	if (errno != 0)
		v = fallback;
	else if (s[0] != 0) {
		errno = EINVAL;
		v = fallback;
	} else if (v > max || v < min) {
		errno = ERANGE;
		v = fallback;
	}

	if (G_UNLIKELY (str_free))
		g_free (str_free);
	return v;
}

/**
 * nm_utils_uuid_generate_from_strings:
 * @string1: a variadic list of strings. Must be NULL terminated.
 *
 * Returns a variant3 UUID based on the concatenated C strings.
 * It does not simply concatenate them, but also includes the
 * terminating '\0' character. For example "a", "b", gives
 * "a\0b\0\0".
 *
 * This has the advantage, that the following invocations
 * all give different UUIDs: (""), ("",""), ("","a"), ("a",""),
 * ("aa"), ("aa", ""), ("", "aa"), ...
 */
char *
nm_utils_uuid_generate_from_strings (const char *string1, ...)
{
	GString *str;
	va_list args;
	const char *s;
	char *uuid;

	if (!string1)
		return nm_utils_uuid_generate_from_string (NULL, 0, NM_UTILS_UUID_TYPE_VARIANT3, NM_UTILS_UUID_NS);

	str = g_string_sized_new (120); /* effectively allocates power of 2 (128)*/

	g_string_append_len (str, string1, strlen (string1) + 1);

	va_start (args, string1);
	s = va_arg (args, const char *);
	while (s) {
		g_string_append_len (str, s, strlen (s) + 1);
		s = va_arg (args, const char *);
	}
	va_end (args);

	uuid = nm_utils_uuid_generate_from_string (str->str, str->len, NM_UTILS_UUID_TYPE_VARIANT3, NM_UTILS_UUID_NS);

	g_string_free (str, TRUE);
	return uuid;
}

/**************************************************************************/

static gint64 monotonic_timestamp_offset_sec;

static void
monotonic_timestamp_get (struct timespec *tp)
{
	static int clock_mode = 0;
	gboolean first_time = FALSE;
	int err = 0;

	switch (clock_mode) {
	case 0:
		/* the clock is not yet initialized (first run) */
		err = clock_gettime (CLOCK_BOOTTIME, tp);
		if (err == -1 && errno == EINVAL) {
			clock_mode = 2;
			err = clock_gettime (CLOCK_MONOTONIC, tp);
		} else
			clock_mode = 1;
		first_time = TRUE;
		break;
	case 1:
		/* default, return CLOCK_BOOTTIME */
		err = clock_gettime (CLOCK_BOOTTIME, tp);
		break;
	case 2:
		/* fallback, return CLOCK_MONOTONIC. Kernels prior to 2.6.39
		 * don't support CLOCK_BOOTTIME. */
		err = clock_gettime (CLOCK_MONOTONIC, tp);
		break;
	}

	g_assert (err == 0); (void)err;
	g_assert (tp->tv_nsec >= 0 && tp->tv_nsec < NM_UTILS_NS_PER_SECOND);

	if (G_LIKELY (!first_time))
		return;

	/* Calculate an offset for the time stamp.
	 *
	 * We always want positive values, because then we can initialize
	 * a timestamp with 0 and be sure, that it will be less then any
	 * value nm_utils_get_monotonic_timestamp_*() might return.
	 * For this to be true also for nm_utils_get_monotonic_timestamp_s() at
	 * early boot, we have to shift the timestamp to start counting at
	 * least from 1 second onward.
	 *
	 * Another advantage of shifting is, that this way we make use of the whole 31 bit
	 * range of signed int, before the time stamp for nm_utils_get_monotonic_timestamp_s()
	 * wraps (~68 years).
	 **/
	monotonic_timestamp_offset_sec = (- ((gint64) tp->tv_sec)) + 1;

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_CORE)) {
		time_t now = time (NULL);
		struct tm tm;
		char s[255];

		strftime (s, sizeof (s), "%Y-%m-%d %H:%M:%S", localtime_r (&now, &tm));
		nm_log_dbg (LOGD_CORE, "monotonic timestamp started counting 1.%09ld seconds ago with "
		                       "an offset of %lld.0 seconds to %s (local time is %s)",
		                       tp->tv_nsec, (long long) -monotonic_timestamp_offset_sec,
		                       clock_mode == 1 ? "CLOCK_BOOTTIME" : "CLOCK_MONOTONIC", s);
	}
}

/**
 * nm_utils_get_monotonic_timestamp_ns:
 *
 * Returns: a monotonically increasing time stamp in nanoseconds,
 * starting at an unspecified offset. See clock_gettime(), %CLOCK_BOOTTIME.
 *
 * The returned value will start counting at an undefined point
 * in the past and will always be positive.
 *
 * All the nm_utils_get_monotonic_timestamp_*s functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint64
nm_utils_get_monotonic_timestamp_ns (void)
{
	struct timespec tp = { 0 };

	monotonic_timestamp_get (&tp);

	/* Although the result will always be positive, we return a signed
	 * integer, which makes it easier to calculate time differences (when
	 * you want to subtract signed values).
	 **/
	return (((gint64) tp.tv_sec) + monotonic_timestamp_offset_sec) * NM_UTILS_NS_PER_SECOND +
	       tp.tv_nsec;
}

/**
 * nm_utils_get_monotonic_timestamp_us:
 *
 * Returns: a monotonically increasing time stamp in microseconds,
 * starting at an unspecified offset. See clock_gettime(), %CLOCK_BOOTTIME.
 *
 * The returned value will start counting at an undefined point
 * in the past and will always be positive.
 *
 * All the nm_utils_get_monotonic_timestamp_*s functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint64
nm_utils_get_monotonic_timestamp_us (void)
{
	struct timespec tp = { 0 };

	monotonic_timestamp_get (&tp);

	/* Although the result will always be positive, we return a signed
	 * integer, which makes it easier to calculate time differences (when
	 * you want to subtract signed values).
	 **/
	return (((gint64) tp.tv_sec) + monotonic_timestamp_offset_sec) * ((gint64) G_USEC_PER_SEC) +
	       (tp.tv_nsec / (NM_UTILS_NS_PER_SECOND/G_USEC_PER_SEC));
}

/**
 * nm_utils_get_monotonic_timestamp_ms:
 *
 * Returns: a monotonically increasing time stamp in milliseconds,
 * starting at an unspecified offset. See clock_gettime(), %CLOCK_BOOTTIME.
 *
 * The returned value will start counting at an undefined point
 * in the past and will always be positive.
 *
 * All the nm_utils_get_monotonic_timestamp_*s functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint64
nm_utils_get_monotonic_timestamp_ms (void)
{
	struct timespec tp = { 0 };

	monotonic_timestamp_get (&tp);

	/* Although the result will always be positive, we return a signed
	 * integer, which makes it easier to calculate time differences (when
	 * you want to subtract signed values).
	 **/
	return (((gint64) tp.tv_sec) + monotonic_timestamp_offset_sec) * ((gint64) 1000) +
	       (tp.tv_nsec / (NM_UTILS_NS_PER_SECOND/1000));
}

/**
 * nm_utils_get_monotonic_timestamp_s:
 *
 * Returns: nm_utils_get_monotonic_timestamp_ms() in seconds (throwing
 * away sub second parts). The returned value will always be positive.
 *
 * This value wraps after roughly 68 years which should be fine for any
 * practical purpose.
 *
 * All the nm_utils_get_monotonic_timestamp_*s functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint32
nm_utils_get_monotonic_timestamp_s (void)
{
	struct timespec tp = { 0 };

	monotonic_timestamp_get (&tp);
	return (((gint64) tp.tv_sec) + monotonic_timestamp_offset_sec);
}

typedef struct
{
	const char *name;
	NMSetting *setting;
	NMSetting *diff_base_setting;
	GHashTable *setting_diff;
} LogConnectionSettingData;

typedef struct
{
	const char *item_name;
	NMSettingDiffResult diff_result;
} LogConnectionSettingItem;

static gint
_log_connection_sort_hashes_fcn (gconstpointer a, gconstpointer b)
{
	const LogConnectionSettingData *v1 = a;
	const LogConnectionSettingData *v2 = b;
	guint32 p1, p2;
	NMSetting *s1, *s2;

	s1 = v1->setting ? v1->setting : v1->diff_base_setting;
	s2 = v2->setting ? v2->setting : v2->diff_base_setting;

	g_assert (s1 && s2);

	p1 = _nm_setting_get_setting_priority (s1);
	p2 = _nm_setting_get_setting_priority (s2);

	if (p1 != p2)
		return p1 > p2 ? 1 : -1;

	return strcmp (v1->name, v2->name);
}

static GArray *
_log_connection_sort_hashes (NMConnection *connection, NMConnection *diff_base, GHashTable *connection_diff)
{
	GHashTableIter iter;
	GArray *sorted_hashes;
	LogConnectionSettingData setting_data;

	sorted_hashes = g_array_sized_new (TRUE, FALSE, sizeof (LogConnectionSettingData), g_hash_table_size (connection_diff));

	g_hash_table_iter_init (&iter, connection_diff);
	while (g_hash_table_iter_next (&iter, (gpointer) &setting_data.name, (gpointer) &setting_data.setting_diff)) {
		setting_data.setting = nm_connection_get_setting_by_name (connection, setting_data.name);
		setting_data.diff_base_setting = diff_base ? nm_connection_get_setting_by_name (diff_base, setting_data.name) : NULL;
		g_assert (setting_data.setting || setting_data.diff_base_setting);
		g_array_append_val (sorted_hashes, setting_data);
	}

	g_array_sort (sorted_hashes, _log_connection_sort_hashes_fcn);
	return sorted_hashes;
}

static gint
_log_connection_sort_names_fcn (gconstpointer a, gconstpointer b)
{
	const LogConnectionSettingItem *v1 = a;
	const LogConnectionSettingItem *v2 = b;

	/* we want to first show the items, that disappeared, then the one that changed and
	 * then the ones that were added. */

	if ((v1->diff_result & NM_SETTING_DIFF_RESULT_IN_A) != (v2->diff_result & NM_SETTING_DIFF_RESULT_IN_A))
		return (v1->diff_result & NM_SETTING_DIFF_RESULT_IN_A) ? -1 : 1;
	if ((v1->diff_result & NM_SETTING_DIFF_RESULT_IN_B) != (v2->diff_result & NM_SETTING_DIFF_RESULT_IN_B))
		return (v1->diff_result & NM_SETTING_DIFF_RESULT_IN_B) ? 1 : -1;
	return strcmp (v1->item_name, v2->item_name);
}

static char *
_log_connection_get_property (NMSetting *setting, const char *name)
{
	GValue val = G_VALUE_INIT;
	char *s;

	g_return_val_if_fail (setting, NULL);

	if (   !NM_IS_SETTING_VPN (setting)
	    && nm_setting_get_secret_flags (setting, name, NULL, NULL))
		return g_strdup ("****");

	if (!_nm_setting_get_property (setting, name, &val))
		g_return_val_if_reached (FALSE);

	if (G_VALUE_HOLDS_STRING (&val)) {
		const char *val_s;

		val_s = g_value_get_string (&val);
		if (!val_s) {
			/* for NULL, we want to return the unquoted string "NULL". */
			s = g_strdup ("NULL");
		} else {
			char *escaped = g_strescape (val_s, "'");

			s = g_strdup_printf ("'%s'", escaped);
			g_free (escaped);
		}
	} else {
		s = g_strdup_value_contents (&val);
		if (s == NULL)
			s = g_strdup ("NULL");
		else {
			char *escaped = g_strescape (s, "'");

			g_free (s);
			s = escaped;
		}
	}
	g_value_unset(&val);
	return s;
}

static void
_log_connection_sort_names (LogConnectionSettingData *setting_data, GArray *sorted_names)
{
	GHashTableIter iter;
	LogConnectionSettingItem item;
	gpointer p;

	g_array_set_size (sorted_names, 0);

	g_hash_table_iter_init (&iter, setting_data->setting_diff);
	while (g_hash_table_iter_next (&iter, (gpointer) &item.item_name, &p)) {
		item.diff_result = GPOINTER_TO_UINT (p);
		g_array_append_val (sorted_names, item);
	}

	g_array_sort (sorted_names, _log_connection_sort_names_fcn);
}

void
nm_utils_log_connection_diff (NMConnection *connection, NMConnection *diff_base, guint32 level, guint64 domain, const char *name, const char *prefix)
{
	GHashTable *connection_diff = NULL;
	GArray *sorted_hashes;
	GArray *sorted_names = NULL;
	int i, j;
	gboolean connection_diff_are_same;
	gboolean print_header = TRUE;
	gboolean print_setting_header;
	GString *str1;

	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (!diff_base || (NM_IS_CONNECTION (diff_base) && diff_base != connection));

	/* For VPN setting types, this is broken, because we cannot (generically) print the content of data/secrets. Bummer... */

	if (!nm_logging_enabled (level, domain))
		return;

	if (!prefix)
		prefix = "";
	if (!name)
		name = "";

	connection_diff_are_same = nm_connection_diff (connection, diff_base, NM_SETTING_COMPARE_FLAG_EXACT | NM_SETTING_COMPARE_FLAG_DIFF_RESULT_NO_DEFAULT, &connection_diff);
	if (connection_diff_are_same) {
		if (diff_base)
			nm_log (level, domain, "%sconnection '%s' (%p/%s and %p/%s): no difference", prefix, name, connection, G_OBJECT_TYPE_NAME (connection), diff_base, G_OBJECT_TYPE_NAME (diff_base));
		else
			nm_log (level, domain, "%sconnection '%s' (%p/%s): no properties set", prefix, name, connection, G_OBJECT_TYPE_NAME (connection));
		g_assert (!connection_diff);
		return;
	}

	/* FIXME: it doesn't nicely show the content of NMSettingVpn, becuase nm_connection_diff() does not
	 * expand the hash values. */

	sorted_hashes = _log_connection_sort_hashes (connection, diff_base, connection_diff);
	if (sorted_hashes->len <= 0)
		goto out;

	sorted_names = g_array_new (FALSE, FALSE, sizeof (LogConnectionSettingItem));
	str1 = g_string_new (NULL);

	for (i = 0; i < sorted_hashes->len; i++) {
		LogConnectionSettingData *setting_data = &g_array_index (sorted_hashes, LogConnectionSettingData, i);

		_log_connection_sort_names (setting_data, sorted_names);
		print_setting_header = TRUE;
		for (j = 0; j < sorted_names->len; j++) {
			char *str_conn, *str_diff;
			LogConnectionSettingItem *item = &g_array_index (sorted_names, LogConnectionSettingItem, j);

			str_conn = (item->diff_result & NM_SETTING_DIFF_RESULT_IN_A)
			           ? _log_connection_get_property (setting_data->setting, item->item_name)
			           : NULL;
			str_diff = (item->diff_result & NM_SETTING_DIFF_RESULT_IN_B)
			           ? _log_connection_get_property (setting_data->diff_base_setting, item->item_name)
			           : NULL;

			if (print_header) {
				GError *err_verify = NULL;

				if (diff_base)
					nm_log (level, domain, "%sconnection '%s' (%p/%s < %p/%s):", prefix, name, connection, G_OBJECT_TYPE_NAME (connection), diff_base, G_OBJECT_TYPE_NAME (diff_base));
				else
					nm_log (level, domain, "%sconnection '%s' (%p/%s):", prefix, name, connection, G_OBJECT_TYPE_NAME (connection));
				print_header = FALSE;

				if (!nm_connection_verify (connection, &err_verify)) {
					nm_log (level, domain, "%sconnection %p does not verify: %s", prefix, connection, err_verify->message);
					g_clear_error (&err_verify);
				}
			}
#define _NM_LOG_ALIGN "-25"
			if (print_setting_header) {
				if (diff_base) {
					if (setting_data->setting && setting_data->diff_base_setting)
						g_string_printf (str1, "%p < %p", setting_data->setting, setting_data->diff_base_setting);
					else if (setting_data->diff_base_setting)
						g_string_printf (str1, "*missing* < %p", setting_data->diff_base_setting);
					else
						g_string_printf (str1, "%p < *missing*", setting_data->setting);
					nm_log (level, domain, "%s%"_NM_LOG_ALIGN"s [ %s ]", prefix, setting_data->name, str1->str);
				} else
					nm_log (level, domain, "%s%"_NM_LOG_ALIGN"s [ %p ]", prefix, setting_data->name, setting_data->setting);
				print_setting_header = FALSE;
			}
			g_string_printf (str1, "%s.%s", setting_data->name, item->item_name);
			switch (item->diff_result & (NM_SETTING_DIFF_RESULT_IN_A | NM_SETTING_DIFF_RESULT_IN_B)) {
				case NM_SETTING_DIFF_RESULT_IN_B:
					nm_log (level, domain, "%s%"_NM_LOG_ALIGN"s < %s", prefix, str1->str, str_diff ? str_diff : "NULL");
					break;
				case NM_SETTING_DIFF_RESULT_IN_A:
					nm_log (level, domain, "%s%"_NM_LOG_ALIGN"s = %s", prefix, str1->str, str_conn ? str_conn : "NULL");
					break;
				default:
					nm_log (level, domain, "%s%"_NM_LOG_ALIGN"s = %s < %s", prefix, str1->str, str_conn ? str_conn : "NULL", str_diff ? str_diff : "NULL");
					break;
#undef _NM_LOG_ALIGN
			}
			g_free (str_conn);
			g_free (str_diff);
		}
	}

	g_array_free (sorted_names, TRUE);
	g_string_free (str1, TRUE);
out:
	g_hash_table_destroy (connection_diff);
	g_array_free (sorted_hashes, TRUE);
}


#define IPV6_PROPERTY_DIR "/proc/sys/net/ipv6/conf/"
#define IPV4_PROPERTY_DIR "/proc/sys/net/ipv4/conf/"
G_STATIC_ASSERT (sizeof (IPV4_PROPERTY_DIR) == sizeof (IPV6_PROPERTY_DIR));

static const char *
_get_property_path (const char *ifname,
                    const char *property,
                    gboolean ipv6)
{
	static char path[sizeof (IPV6_PROPERTY_DIR) + IFNAMSIZ + 32];
	int len;

	ifname = ASSERT_VALID_PATH_COMPONENT (ifname);
	property = ASSERT_VALID_PATH_COMPONENT (property);

	len = g_snprintf (path,
	                  sizeof (path),
	                  "%s%s/%s",
	                  ipv6 ? IPV6_PROPERTY_DIR : IPV4_PROPERTY_DIR,
	                  ifname,
	                  property);
	g_assert (len < sizeof (path) - 1);

	return path;
}

/**
 * nm_utils_ip6_property_path:
 * @ifname: an interface name
 * @property: a property name
 *
 * Returns the path to IPv6 property @property on @ifname. Note that
 * this uses a static buffer.
 */
const char *
nm_utils_ip6_property_path (const char *ifname, const char *property)
{
	return _get_property_path (ifname, property, TRUE);
}

/**
 * nm_utils_ip4_property_path:
 * @ifname: an interface name
 * @property: a property name
 *
 * Returns the path to IPv4 property @property on @ifname. Note that
 * this uses a static buffer.
 */
const char *
nm_utils_ip4_property_path (const char *ifname, const char *property)
{
	return _get_property_path (ifname, property, FALSE);
}

const char *
ASSERT_VALID_PATH_COMPONENT (const char *name)
{
	const char *n;

	if (name == NULL || name[0] == '\0')
		goto fail;

	if (name[0] == '.') {
		if (name[1] == '\0')
			goto fail;
		if (name[1] == '.' && name[2] == '\0')
			goto fail;
	}
	n = name;
	do {
		if (*n == '/')
			goto fail;
	} while (*(++n) != '\0');

	return name;
fail:
	if (name)
		nm_log_err (LOGD_CORE, "Failed asserting path component: NULL");
	else
		nm_log_err (LOGD_CORE, "Failed asserting path component: \"%s\"", name);
	g_error ("FATAL: Failed asserting path component: %s", name ? name : "(null)");
	g_assert_not_reached ();
}

gboolean
nm_utils_is_specific_hostname (const char *name)
{
	if (!name)
		return FALSE;
	if (   strcmp (name, "(none)")
	    && strcmp (name, "localhost")
	    && strcmp (name, "localhost6")
	    && strcmp (name, "localhost.localdomain")
	    && strcmp (name, "localhost6.localdomain6"))
		return TRUE;
	return FALSE;
}

/******************************************************************/

/* Returns the "u" (universal/local) bit value for a Modified EUI-64 */
static gboolean
get_gre_eui64_u_bit (guint32 addr)
{
	static const struct {
		guint32 mask;
		guint32 result;
	} items[] = {
		{ 0xff000000 }, { 0x7f000000 },  /* IPv4 loopback */
		{ 0xf0000000 }, { 0xe0000000 },  /* IPv4 multicast */
		{ 0xffffff00 }, { 0xe0000000 },  /* IPv4 local multicast */
		{ 0xffffffff }, { INADDR_BROADCAST },  /* limited broadcast */
		{ 0xff000000 }, { 0x00000000 },  /* zero net */
		{ 0xff000000 }, { 0x0a000000 },  /* private 10 (RFC3330) */
		{ 0xfff00000 }, { 0xac100000 },  /* private 172 */
		{ 0xffff0000 }, { 0xc0a80000 },  /* private 192 */
		{ 0xffff0000 }, { 0xa9fe0000 },  /* IPv4 link-local */
		{ 0xffffff00 }, { 0xc0586300 },  /* anycast 6-to-4 */
		{ 0xffffff00 }, { 0xc0000200 },  /* test 192 */
		{ 0xfffe0000 }, { 0xc6120000 },  /* test 198 */
	};
	guint i;

	for (i = 0; i < G_N_ELEMENTS (items); i++) {
		if ((addr & htonl (items[i].mask)) == htonl (items[i].result))
			return 0x00; /* "local" scope */
	}
	return 0x02; /* "universal" scope */
}

/**
 * nm_utils_get_ipv6_interface_identifier:
 * @link_type: the hardware link type
 * @hwaddr: the hardware address of the interface
 * @hwaddr_len: the length (in bytes) of @hwaddr
 * @out_iid: on success, filled with the interface identifier; on failure
 * zeroed out
 *
 * Constructs an interface identifier in "Modified EUI-64" format which is
 * suitable for constructing IPv6 addresses.  Note that the identifier is
 * not obscured in any way (eg, RFC3041).
 *
 * Returns: %TRUE if the interface identifier could be constructed, %FALSE if
 * if could not be constructed.
 */
gboolean
nm_utils_get_ipv6_interface_identifier (NMLinkType link_type,
                                        const guint8 *hwaddr,
                                        guint hwaddr_len,
                                        NMUtilsIPv6IfaceId *out_iid)
{
	guint32 addr;

	g_return_val_if_fail (hwaddr != NULL, FALSE);
	g_return_val_if_fail (hwaddr_len > 0, FALSE);
	g_return_val_if_fail (out_iid != NULL, FALSE);

	out_iid->id = 0;

	switch (link_type) {
	case NM_LINK_TYPE_INFINIBAND:
		/* Use the port GUID per http://tools.ietf.org/html/rfc4391#section-8,
		 * making sure to set the 'u' bit to 1.  The GUID is the lower 64 bits
		 * of the IPoIB interface's hardware address.
		 */
		g_return_val_if_fail (hwaddr_len == INFINIBAND_ALEN, FALSE);
		memcpy (out_iid->id_u8, hwaddr + INFINIBAND_ALEN - 8, 8);
		out_iid->id_u8[0] |= 0x02;
		return TRUE;
	case NM_LINK_TYPE_GRE:
	case NM_LINK_TYPE_GRETAP:
		/* Hardware address is the network-endian IPv4 address */
		g_return_val_if_fail (hwaddr_len == 4, FALSE);
		addr = * (guint32 *) hwaddr;
		out_iid->id_u8[0] = get_gre_eui64_u_bit (addr);
		out_iid->id_u8[1] = 0x00;
		out_iid->id_u8[2] = 0x5E;
		out_iid->id_u8[3] = 0xFE;
		memcpy (out_iid->id_u8 + 4, &addr, 4);
		return TRUE;
	default:
		if (hwaddr_len == ETH_ALEN) {
			/* Translate 48-bit MAC address to a 64-bit Modified EUI-64.  See
			 * http://tools.ietf.org/html/rfc4291#appendix-A
			 */
			out_iid->id_u8[0] = hwaddr[0] ^ 0x02;
			out_iid->id_u8[1] = hwaddr[1];
			out_iid->id_u8[2] = hwaddr[2];
			out_iid->id_u8[3] = 0xff;
			out_iid->id_u8[4] = 0xfe;
			out_iid->id_u8[5] = hwaddr[3];
			out_iid->id_u8[6] = hwaddr[4];
			out_iid->id_u8[7] = hwaddr[5];
			return TRUE;
		}
		break;
	}
	return FALSE;
}

void
nm_utils_ipv6_addr_set_interface_identfier (struct in6_addr *addr,
                                            const NMUtilsIPv6IfaceId iid)
{
	memcpy (addr->s6_addr + 8, &iid.id_u8, 8);
}

void
nm_utils_ipv6_interface_identfier_get_from_addr (NMUtilsIPv6IfaceId *iid,
                                                 const struct in6_addr *addr)
{
	memcpy (iid, addr->s6_addr + 8, 8);
}

/**
 * nm_utils_connection_hash_to_dict:
 * @hash: a hashed #NMConnection
 *
 * Returns: a (floating) #GVariant equivalent to @hash.
 */
GVariant *
nm_utils_connection_hash_to_dict (GHashTable *hash)
{
	GValue val = { 0, };
	GVariant *variant;

	if (!hash)
		return NULL;

	g_value_init (&val, DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT);
	g_value_set_boxed (&val, hash);
	variant = dbus_g_value_build_g_variant (&val);
	g_value_unset (&val);

	return variant;
}

/**
 * nm_utils_connection_dict_to_hash:
 * @dict: a #GVariant-serialized #NMConnection
 *
 * Returns: a #GHashTable equivalent to @dict.
 */
GHashTable *
nm_utils_connection_dict_to_hash (GVariant *dict)
{
	GValue val = { 0, };

	if (!dict)
		return NULL;

	dbus_g_value_parse_g_variant (dict, &val);
	return g_value_get_boxed (&val);
}

GSList *
nm_utils_ip4_routes_from_gvalue (const GValue *value)
{
	GPtrArray *routes;
	int i;
	GSList *list = NULL;

	routes = (GPtrArray *) g_value_get_boxed (value);
	for (i = 0; routes && (i < routes->len); i++) {
		GArray *array = (GArray *) g_ptr_array_index (routes, i);
		guint32 *array_val = (guint32 *) array->data;
		NMIPRoute *route;
		GError *error = NULL;

		if (array->len < 4) {
			g_warning ("Ignoring invalid IP4 route");
			continue;
		}

		route = nm_ip_route_new_binary (AF_INET,
		                                &array_val[0], array_val[1],
		                                &array_val[2], array_val[3],
		                                &error);
		if (route)
			list = g_slist_prepend (list, route);
		else {
			g_warning ("Ignoring invalid IP4 route: %s", error->message);
			g_clear_error (&error);
		}
	}

	return g_slist_reverse (list);
}

static gboolean
_nm_utils_gvalue_array_validate (GValueArray *elements, guint n_expected, ...)
{
	va_list args;
	GValue *tmp;
	int i;
	gboolean valid = FALSE;

	if (n_expected != elements->n_values)
		return FALSE;

	va_start (args, n_expected);
	for (i = 0; i < n_expected; i++) {
		tmp = g_value_array_get_nth (elements, i);
		if (G_VALUE_TYPE (tmp) != va_arg (args, GType))
			goto done;
	}
	valid = TRUE;

done:
	va_end (args);
	return valid;
}

GSList *
nm_utils_ip6_routes_from_gvalue (const GValue *value)
{
	GPtrArray *routes;
	int i;
	GSList *list = NULL;

	routes = (GPtrArray *) g_value_get_boxed (value);
	for (i = 0; routes && (i < routes->len); i++) {
		GValueArray *route_values = (GValueArray *) g_ptr_array_index (routes, i);
		GByteArray *dest, *next_hop;
		guint prefix, metric;
		NMIPRoute *route;
		GError *error = NULL;

		if (!_nm_utils_gvalue_array_validate (route_values, 4,
		                                      DBUS_TYPE_G_UCHAR_ARRAY,
		                                      G_TYPE_UINT,
		                                      DBUS_TYPE_G_UCHAR_ARRAY,
		                                      G_TYPE_UINT)) {
			g_warning ("Ignoring invalid IP6 route");
			continue;
		}

		dest = g_value_get_boxed (g_value_array_get_nth (route_values, 0));
		if (dest->len != 16) {
			g_warning ("%s: ignoring invalid IP6 dest address of length %d",
			           __func__, dest->len);
			continue;
		}

		prefix = g_value_get_uint (g_value_array_get_nth (route_values, 1));

		next_hop = g_value_get_boxed (g_value_array_get_nth (route_values, 2));
		if (next_hop->len != 16) {
			g_warning ("%s: ignoring invalid IP6 next_hop address of length %d",
			           __func__, next_hop->len);
			continue;
		}

		metric = g_value_get_uint (g_value_array_get_nth (route_values, 3));

		route = nm_ip_route_new_binary (AF_INET6,
		                                dest->data, prefix,
		                                next_hop->data, metric,
		                                &error);
		if (route)
			list = g_slist_prepend (list, route);
		else {
			g_warning ("Ignoring invalid IP6 route: %s", error->message);
			g_clear_error (&error);
		}
	}

	return g_slist_reverse (list);
}
