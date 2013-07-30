/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
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
 * (C) Copyright 2008 - 2014 Red Hat, Inc.
 * Author: David Zeuthen <davidz@redhat.com>
 * Author: Dan Williams <dcbw@redhat.com>
 * Author: Matthias Clasen
 * Author: Pavel Šimerda <psimerda@redhat.com>
 */
#include "config.h"

#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <sys/stat.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <stdlib.h>

#ifdef SESSION_TRACKING_SYSTEMD
#include <systemd/sd-login.h>
#endif

#include "nm-session-monitor.h"
#include "nm-logging.h"

/********************************************************************/

/* <internal>
 * SECTION:nm-session-monitor
 * @title: NMSessionMonitor
 * @short_description: Monitor sessions
 *
 * The #NMSessionMonitor class is a utility class to track and monitor sessions.
 */

struct _NMSessionMonitor {
	GObject parent_instance;

	GKeyFile *database;
	GFileMonitor *database_monitor;
	time_t database_mtime;
	GHashTable *sessions_by_uid;
	GHashTable *sessions_by_user;

	GSource *sd_source;
};

struct _NMSessionMonitorClass {
	GObjectClass parent_class;

	void (*changed) (NMSessionMonitor *monitor);
};

G_DEFINE_TYPE (NMSessionMonitor, nm_session_monitor, G_TYPE_OBJECT);

enum {
	CHANGED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

#define NM_SESSION_MONITOR_ERROR         (nm_session_monitor_error_quark ())
GType  nm_session_monitor_error_get_type (void) G_GNUC_CONST;

typedef enum {
	NM_SESSION_MONITOR_ERROR_IO_ERROR = 0,       /*< nick=IOError >*/
	NM_SESSION_MONITOR_ERROR_MALFORMED_DATABASE, /*< nick=MalformedDatabase >*/
	NM_SESSION_MONITOR_ERROR_UNKNOWN_USER,       /*< nick=UnknownUser >*/
	NM_SESSION_MONITOR_ERROR_NO_DATABASE,        /*< nick=NoDatabase >*/
} NMSessionMonitorError;

static GQuark
nm_session_monitor_error_quark (void)
{
	static GQuark quark = 0;

	if (G_UNLIKELY (quark == 0))
		quark = g_quark_from_static_string ("nm-session-monitor-error");

	return quark;
}

/********************************************************************/

static gboolean
nm_session_monitor_uid_to_user (uid_t uid, const char **out_user, GError **error)
{
	struct passwd *pw;

	pw = getpwuid (uid);
	if (!pw) {
		g_set_error (error,
			         NM_SESSION_MONITOR_ERROR,
			         NM_SESSION_MONITOR_ERROR_UNKNOWN_USER,
			         "Could not get username for UID %d",
			         uid);
		return FALSE;
	}

	if (out_user)
		*out_user = pw->pw_name;
	return TRUE;
}

static gboolean
nm_session_monitor_user_to_uid (const char *user, uid_t *out_uid, GError **error)
{
	struct passwd *pw;

	pw = getpwnam (user);
	if (!pw) {
		g_set_error (error,
			         NM_SESSION_MONITOR_ERROR,
			         NM_SESSION_MONITOR_ERROR_UNKNOWN_USER,
			         "Could not get UID for username '%s'",
			         user);
		return FALSE;
	}

	if (out_uid)
		*out_uid = pw->pw_uid;
	return TRUE;
}

/********************************************************************/

#ifdef SESSION_TRACKING_SYSTEMD
typedef struct {
	GSource source;
	GPollFD pollfd;
	sd_login_monitor *monitor;
} SdSource;

static gboolean
sd_source_prepare (GSource *source, gint *timeout)
{
	*timeout = -1;
	return FALSE;
}

static gboolean
sd_source_check (GSource *source)
{
	SdSource *sd_source = (SdSource *) source;

	return sd_source->pollfd.revents != 0;
}

static gboolean
sd_source_dispatch (GSource     *source,
                    GSourceFunc  callback,
                    gpointer     user_data)

{
	SdSource *sd_source = (SdSource *)source;
	gboolean ret;

	g_warn_if_fail (callback != NULL);
	ret = (*callback) (user_data);
	sd_login_monitor_flush (sd_source->monitor);
	return ret;
}

static void
sd_source_finalize (GSource *source)
{
	SdSource *sd_source = (SdSource*) source;

	sd_login_monitor_unref (sd_source->monitor);
}

static GSourceFuncs sd_source_funcs = {
	sd_source_prepare,
	sd_source_check,
	sd_source_dispatch,
	sd_source_finalize
};

static GSource *
sd_source_new (void)
{
	GSource *source;
	SdSource *sd_source;
	int ret;

	source = g_source_new (&sd_source_funcs, sizeof (SdSource));
	sd_source = (SdSource *)source;

	ret = sd_login_monitor_new (NULL, &sd_source->monitor);
	if (ret < 0)
		g_printerr ("Error getting login monitor: %d", ret);
	else {
		sd_source->pollfd.fd = sd_login_monitor_get_fd (sd_source->monitor);
		sd_source->pollfd.events = G_IO_IN;
		g_source_add_poll (source, &sd_source->pollfd);
	}

	return source;
}

static gboolean
sessions_changed (gpointer user_data)
{
	NMSessionMonitor *monitor = NM_SESSION_MONITOR (user_data);

	g_signal_emit (monitor, signals[CHANGED], 0);
	return TRUE;
}

static gboolean
nm_session_monitor_lookup_systemd (uid_t uid, gboolean active, GError **error)
{
	int status;

	status = sd_uid_get_sessions (uid, active, NULL) > 0;
	if (status < 0) {
		nm_log_warn (LOGD_CORE, "Failed to get systemd sessions for uid %d: %d",
		             uid, status);
		return FALSE;
	}
	return status > 0 ? TRUE : FALSE;
}

static void
nm_session_monitor_init_systemd (NMSessionMonitor *monitor)
{
	if (access("/run/systemd/seats/", F_OK) < 0)
		return;
	
	monitor->sd_source = sd_source_new ();
	g_source_set_callback (monitor->sd_source, sessions_changed, monitor, NULL);
	g_source_attach (monitor->sd_source, NULL);
}

static void
nm_session_monitor_finalize_systemd (NMSessionMonitor *monitor)
{
	if (!monitor->sd_source)
		return;
	
	g_source_destroy (monitor->sd_source);
	g_source_unref (monitor->sd_source);
}
#endif /* SESSION_TRACKING_SYSTEMD */

/********************************************************************/

#ifdef SESSION_TRACKING_CONSOLEKIT
typedef struct {
	char *user;
	uid_t uid;
	gboolean local;
	gboolean active;
} Session;

static void
session_free (Session *session)
{
	g_free (session->user);
	memset (session, 0, sizeof (Session));
	g_free (session);
}

static gboolean
check_key (GKeyFile *keyfile, const char *group, const char *key, GError **error)
{
	if (g_key_file_has_key (keyfile, group, key, error))
		return TRUE;

	if (!error) {
		g_set_error (error,
		             NM_SESSION_MONITOR_ERROR,
		             NM_SESSION_MONITOR_ERROR_MALFORMED_DATABASE,
		             "ConsoleKit database " CKDB_PATH " group '%s' had no '%s' key",
		             group, key);
	}
	return FALSE;
}

static Session *
session_new (GKeyFile *keyfile, const char *group, GError **error)
{
	GError *local = NULL;
	Session *session;
	const char *uname = NULL;

	session = g_new0 (Session, 1);
	g_assert (session);

	session->uid = G_MAXUINT; /* paranoia */
	if (!check_key (keyfile, group, "uid", &local))
		goto error;
	session->uid = (uid_t) g_key_file_get_integer (keyfile, group, "uid", &local);
	if (local)
		goto error;

	if (!check_key (keyfile, group, "is_active", &local))
		goto error;
	session->active = g_key_file_get_boolean (keyfile, group, "is_active", &local);
	if (local)
		goto error;

	if (!check_key (keyfile, group, "is_local", &local))
		goto error;
	session->local = g_key_file_get_boolean (keyfile, group, "is_local", &local);
	if (local)
		goto error;

	if (!nm_session_monitor_uid_to_user (session->uid, &uname, error))
		return FALSE;
	session->user = g_strdup (uname);

	return session;

error:
	session_free (session);
	g_propagate_error (error, local);
	return NULL;
}

static void
session_merge (Session *src, Session *dest)
{
	g_return_if_fail (src != NULL);
	g_return_if_fail (dest != NULL);

	g_warn_if_fail (g_strcmp0 (src->user, dest->user) == 0);
	g_warn_if_fail (src->uid == dest->uid);

	dest->local = (dest->local || src->local);
	dest->active = (dest->active || src->active);
}

static void
free_database (NMSessionMonitor *self)
{
	if (self->database != NULL) {
		g_key_file_free (self->database);
		self->database = NULL;
	}

	g_hash_table_remove_all (self->sessions_by_uid);
	g_hash_table_remove_all (self->sessions_by_user);
}

static gboolean
reload_database (NMSessionMonitor *self, GError **error)
{
	struct stat statbuf;
	char **groups = NULL;
	gsize len = 0, i;
	Session *session;

	free_database (self);

	errno = 0;
	if (stat (CKDB_PATH, &statbuf) != 0) {
		g_set_error (error,
		             NM_SESSION_MONITOR_ERROR,
		             errno == ENOENT ? NM_SESSION_MONITOR_ERROR_NO_DATABASE : NM_SESSION_MONITOR_ERROR_IO_ERROR,
		             "Error statting file " CKDB_PATH ": %s",
		             strerror (errno));
		goto error;
	}
	self->database_mtime = statbuf.st_mtime;

	self->database = g_key_file_new ();
	if (!g_key_file_load_from_file (self->database, CKDB_PATH, G_KEY_FILE_NONE, error))
		goto error;

	groups = g_key_file_get_groups (self->database, &len);
	if (!groups) {
		g_set_error_literal (error,
		                     NM_SESSION_MONITOR_ERROR,
		                     NM_SESSION_MONITOR_ERROR_IO_ERROR,
		                     "Could not load groups from " CKDB_PATH "");
		goto error;
	}

	for (i = 0; i < len; i++) {
		Session *found;

		if (!g_str_has_prefix (groups[i], "Session "))
			continue;

		session = session_new (self->database, groups[i], error);
		if (!session)
			goto error;

		found = g_hash_table_lookup (self->sessions_by_user, (gpointer) session->user);
		if (found) {
			session_merge (session, found);
			session_free (session);
		} else {
			/* Entirely new user */
			g_hash_table_insert (self->sessions_by_user, (gpointer) session->user, session);
			g_hash_table_insert (self->sessions_by_uid, GUINT_TO_POINTER (session->uid), session);
		}
	}

	g_strfreev (groups);
	return TRUE;

error:
	if (groups)
		g_strfreev (groups);
	free_database (self);
	return FALSE;
}

static gboolean
ensure_database (NMSessionMonitor *self, GError **error)
{
	gboolean ret = FALSE;

	if (self->database != NULL) {
		struct stat statbuf;

		errno = 0;
		if (stat (CKDB_PATH, &statbuf) != 0) {
			g_set_error (error,
			             NM_SESSION_MONITOR_ERROR,
			             errno == ENOENT ? NM_SESSION_MONITOR_ERROR_NO_DATABASE : NM_SESSION_MONITOR_ERROR_IO_ERROR,
			             "Error statting file " CKDB_PATH " to check timestamp: %s",
			             strerror (errno));
			goto out;
		}

		if (statbuf.st_mtime == self->database_mtime) {
			ret = TRUE;
			goto out;
		}
	}

	ret = reload_database (self, error);

out:
	return ret;
}

static void
on_file_monitor_changed (GFileMonitor *    file_monitor,
                         GFile *           file,
                         GFile *           other_file,
                         GFileMonitorEvent event_type,
                         gpointer          user_data)
{
	NMSessionMonitor *self = NM_SESSION_MONITOR (user_data);

	/* throw away cache */
	free_database (self);

	g_signal_emit (self, signals[CHANGED], 0);
}

static gboolean
nm_session_monitor_lookup_consolekit (NMSessionMonitor *monitor, uid_t uid, gboolean active, GError **error)
{
	Session *session;

	if (!ensure_database (monitor, error))
		return FALSE;

	session = g_hash_table_lookup (monitor->sessions_by_uid, GUINT_TO_POINTER (uid));
	if (!session) {
		g_set_error (error,
		             NM_SESSION_MONITOR_ERROR,
		             NM_SESSION_MONITOR_ERROR_UNKNOWN_USER,
		             "No session found for uid %d",
		             uid);
		return FALSE;
	}

	if (active && !session->active)
		return FALSE;

	return TRUE;
}

static void
nm_session_monitor_init_consolekit (NMSessionMonitor *monitor)
{
	GError *error = NULL;
	GFile *file;

	/* Sessions-by-user is responsible for destroying the Session objects */
	monitor->sessions_by_user = g_hash_table_new_full (g_str_hash, g_str_equal,
			NULL, (GDestroyNotify) session_free);
	monitor->sessions_by_uid = g_hash_table_new (g_direct_hash, g_direct_equal);

	if (!ensure_database (monitor, &error)) {
		/* Ignore the first error if the CK database isn't found yet */
		if (g_error_matches (error,
		                     NM_SESSION_MONITOR_ERROR,
		                     NM_SESSION_MONITOR_ERROR_NO_DATABASE) == FALSE) {
			nm_log_err (LOGD_CORE, "Error loading " CKDB_PATH ": %s", error->message);
		}
		g_clear_error (&error);
	}

	file = g_file_new_for_path (CKDB_PATH);
	monitor->database_monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, &error);
	g_object_unref (file);
	if (monitor->database_monitor == NULL) {
		nm_log_err (LOGD_CORE, "Error monitoring " CKDB_PATH ": %s", error->message);
		g_clear_error (&error);
	} else {
		g_signal_connect (monitor->database_monitor,
		                  "changed",
		                  G_CALLBACK (on_file_monitor_changed),
		                  monitor);
	}
}

static void
nm_session_monitor_finalize_consolekit (NMSessionMonitor *monitor)
{
	g_object_unref (monitor->database_monitor);
	free_database (monitor);
}
#endif /* SESSION_TRACKING_CONSOLEKIT */

/********************************************************************/

static gboolean
nm_session_monitor_lookup (NMSessionMonitor *monitor, uid_t uid, gboolean active, GError **error)
{
#ifdef SESSION_TRACKING_SYSTEMD
	if (monitor->sd_source)
		return nm_session_monitor_lookup_systemd (uid, active, error);
#endif

#ifdef SESSION_TRACKING_CONSOLEKIT
	return nm_session_monitor_lookup_consolekit (monitor, uid, active, error);
#endif

#ifdef SESSION_TRACKING_FAKE
	return TRUE;
#endif

	return FALSE;
}

/**
 * nm_session_monitor_user_has_session:
 * @monitor: A #NMSessionMonitor.
 * @username: A username.
 * @error: Return location for error.
 *
 * Checks whether the given @username is logged into a session or not.
 *
 * Returns: %FALSE if @error is set otherwise %TRUE if the given @username is
 * currently logged into a session.
 */
gboolean
nm_session_monitor_user_has_session (NMSessionMonitor *monitor,
                                     const char *username,
                                     uid_t *out_uid,
                                     GError **error)
{
	uid_t uid;

	if (!nm_session_monitor_user_to_uid (username, &uid, error))
		return FALSE;

	if (out_uid)
		*out_uid = uid;

	return nm_session_monitor_lookup (monitor, uid, FALSE, error);
}

/**
 * nm_session_monitor_uid_has_session:
 * @monitor: A #NMSessionMonitor.
 * @uid: A user ID.
 * @error: Return location for error.
 *
 * Checks whether the given @uid is logged into a session or not.
 *
 * Returns: %FALSE if @error is set otherwise %TRUE if the given @uid is
 * currently logged into a session.
 */
gboolean
nm_session_monitor_uid_has_session (NMSessionMonitor *monitor,
                                    uid_t uid,
                                    const char **out_user,
                                    GError **error)
{
	if (out_user && !nm_session_monitor_uid_to_user (uid, out_user, error))
		return FALSE;

	return nm_session_monitor_lookup (monitor, uid, FALSE, error);
}

/**
 * nm_session_monitor_user_active:
 * @monitor: A #NMSessionMonitor.
 * @username: A username.
 * @error: Return location for error.
 *
 * Checks whether the given @username is logged into a active session or not.
 *
 * Returns: %FALSE if @error is set otherwise %TRUE if the given @username is
 * logged into an active session.
 */
gboolean
nm_session_monitor_user_active (NMSessionMonitor *monitor,
                                const char *username,
                                GError **error)
{
	uid_t uid;

	if (!nm_session_monitor_user_to_uid (username, &uid, error))
		return FALSE;

	return nm_session_monitor_lookup (monitor, uid, TRUE, error);
}

/**
 * nm_session_monitor_uid_active:
 * @monitor: A #NMSessionMonitor.
 * @uid: A user ID.
 * @error: Return location for error.
 *
 * Checks whether the given @uid is logged into a active session or not.
 *
 * Returns: %FALSE if @error is set otherwise %TRUE if the given @uid is
 * logged into an active session.
 */
gboolean
nm_session_monitor_uid_active (NMSessionMonitor *monitor,
                               uid_t uid,
                               GError **error)
{
	return nm_session_monitor_lookup (monitor, uid, TRUE, error);
}

/********************************************************************/

NMSessionMonitor *
nm_session_monitor_get (void)
{
	static NMSessionMonitor *singleton = NULL;

	if (!singleton)
		singleton = NM_SESSION_MONITOR (g_object_new (NM_TYPE_SESSION_MONITOR, NULL));
	g_assert (singleton);

	return singleton;
}

static void
nm_session_monitor_init (NMSessionMonitor *monitor)
{
#ifdef SESSION_TRACKING_SYSTEMD
	nm_session_monitor_init_systemd (monitor);
#endif

#ifdef SESSION_TRACKING_CONSOLEKIT
	nm_session_monitor_init_consolekit (monitor);
#endif
}

static void
nm_session_monitor_finalize (GObject *object)
{
#ifdef SESSION_TRACKING_SYSTEMD
	nm_session_monitor_finalize_systemd (NM_SESSION_MONITOR (object));
#endif

#ifdef SESSION_TRACKING_CONSOLEKIT
	nm_session_monitor_finalize_consolekit (NM_SESSION_MONITOR (object));
#endif

	if (G_OBJECT_CLASS (nm_session_monitor_parent_class)->finalize != NULL)
		G_OBJECT_CLASS (nm_session_monitor_parent_class)->finalize (object);
}

static void
nm_session_monitor_class_init (NMSessionMonitorClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->finalize = nm_session_monitor_finalize;

	/**
	 * NMSessionMonitor::changed:
	 * @monitor: A #NMSessionMonitor
	 *
	 * Emitted when something changes.
	 */
	signals[CHANGED] = g_signal_new (NM_SESSION_MONITOR_CHANGED,
	                                        NM_TYPE_SESSION_MONITOR,
	                                        G_SIGNAL_RUN_LAST,
	                                        G_STRUCT_OFFSET (NMSessionMonitorClass, changed),
	                                        NULL,                   /* accumulator      */
	                                        NULL,                   /* accumulator data */
	                                        g_cclosure_marshal_VOID__VOID,
	                                        G_TYPE_NONE,
	                                        0);
}
