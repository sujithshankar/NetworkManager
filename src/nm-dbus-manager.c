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
 * Copyright (C) 2006 - 2013 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "config.h"
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include "nm-dbus-interface.h"
#include "nm-dbus-manager.h"
#include "nm-dbus-utils.h"
#include "nm-glib-compat.h"
#include "nm-properties-changed-signal.h"

#include <string.h>
#include "nm-logging.h"

#define PRIV_SOCK_PATH NMRUNDIR "/private"
#define PRIV_SOCK_TAG  "private"

enum {
	DBUS_CONNECTION_CHANGED = 0,
	NAME_OWNER_CHANGED,
	PRIVATE_CONNECTION_NEW,
	PRIVATE_CONNECTION_DISCONNECTED,
	NUMBER_OF_SIGNALS
};

static guint signals[NUMBER_OF_SIGNALS];

G_DEFINE_TYPE(NMDBusManager, nm_dbus_manager, G_TYPE_OBJECT)

#define NM_DBUS_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                        NM_TYPE_DBUS_MANAGER, \
                                        NMDBusManagerPrivate))

typedef struct _PrivateServer PrivateServer;

typedef struct {
	GDBusConnection *connection;
	GHashTable *exported;
	gboolean started;

	GSList *private_servers;
	PrivateServer *priv_server;

	GDBusProxy *proxy;
	guint proxy_destroy_id;

	guint reconnect_id;
} NMDBusManagerPrivate;

static gboolean nm_dbus_manager_init_bus (NMDBusManager *self);
static void nm_dbus_manager_cleanup (NMDBusManager *self, gboolean dispose);
static void start_reconnection_timeout (NMDBusManager *self);
static void object_destroyed (NMDBusManager *self, gpointer object);

NMDBusManager *
nm_dbus_manager_get (void)
{
	static NMDBusManager *singleton = NULL;
	static gsize once = 0;

	if (g_once_init_enter (&once)) {
		singleton = (NMDBusManager *) g_object_new (NM_TYPE_DBUS_MANAGER, NULL);
		g_assert (singleton);
		if (!nm_dbus_manager_init_bus (singleton))
			start_reconnection_timeout (singleton);
		g_once_init_leave (&once, 1);
	}
	return singleton;
}

/**************************************************************/

struct _PrivateServer {
	char *tag;
	GQuark detail;
	char *address;
	GDBusServer *server;
	GHashTable *connections;
	NMDBusManager *manager;
};

static GDBusMessage *
private_server_message_filter (GDBusConnection *conn,
                               GDBusMessage *message,
                               gboolean incoming,
                               gpointer data)
{
	PrivateServer *s = data;

	if (   incoming
	    && (g_dbus_message_get_message_type (message) == G_DBUS_MESSAGE_TYPE_SIGNAL)
	    && !strcmp (g_dbus_message_get_interface (message), DBUS_INTERFACE_LOCAL)
	    && !strcmp (g_dbus_message_get_member (message), "Disconnected")) {
		/* Clean up after the connection */
		nm_log_dbg (LOGD_CORE, "(%s) closed connection %p on private socket.",
		            s->tag, conn);

		/* Emit this for the manager */
		g_signal_emit (s->manager,
		               signals[PRIVATE_CONNECTION_DISCONNECTED],
		               s->detail,
		               conn);

		g_hash_table_remove (s->connections, conn);
	}

	return message;
}

static gboolean
private_server_new_connection (GDBusServer *server,
                               GDBusConnection *conn,
                               gpointer user_data)
{
	PrivateServer *s = user_data;
	static guint32 counter = 0;
	char *sender;

	g_dbus_connection_add_filter (conn, private_server_message_filter, s, NULL);

	/* Fake a sender since private connections don't have one */
	sender = g_strdup_printf ("x:y:%d", counter++);
	g_hash_table_insert (s->connections, dbus_connection_ref (conn), sender);

	nm_log_dbg (LOGD_CORE, "(%s) accepted connection %p on private socket.", s->tag, conn);

	/* Emit this for the manager */
	g_signal_emit (s->manager,
	               signals[PRIVATE_CONNECTION_NEW],
	               s->detail,
	               conn);
}

static void
private_server_dbus_connection_destroy (DBusConnection *conn)
{
	if (dbus_connection_get_is_connected (conn))
		dbus_connection_close (conn);
	dbus_connection_unref (conn);
}

static gboolean
private_server_authorize (GDBusAuthObserver *observer,
                          GIOStream         *stream,
                          GCredentials      *credentials,
                          gpointer           user_data)
{
	return g_credentials_get_unix_uid (credentials) == 0;
}

static PrivateServer *
private_server_new (const char *path,
                    const char *tag,
                    NMDBusManager *manager)
{
	PrivateServer *s;
	GDBusAuthObserver *auth_observer;
	GDBusServer *server;
	GError *error = NULL;
	char *address, *guid;

	unlink (path);
	address = g_strdup_printf ("unix:path=%s", path);

	nm_log_dbg (LOGD_CORE, "(%s) creating private socket %s.", tag, address);

	guid = g_dbus_generate_guid ();
	auth_observer = g_dbus_auth_observer_new ();
	g_signal_connection (auth_observer, "authorize-authenticated-peer",
	                     private_server_authorize, NULL);
	server = g_dbus_server_new_sync (address,
	                                 G_DBUS_SERVER_FLAGS_NONE,
	                                 guid,
	                                 auth_observer,
	                                 NULL, &error);
	g_free (guid);
	g_object_unref (auth_observer);

	if (!server) {
		nm_log_warn (LOGD_CORE, "(%s) failed to set up private socket %s: %s",
		             tag, address, error->message);
		g_error_free (error);
		return NULL;
	}

	s = g_malloc0 (sizeof (*s));
	s->address = address;
	s->server = server;
	g_signal_connect (server, "new-connection",
	                  G_CALLBACK (private_server_new_connection), s);

	s->connections = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                        (GDestroyNotify) private_server_dbus_connection_destroy,
	                                        g_free);
	s->manager = manager;
	s->tag = g_strdup (tag);
	s->detail = g_quark_from_string (s->tag);

	g_dbus_server_start (server);

	return s;
}

static void
private_server_free (gpointer ptr)
{
	PrivateServer *s = ptr;

	unlink (s->address);
	g_free (s->address);
	g_free (s->tag);
	g_hash_table_destroy (s->connections);

	g_dbus_server-stop (s->server);
	g_object_unref (s->server);

	memset (s, 0, sizeof (*s));
	g_free (s);
}

void
nm_dbus_manager_private_server_register (NMDBusManager *self,
                                         const char *path,
                                         const char *tag)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	PrivateServer *s;
	GSList *iter;

	g_return_if_fail (self != NULL);
	g_return_if_fail (path != NULL);
	g_return_if_fail (tag != NULL);

	/* Only one instance per tag; but don't warn */
	for (iter = priv->private_servers; iter; iter = g_slist_next (iter)) {
		s = iter->data;
		if (g_strcmp0 (tag, s->tag) == 0)
			return;
	}

	s = private_server_new (path, tag, self);
	if (s)
		priv->private_servers = g_slist_append (priv->private_servers, s);
}

static const char *
private_server_get_connection_owner (PrivateServer *s, GDBusConnection *connection)
{
	g_return_val_if_fail (s != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);

	return g_hash_table_lookup (s->connections, connection)
}

/**************************************************************/

static gboolean
_bus_get_unix_pid (NMDBusManager *self,
                   const char *sender,
                   gulong *out_pid,
                   GError **error)
{
	guint32 unix_pid = G_MAXUINT32;
	GVariant *ret;

	ret = g_dbus_proxy_call_sync (NM_DBUS_MANAGER_GET_PRIVATE (self)->proxy,
	                              "GetConnectionUnixProcessID",
	                              g_variant_new ("(s)", sender),
	                              G_DBUS_CALL_FLAGS_NONE, 2000,
	                              NULL, error);
	if (!ret)
		return FALSE;

	g_return_val_if_fail (g_variant_is_of_type (ret, G_VARIANT_TYPE ("(u)")), FALSE);
	g_variant_get (ret, "(u)", &unix_pid);

	*out_pid = (gulong) unix_pid;
	return TRUE;
}

static gboolean
_bus_get_unix_user (NMDBusManager *self,
                    const char *sender,
                    gulong *out_user,
                    GError **error)
{
	guint32 unix_uid = G_MAXUINT32;
	GVariant *ret;

	ret = g_dbus_proxy_call_sync (NM_DBUS_MANAGER_GET_PRIVATE (self)->proxy,
	                              "GetConnectionUnixUser",
	                              g_variant_new ("(s)", sender),
	                              G_DBUS_CALL_FLAGS_NONE, 2000,
	                              NULL, error);
	if (!ret)
		return FALSE;

	g_return_val_if_fail (g_variant_is_of_type (ret, G_VARIANT_TYPE ("(u)")), FALSE);
	g_variant_get (ret, "(u)", &unix_uid);

	*out_user = (gulong) unix_uid;
	return TRUE;
}

/**
 * _get_caller_info_from_context():
 *
 * Given a GDBus method invocation, or a GDBusConnection + GDBusMessage,
 * return the sender and the UID of the sender.
 */
static gboolean
_get_caller_info (NMDBusManager *self,
                  GDBusMethodInvocation *context,
                  GDBusConnection *connection,
                  GDBusMessage *message,
                  char **out_sender,
                  gulong *out_uid,
                  gulong *out_pid)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	const char *sender;
	DBusError error;
	GSList *iter;

	if (context) {
		connection = g_dbus_method_invocation_get_connection (context);

		/* only bus connections will have a sender */
		sender = g_dbus_method_invocation_get_sender (context);
	} else {
		g_assert (message);
		sender = g_dbus_message_get_sender (message);
	}
	g_assert (connection);

	if (!sender) {
		/* Might be a private connection, for which we fake a sender */
		for (iter = priv->private_servers; iter; iter = g_slist_next (iter)) {
			PrivateServer *s = iter->data;

			sender = g_hash_table_lookup (s->connections, connection);
			if (sender) {
				if (out_uid)
					*out_uid = 0;
				if (out_sender)
					*out_sender = g_strdup (sender);
				if (out_pid) {
					GCredentials *creds;

					creds = g_dbus_connection_get_credentials (connection);
					if (creds)
						*out_pid = g_credentials_get_unix_pid (creds);
					else
						*out_pid = G_MAXULONG;
				}
				return TRUE;
			}
		}
		return FALSE;
	}

	/* Bus connections always have a sender */
	g_assert (sender);
	if (out_uid) {
		if (!_bus_get_unix_user (self, sender, out_user, NULL)) {
			*out_user = G_MAXULONG;
			g_free (sender);
			return FALSE;
		}
	}

	if (out_pid) {
		if (!_bus_get_unix_pid (self, sender, out_pid, NULL)) {
			*out_pid = G_MAXULONG;
			g_free (sender);
			return FALSE;
		}
	}

	if (out_sender)
		*out_sender = g_strdup (sender);

	g_free (sender);
	return TRUE;
}

gboolean
nm_dbus_manager_get_caller_info (NMDBusManager *self,
                                 GDBusMethodInvocation *context,
                                 char **out_sender,
                                 gulong *out_uid,
                                 gulong *out_pid)
{
	return _get_caller_info (self, context, NULL, NULL, out_sender, out_uid, out_pid);
}

gboolean
nm_dbus_manager_get_caller_info_from_message (NMDBusManager *self,
                                              GDBusConnection *connection,
                                              GDBusMessage *message,
                                              char **out_sender,
                                              gulong *out_uid,
                                              gulong *out_pid)
{
	return _get_caller_info (self, NULL, connection, message, out_sender, out_uid, out_pid);
}

gboolean
nm_dbus_manager_get_unix_user (NMDBusManager *self,
                               const char *sender,
                               gulong *out_uid)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	GSList *iter;
	GError *error = NULL;

	g_return_val_if_fail (sender != NULL, FALSE);
	g_return_val_if_fail (out_uid != NULL, FALSE);

	/* Check if it's a private connection sender, which we fake */
	for (iter = priv->private_servers; iter; iter = g_slist_next (iter)) {
		PrivateServer *s = iter->data;
		GHashTableIter hiter;
		const char *priv_sender;

		g_hash_table_iter_init (&hiter, s->connections);
		while (g_hash_table_iter_next (&hiter, NULL, (gpointer) &priv_sender)) {
			if (g_strcmp0 (sender, priv_sender) == 0) {
				*out_uid = 0;
				return TRUE;
			}
		}
	}

	/* Otherwise, a bus connection */
	dbus_error_init (&error);
	if (!_bus_get_unix_user (self, sender, out_uid, &error)) {
		nm_log_warn (LOGD_CORE, "Failed to get unix user for dbus sender '%s': %s",
		             sender, error->message);
		g_error_free (error);
		return FALSE;
	}

	return TRUE;
}

/**************************************************************/

static void
private_connection_new (NMDBusManager *self, GDBusConnection *connection)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	GDBusInterfaceSkeleton *interface;
	const char *path;
	GError *error = NULL;

	/* Register all exported objects on this private connection */
	g_hash_table_iter_init (&iter, priv->exported);
	while (g_hash_table_iter_next (&iter, (gpointer) &interface, (gpointer) &path)) {
		if (g_dbus_interface_skeleton_export (interface, connection, path, &error)) {
			nm_log_dbg (LOGD_CORE, "(%s) registered %p (%s) at '%s' on private socket.",
			            PRIV_SOCK_TAG, object, G_OBJECT_TYPE_NAME (object), path);
		} else {
			nm_log_warn (LOGD_CORE, "(%s) could not register %p (%s) at '%s' on private socket: %s.",
			             PRIV_SOCK_TAG, object, G_OBJECT_TYPE_NAME (object), path,
			             error->message);
			g_clear_error (&error);
		}
	}
}

static void
private_connection_disconnected (NMDBusManager *self, DBusGConnection *connection)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	const char *owner;

	owner = private_server_get_connection_owner (priv->priv_server, connection);
	g_assert (owner);

	/* Fake a NameOwnerChanged to let listerners know this owner has quit */
	g_signal_emit (G_OBJECT (self), signals[NAME_OWNER_CHANGED],
	               0, owner, owner, NULL);
}

static void
private_server_setup (NMDBusManager *self)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	/* Skip this step if this is just a test program */
	if (g_test_initialized ())
		return;

	/* Set up our main private DBus socket */
	if (mkdir (NMRUNDIR, 0700) == -1) {
		if (errno != EEXIST)
			nm_log_warn (LOGD_CORE, "Error creating directory \"%s\": %d (%s)", NMRUNDIR, errno, g_strerror (errno));
	}
	priv->priv_server = private_server_new (PRIV_SOCK_PATH, PRIV_SOCK_TAG, self);
	if (priv->priv_server) {
		priv->private_servers = g_slist_append (priv->private_servers, priv->priv_server);

		g_signal_connect (self,
		                  NM_DBUS_MANAGER_PRIVATE_CONNECTION_NEW "::" PRIV_SOCK_TAG,
		                  (GCallback) private_connection_new,
		                  NULL);
		g_signal_connect (self,
		                  NM_DBUS_MANAGER_PRIVATE_CONNECTION_DISCONNECTED "::" PRIV_SOCK_TAG,
		                  (GCallback) private_connection_disconnected,
		                  NULL);
	}
}

static void
nm_dbus_manager_init (NMDBusManager *self)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	priv->exported = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_free);

	private_server_setup (self);
}

static void
nm_dbus_manager_dispose (GObject *object)
{
	NMDBusManager *self = NM_DBUS_MANAGER (object);
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	GObject *exported;

	if (priv->exported) {
		g_hash_table_iter_init (&iter, priv->exported);
		while (g_hash_table_iter_next (&iter, (gpointer) &exported, NULL))
			g_object_weak_unref (exported, (GWeakNotify) object_destroyed, self);

		g_hash_table_destroy (priv->exported);
		priv->exported = NULL;
	}

	g_slist_free_full (priv->private_servers, private_server_free);
	priv->private_servers = NULL;
	priv->priv_server = NULL;

	nm_dbus_manager_cleanup (self, TRUE);

	if (priv->reconnect_id) {
		g_source_remove (priv->reconnect_id);
		priv->reconnect_id = 0;
	}

	G_OBJECT_CLASS (nm_dbus_manager_parent_class)->dispose (object);
}

static void
nm_dbus_manager_class_init (NMDBusManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDBusManagerPrivate));

	object_class->dispose = nm_dbus_manager_dispose;

	signals[DBUS_CONNECTION_CHANGED] =
		g_signal_new (NM_DBUS_MANAGER_DBUS_CONNECTION_CHANGED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMDBusManagerClass, dbus_connection_changed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);

	signals[NAME_OWNER_CHANGED] =
		g_signal_new (NM_DBUS_MANAGER_NAME_OWNER_CHANGED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMDBusManagerClass, name_owner_changed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

	signals[PRIVATE_CONNECTION_NEW] =
		g_signal_new (NM_DBUS_MANAGER_PRIVATE_CONNECTION_NEW,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
		              G_STRUCT_OFFSET (NMDBusManagerClass, private_connection_new),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);

	signals[PRIVATE_CONNECTION_DISCONNECTED] =
		g_signal_new (NM_DBUS_MANAGER_PRIVATE_CONNECTION_DISCONNECTED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
		              G_STRUCT_OFFSET (NMDBusManagerClass, private_connection_disconnected),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);
}


/* Only cleanup a specific dbus connection, not all our private data */
static void
nm_dbus_manager_cleanup (NMDBusManager *self, gboolean dispose)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	if (priv->proxy) {
		if (dispose) {
			g_signal_handler_disconnect (priv->proxy, priv->proxy_destroy_id);
			priv->proxy_destroy_id = 0;
		}
		g_object_unref (priv->proxy);
		priv->proxy = NULL;
	}

	g_clear_pointer (&priv->connection);

	priv->started = FALSE;
}

static gboolean
nm_dbus_manager_reconnect (gpointer user_data)
{
	NMDBusManager *self = NM_DBUS_MANAGER (user_data);
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	g_assert (self != NULL);

	if (nm_dbus_manager_init_bus (self)) {
		if (nm_dbus_manager_start_service (self)) {
			nm_log_info (LOGD_CORE, "reconnected to the system bus.");
			g_signal_emit (self, signals[DBUS_CONNECTION_CHANGED],
			               0, priv->connection);
			priv->reconnect_id = 0;
			return FALSE;
		}
	}

	/* Try again */
	nm_dbus_manager_cleanup (self, FALSE);
	return TRUE;
}

static void
start_reconnection_timeout (NMDBusManager *self)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	if (priv->reconnect_id)
		g_source_remove (priv->reconnect_id);

	/* Schedule timeout for reconnection attempts */
	priv->reconnect_id = g_timeout_add_seconds (3, nm_dbus_manager_reconnect, self);
}

char *
nm_dbus_manager_get_name_owner (NMDBusManager *self,
                                const char *name,
                                GError **error)
{
	GVariant *ret;
	char *owner = NULL;

	g_return_val_if_fail (NM_IS_DBUS_MANAGER (self), NULL);
	g_return_val_if_fail (name != NULL, NULL);
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	if (!NM_DBUS_MANAGER_GET_PRIVATE (self)->proxy)
		return NULL;

	ret = g_dbus_proxy_call_sync (NM_DBUS_MANAGER_GET_PRIVATE (self)->proxy,
	                              "GetNameOwner",
	                              g_variant_new ("(s)", name),
	                              G_DBUS_CALL_FLAGS_NONE, 2000,
	                              NULL, error);
	if (!ret)
		return NULL;

	g_return_val_if_fail (g_variant_is_of_type (ret, G_VARIANT_TYPE ("(s)")));
	g_variant_get (ret, "(s)", &owner);
	g_variant_unref (ret);

	return owner;
}

gboolean
nm_dbus_manager_name_has_owner (NMDBusManager *self,
                                const char *name)
{
	gboolean has_owner = FALSE;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_DBUS_MANAGER (self), FALSE);
	g_return_val_if_fail (name != NULL, FALSE);

	if (!NM_DBUS_MANAGER_GET_PRIVATE (self)->connection)
		return FALSE;

	if (!_nm_dbus_check_has_name_owner_sync (NM_DBUS_MANAGER_GET_PRIVATE (self)->connection,
	                                         name,
	                                         &has_owner,
	                                         NULL,
	                                         &err)) {
		nm_log_warn (LOGD_CORE, "NameHasOwner request failed: %s",
		             (err && err->message) ? err->message : "(unknown)");
		g_clear_error (&err);
	}

	return has_owner;
}

static void
proxy_dbus_signal (GDBusProxy  *proxy,
                   const gchar *sender_name,
                   const gchar *signal_name,
                   GVariant    *parameters,
                   gpointer     user_data)
{
	const char *name, *old_owner, *new_owner;

	if (   strcmp (signal_name, "NameOwnerChanged") != 0
	    || !g_variant_is_of_type (parameters, "(sss)"))
		return;

	g_variant_get (parameters, "(&s&s&s)", &name, &old_owner, &new_owner);
	g_signal_emit (G_OBJECT (user_data), signals[NAME_OWNER_CHANGED],
	               0, name, old_owner, new_owner);
}

#if FIXME
static void
destroy_cb (DBusGProxy *proxy, gpointer user_data)
{
	NMDBusManager *self = NM_DBUS_MANAGER (user_data);

	/* Clean up existing connection */
	nm_log_warn (LOGD_CORE, "disconnected by the system bus.");
	NM_DBUS_MANAGER_GET_PRIVATE (self)->proxy = NULL;

	nm_dbus_manager_cleanup (self, FALSE);

	g_signal_emit (G_OBJECT (self), signals[DBUS_CONNECTION_CHANGED], 0, NULL);

	start_reconnection_timeout (self);
}
#endif

static gboolean
nm_dbus_manager_init_bus (NMDBusManager *self)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;

	if (priv->connection) {
		nm_log_warn (LOGD_CORE, "DBus Manager already has a valid connection.");
		return FALSE;
	}

	priv->connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
	if (!priv->g_connection) {
		/* Log with 'info' severity; there won't be a bus daemon in minimal
		 * environments (eg, initrd) where we only want to use the private
		 * socket.
		 */
		nm_log_info (LOGD_CORE, "Could not connect to the system bus (%s); only the "
		             "private D-Bus socket will be available.",
		             error->message);
		g_error_free (error);
		return FALSE;
	}

	priv->proxy = g_dbus_proxy_new_sync (priv->connection,
	                                     G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                                         G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
	                                     NULL,
	                                     "org.freedesktop.DBus",
	                                     "/org/freedesktop/DBus",
	                                     "org.freedesktop.DBus",
	                                     NULL, &error);
	if (!priv->proxy) {
		g_clear_object (&priv->connection);
		nm_log_warn (LOGD_CORE, "Could not create org.freedesktop.DBus proxy (%s); only the "
		             "private D-Bus socket will be available.",
		             error->message);
		g_error_free (error);
		return FALSE;
	}

#if FIXME
	priv->proxy_destroy_id = g_signal_connect (priv->proxy, "destroy",
	                                           G_CALLBACK (destroy_cb), self);
#endif

	g_signal_connect (priv->proxy, "g-signal",
	                  G_CALLBACK (proxy_dbus_signal), self);
	return TRUE;
}

/* Register our service on the bus; shouldn't be called until
 * all necessary message handlers have been registered, because
 * when we register on the bus, clients may start to call.
 */
gboolean
nm_dbus_manager_start_service (NMDBusManager *self)
{
	NMDBusManagerPrivate *priv;
	GVariant *ret;
	int result;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_DBUS_MANAGER (self), FALSE);

	priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	if (priv->started) {
		nm_log_err (LOGD_CORE, "Service has already started.");
		return FALSE;
	}

	/* Pointless to request a name when we aren't connected to the bus */
	if (!priv->proxy)
		return FALSE;

	ret = g_dbus_proxy_call_sync (priv->proxy,
	                              "RequestName",
	                              g_variant_new ("(su)",
	                                             NM_DBUS_SERVICE,
	                                             0x4 /* DBUS_NAME_FLAG_DO_NOT_QUEUE */),
	                              G_DBUS_CALL_FLAGS_NONE, -1,
	                              NULL, &err);
	if (!ret) {
		nm_log_err (LOGD_CORE, "Could not acquire the NetworkManager service.\n"
		            "  Error: '%s'", err->message);
		g_error_free (err);
		return FALSE;
	}

	g_return_val_if_fail (g_variant_is_of_type (ret, "(u)"), FALSE);
	g_variant_get (ret, "(u)", &result);

	if (result != 1 /* DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER */) {
		nm_log_err (LOGD_CORE, "Could not acquire the NetworkManager service as it is already taken.");
		return FALSE;
	}

	priv->started = TRUE;
	return priv->started;
}

GDBusConnection *
nm_dbus_manager_get_connection (NMDBusManager *self)
{
	g_return_val_if_fail (NM_IS_DBUS_MANAGER (self), NULL);

	return NM_DBUS_MANAGER_GET_PRIVATE (self)->connection;
}

static void
object_destroyed (NMDBusManager *self, gpointer object)
{
	g_hash_table_remove (NM_DBUS_MANAGER_GET_PRIVATE (self)->exported, object);
}

void
nm_dbus_manager_register_object (NMDBusManager *self,
                                 const char *path,
                                 gpointer interface)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	GDBusConnection *connection;

	g_assert (G_IS_DBUS_INTERFACE_SKELETON (object));

	g_warn_if_fail (g_hash_table_lookup (priv->exported, object) == NULL);
	g_hash_table_insert (priv->exported, object, g_strdup (path));

	if (priv->connection) {
		g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (object),
		                                  priv->connection, path, NULL);
	}

	if (priv->priv_server) {
		g_hash_table_iter_init (&iter, priv->priv_server->connections);
		while (g_hash_table_iter_next (&iter, (gpointer) &connection, NULL)) {
			g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (object),
			                                  connection, path, NULL);
		}
	}

	g_object_weak_ref (G_OBJECT (object), (GWeakNotify) object_destroyed, self);
}

void
nm_dbus_manager_unregister_object (NMDBusManager *self, gpointer object)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	g_assert (G_IS_DBUS_INTERFACE_SKELETON (object));

	g_hash_table_remove (NM_DBUS_MANAGER_GET_PRIVATE (self)->exported, object);
	g_object_weak_unref (G_OBJECT (object), (GWeakNotify) object_destroyed, self);

	g_dbus_interface_skeleton_unexport (G_DBUS_INTERFACE_SKELETON (object));
}

/**
 * nm_dbus_manager_new_proxy:
 * @self: the #NMDBusManager
 * @context: the method call context this proxy should be created
 * @name: any name on the message bus
 * @path: name of the object instance to call methods on
 * @iface: name of the interface to call methods on
 *
 * Creates a new proxy for a name on a given bus.  Since the process which
 * called the D-Bus method could be coming from a private connection or the
 * system bus connection, different proxies must be created for each case.  This
 * function abstracts that.
 *
 * Returns: a #GDBusProxy capable of calling D-Bus methods of the calling process
 */
GDBusProxy *
nm_dbus_manager_new_proxy (NMDBusManager *self,
                           GDBusMethodInvocation *context,
                           const char *name,
                           const char *path,
                           const char *iface)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	GDBusConnection *connection;
	GSList *iter;
	const char *owner;
	GDBusProxy *proxy;

	connection = g_dbus_method_invocation_get_connection (context);
	g_assert (connection);

	/* Might be a private connection, for which @name is fake */
	for (iter = priv->private_servers; iter; iter = g_slist_next (iter)) {
		PrivateServer *s = iter->data;

		owner = private_server_get_connection_owner (s, connection);
		if (owner) {
			g_assert_cmpstr (owner, ==, name);
			name = NULL;
			break;
		}
	}

	proxy = g_dbus_proxy_new_sync (connection,
	                               G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                                   G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
	                               NULL,
	                               name, path, interface,
	                               NULL, &error);
	if (!proxy) {
		nm_log_warn (LOGD_CORE, "Could not create proxy for %s on connection %s: %s",
		             interface, name, error->message);
		g_error_free (error);
	}
	return proxy;
}
