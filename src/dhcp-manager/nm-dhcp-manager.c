/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-dhcp-manager.c - Handle the DHCP daemon for NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2005 - 2013 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 *
 */

#include "config.h"
#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "nm-dhcp-manager.h"
#include "nm-dhcp-dhclient.h"
#include "nm-dhcp-dhcpcd.h"
#include "nm-logging.h"
#include "nm-dbus-manager.h"
#include "nm-hostname-provider.h"
#include "nm-config.h"
#include "nm-dbus-glib-types.h"
#include "nm-glib-compat.h"
#include "NetworkManagerUtils.h"

GQuark
nm_dhcp_manager_error_quark (void)
{
    static GQuark ret = 0;

    if (ret == 0)
        ret = g_quark_from_static_string ("nm_dhcp_manager_error");

    return ret;
}

#define NM_DHCP_CLIENT_DBUS_IFACE   "org.freedesktop.nm_dhcp_client"

#define DHCP_TIMEOUT 45 /* default DHCP timeout, in seconds */

#define PRIV_SOCK_PATH NMRUNDIR "/private-dhcp"
#define PRIV_SOCK_TAG  "dhcp"

static NMDHCPManager *singleton = NULL;

/* default to installed helper, but can be modified for testing */
const char *nm_dhcp_helper_path = LIBEXECDIR "/nm-dhcp-helper";

typedef GSList * (*GetLeaseConfigFunc) (const char *iface, const char *uuid, gboolean ipv6);

typedef struct {
	GType               client_type;
	GetLeaseConfigFunc  get_lease_ip_configs_func;

	NMDBusManager *     dbus_mgr;
	guint               new_conn_id;
	guint               dis_conn_id;
	GHashTable *        proxies;

	GHashTable *        clients;
	DBusGProxy *        proxy;
	NMHostnameProvider *hostname_provider;
} NMDHCPManagerPrivate;

struct client_data {
	NMDHCPClient *client;

	/* owns_client==TRUE means we have a ref of the client, but weak ref.
	 * Otherwise, we don't own a reference, but have a weak ref registered
	 * to get notification about removal. */
	gboolean owns_client;

	gboolean started;
	guint instance_counter;
	gboolean ipv6;
	char *iface;
	gulong timeout_id;
	gulong remove_id;

	/* cache parameters to start the client, if we queue/delate the start
	 * due to concurrent clients.*/
	char *dhcp_client_id;
	GByteArray *dhcp_anycast_addr;
	char *hostname;
	gboolean info_only;
};

#define NM_DHCP_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP_MANAGER, NMDHCPManagerPrivate))

G_DEFINE_TYPE (NMDHCPManager, nm_dhcp_manager, G_TYPE_OBJECT)


static void remove_client (NMDHCPManager *self, NMDHCPClient *client, gboolean force);


static char *
garray_to_string (GArray *array, const char *key)
{
	GString *str;
	int i;
	unsigned char c;
	char *converted = NULL;

	g_return_val_if_fail (array != NULL, NULL);

	/* Since the DHCP options come through environment variables, they should
	 * already be UTF-8 safe, but just make sure.
	 */
	str = g_string_sized_new (array->len);
	for (i = 0; i < array->len; i++) {
		c = array->data[i];

		/* Convert NULLs to spaces and non-ASCII characters to ? */
		if (c == '\0')
			c = ' ';
		else if (c > 127)
			c = '?';
		str = g_string_append_c (str, c);
	}
	str = g_string_append_c (str, '\0');

	converted = str->str;
	if (!g_utf8_validate (converted, -1, NULL))
		nm_log_warn (LOGD_DHCP, "DHCP option '%s' couldn't be converted to UTF-8", key);
	g_string_free (str, FALSE);
	return converted;
}

static NMDHCPClient *
get_client_for_pid (NMDHCPManager *manager, GPid pid, const char *iface)
{
	NMDHCPManagerPrivate *priv;
	GHashTableIter iter;
	gpointer value;
	struct client_data *best = NULL;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (manager), NULL);

	g_return_val_if_fail (pid >= 0, NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	g_hash_table_iter_init (&iter, priv->clients);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		struct client_data *client_data = value;
		NMDHCPClient *candidate = NM_DHCP_CLIENT (client_data->client);

		if (!client_data->started) {
			/* not yet started clients don't even have a PID. */
			continue;
		}

		if (nm_dhcp_client_get_pid (candidate) == pid) {
			if (!nm_dhcp_client_is_reaped (candidate) && client_data->owns_client)
				return candidate;

			/* we have a dead candidate for this PID. If it has a matching @iface
			 * we accept it. */
			if (g_strcmp0 (iface, nm_dhcp_client_get_iface (candidate)) != 0)
				continue;

			/* If we have more then one candidates, choose the last recently created
			 * one. */
			if (   !best
			    || best->instance_counter < client_data->instance_counter)
				best = client_data;
		}
	}

	return best ? best->client : NULL;
}

static gboolean
dispose_old_clients (NMDHCPManager *self,
                     const char *iface,
                     gboolean ip6)
{
	NMDHCPManagerPrivate *priv;
	GHashTableIter iter;
	gpointer value;
	gboolean has_zombie_clients = FALSE;
	struct client_data *concurrent_client = NULL;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), FALSE);
	g_return_val_if_fail (iface, FALSE);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	ip6 = !!ip6;

	g_hash_table_iter_init (&iter, priv->clients);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		struct client_data *client_data = value;

		if (nm_dhcp_client_is_reaped (client_data->client)) {
			/* reaped clients are only in the list so that we are able to
			 * react on delated events. They do not block a new client. */
			continue;
		}

		if (   strcmp (iface, client_data->iface) == 0
		    && client_data->ipv6  != ip6) {
		    if (client_data->owns_client) {
				/* we expect at most one concurrent client that is still active (owned) */
				g_assert (!concurrent_client);
				concurrent_client = client_data;
			} else {
				/* we expect at most one concurrent client that is waiting to be reaped (not owned) */
				g_assert (!has_zombie_clients);
				has_zombie_clients = TRUE;
			}
		}
	}
	if (concurrent_client) {
		if (concurrent_client->started) {
			NMDHCPClient *client = concurrent_client->client;

			nm_dhcp_client_stop (client, FALSE);
			remove_client (self, client, FALSE);

			has_zombie_clients = has_zombie_clients ||
			                     !!g_hash_table_lookup (priv->clients, client);
		} else
			remove_client (self, concurrent_client->client, TRUE);
	}

	return has_zombie_clients;
}

static char *
get_option (GHashTable *hash, const char *key)
{
	GValue *value;

	value = g_hash_table_lookup (hash, key);
	if (value == NULL)
		return NULL;

	if (G_VALUE_TYPE (value) != DBUS_TYPE_G_UCHAR_ARRAY) {
		nm_log_warn (LOGD_DHCP, "unexpected key %s value type was not "
		             "DBUS_TYPE_G_UCHAR_ARRAY",
		             (char *) key);
		return NULL;
	}

	return garray_to_string ((GArray *) g_value_get_boxed (value), key);
}

static void
nm_dhcp_manager_handle_event (DBusGProxy *proxy,
                              GHashTable *options,
                              gpointer user_data)
{
	NMDHCPManager *manager = NM_DHCP_MANAGER (user_data);
	NMDHCPClient *client;
	char *iface = NULL;
	char *pid_str = NULL;
	char *reason = NULL;
	long pid;

	iface = get_option (options, "interface");
	if (iface == NULL) {
		nm_log_warn (LOGD_DHCP, "DHCP event: didn't have associated interface.");
		goto out;
	}

	pid_str = get_option (options, "pid");
	pid = nm_utils_ascii_str_to_int64 (pid_str, 10, 0, LONG_MAX, -1);
	if (pid == -1 || pid != (GPid)pid) {
		nm_log_warn (LOGD_DHCP, "DHCP event: couldn't convert PID '%s' to an integer", pid_str ? pid_str : "(null)");
		goto out;
	}

	reason = get_option (options, "reason");
	client = get_client_for_pid (manager, (GPid) pid, iface);
	if (client == NULL) {
		if (reason && g_ascii_strcasecmp (reason, "RELEASE") == 0) {
			/* This happens regularly, when the dhcp client gets killed and we receive its last message.
			 * Don't log a warning in this case. */
			nm_log_dbg (LOGD_DHCP, "(pid %ld) unhandled RELEASE DHCP event for interface %s", pid, iface);
		} else
			nm_log_warn (LOGD_DHCP, "(pid %ld) unhandled DHCP event for interface %s", pid, iface);
		goto out;
	}

	if (strcmp (iface, nm_dhcp_client_get_iface (client))) {
		nm_log_warn (LOGD_DHCP, "(pid %ld) received DHCP event from unexpected interface '%s' (expected '%s')",
		             pid, iface, nm_dhcp_client_get_iface (client));
		goto out;
	}

	if (reason == NULL) {
		nm_log_warn (LOGD_DHCP, "(pid %ld) DHCP event didn't have a reason", pid);
		goto out;
	}

	g_object_ref (client);
	nm_dhcp_client_new_options (client, options, reason);
	g_object_unref (client);

out:
	g_free (iface);
	g_free (pid_str);
	g_free (reason);
}

#if HAVE_DBUS_GLIB_100
static void
new_connection_cb (NMDBusManager *mgr,
                   DBusGConnection *connection,
                   NMDHCPManager *self)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (self);
	DBusGProxy *proxy;

	/* Create a new proxy for the client */
	proxy = dbus_g_proxy_new_for_peer (connection, "/", NM_DHCP_CLIENT_DBUS_IFACE);
	dbus_g_proxy_add_signal (proxy,
	                         "Event",
	                         DBUS_TYPE_G_MAP_OF_VARIANT,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy,
	                             "Event",
	                             G_CALLBACK (nm_dhcp_manager_handle_event),
	                             self,
	                             NULL);
	g_hash_table_insert (priv->proxies, connection, proxy);
}

static void
dis_connection_cb (NMDBusManager *mgr,
                   DBusGConnection *connection,
                   NMDHCPManager *self)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (self);
	DBusGProxy *proxy;

	proxy = g_hash_table_lookup (priv->proxies, connection);
	if (proxy) {
		dbus_g_proxy_disconnect_signal (proxy,
		                                "Event",
		                                G_CALLBACK (nm_dhcp_manager_handle_event),
		                                self);
		g_hash_table_remove (priv->proxies, connection);
	}
}
#endif

static GType
get_client_type (const char *client, GError **error)
{
	const char *dhclient_path = NULL;
	const char *dhcpcd_path = NULL;

	/* If a client was disabled at build-time, its *_PATH define will be
	 * an empty string.
	 */
	/* coverity[array_null] */
	if (DHCLIENT_PATH && strlen (DHCLIENT_PATH))
		dhclient_path = nm_dhcp_dhclient_get_path (DHCLIENT_PATH);
	/* coverity[array_null] */
	if (DHCPCD_PATH && strlen (DHCPCD_PATH))
		dhcpcd_path = nm_dhcp_dhcpcd_get_path (DHCPCD_PATH);

	if (!client) {
		if (dhclient_path)
			return NM_TYPE_DHCP_DHCLIENT;
		else if (dhcpcd_path)
			return NM_TYPE_DHCP_DHCPCD;
		else {
			g_set_error_literal (error,
			                     NM_DHCP_MANAGER_ERROR, NM_DHCP_MANAGER_ERROR_BAD_CLIENT,
			                     _("no usable DHCP client could be found."));
			return G_TYPE_INVALID;
		}
	}

	if (!strcmp (client, "dhclient")) {
		if (!dhclient_path) {
			g_set_error_literal (error,
			                     NM_DHCP_MANAGER_ERROR, NM_DHCP_MANAGER_ERROR_BAD_CLIENT,
			                     _("'dhclient' could be found."));
			return G_TYPE_INVALID;
		}
		return NM_TYPE_DHCP_DHCLIENT;
	}

	if (!strcmp (client, "dhcpcd")) {
		if (!dhcpcd_path) {
			g_set_error_literal (error,
			                     NM_DHCP_MANAGER_ERROR, NM_DHCP_MANAGER_ERROR_BAD_CLIENT,
			                     _("'dhcpcd' could be found."));
			return G_TYPE_INVALID;
		}
		return NM_TYPE_DHCP_DHCPCD;
	}

	g_set_error (error,
	             NM_DHCP_MANAGER_ERROR, NM_DHCP_MANAGER_ERROR_BAD_CLIENT,
	             _("unsupported DHCP client '%s'"), client);
	return G_TYPE_INVALID;
}

static void
client_data_free_params (struct client_data *client_data)
{
	g_clear_pointer (&client_data->dhcp_client_id, g_free);
	g_clear_pointer (&client_data->hostname, g_free);

	if (client_data->dhcp_anycast_addr) {
		g_byte_array_free (client_data->dhcp_anycast_addr, TRUE);
		client_data->dhcp_anycast_addr = NULL;
	}
}

static void
client_data_free (void *data)
{
	struct client_data *client_data = data;

	client_data_free_params (client_data);
	g_free (client_data->iface);
	g_free (data);
}

NMDHCPManager *
nm_dhcp_manager_get (void)
{
	NMDHCPManagerPrivate *priv;
	const char *client;
	GError *error = NULL;
#if !HAVE_DBUS_GLIB_100
	DBusGConnection *g_connection;
#endif

	if (singleton)
		return g_object_ref (singleton);

	singleton = g_object_new (NM_TYPE_DHCP_MANAGER, NULL);
	priv = NM_DHCP_MANAGER_GET_PRIVATE (singleton);

	/* Client-specific setup */
	client = nm_config_get_dhcp_client (nm_config_get ());
	priv->client_type = get_client_type (client, &error);

	if (priv->client_type == NM_TYPE_DHCP_DHCLIENT)
		priv->get_lease_ip_configs_func = nm_dhcp_dhclient_get_lease_ip_configs;
	else if (priv->client_type == G_TYPE_INVALID) {
		nm_log_warn (LOGD_DHCP, "No usable DHCP client found (%s)! DHCP configurations will fail.",
		             error->message);
	}
	g_clear_error (&error);

	priv->clients = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                       NULL,
	                                       client_data_free);

	priv->dbus_mgr = nm_dbus_manager_get ();

#if HAVE_DBUS_GLIB_100
	/* Register the socket our DHCP clients will return lease info on */
	nm_dbus_manager_private_server_register (priv->dbus_mgr, PRIV_SOCK_PATH, PRIV_SOCK_TAG);
	priv->new_conn_id = g_signal_connect (priv->dbus_mgr,
	                                      NM_DBUS_MANAGER_PRIVATE_CONNECTION_NEW "::" PRIV_SOCK_TAG,
	                                      (GCallback) new_connection_cb,
	                                      singleton);
	priv->dis_conn_id = g_signal_connect (priv->dbus_mgr,
	                                      NM_DBUS_MANAGER_PRIVATE_CONNECTION_DISCONNECTED "::" PRIV_SOCK_TAG,
	                                      (GCallback) dis_connection_cb,
	                                      singleton);
#else
	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	priv->proxy = dbus_g_proxy_new_for_name (g_connection,
	                                         "org.freedesktop.nm_dhcp_client",
	                                         "/",
	                                         NM_DHCP_CLIENT_DBUS_IFACE);
	g_assert (priv->proxy);
	dbus_g_proxy_add_signal (priv->proxy,
	                         "Event",
	                         DBUS_TYPE_G_MAP_OF_VARIANT,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Event",
	                             G_CALLBACK (nm_dhcp_manager_handle_event),
	                             singleton,
	                             NULL);
#endif
	return singleton;
}

static gboolean
start_client (NMDHCPManager *self,
              struct client_data *client_data,
              const char *dhcp_client_id,
              GByteArray *dhcp_anycast_addr,
              const char *hostname,
              gboolean info_only)
{
	gboolean success;
	NMDHCPClient *client = client_data->client;

	if (client_data->ipv6)
		success = nm_dhcp_client_start_ip6 (client, dhcp_anycast_addr, hostname, info_only);
	else
		success = nm_dhcp_client_start_ip4 (client, dhcp_client_id, dhcp_anycast_addr, hostname);

	if (!success) {
		nm_log_dbg (LOGD_DHCP, "DHCP manager: client %p: failed to start", client);
		remove_client (self, client, TRUE);
	} else {
		nm_log_dbg (LOGD_DHCP, "DHCP manager: client %p: started", client);
		client_data->started = TRUE;
	}

	return success;
}

static void
dispose_client_cb (gpointer data, GObject *where_the_object_was)
{
	GHashTableIter iter;
	gpointer value;
	NMDHCPManager *self = data;
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (self);
	struct client_data *client_data;
	gboolean client_started = FALSE;
	gboolean success;

	client_data = g_hash_table_lookup (priv->clients, where_the_object_was);

	g_return_if_fail (client_data);
	g_return_if_fail (!client_data->owns_client);

	nm_log_dbg (LOGD_DHCP, "DHCP manager: client %p: remove zombie", client_data->client);

	/* We are about to remove a zombie client. This might mean we have
	 * to start a queued client... look for a waiting client and start it... */
	g_hash_table_iter_init (&iter, priv->clients);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		struct client_data *client_data2 = value;

		if (   client_data2 == client_data
		    || client_data->started
		    || client_data->ipv6 != client_data2->ipv6
		    || g_strcmp0 (client_data->iface, client_data2->iface) != 0)
			continue;

		/* we only expect one client ready to be started. */
		g_assert (!client_started); (void)client_started;
		client_started = TRUE;

		success = start_client (self, client_data2,
		                        client_data2->dhcp_client_id,
		                        client_data2->dhcp_anycast_addr,
		                        client_data2->hostname,
		                        client_data2->info_only);

		if (success) {
			/* we don't need the start parameters anymore. Clear them. */
			client_data_free_params (client_data2);
		}
	}

	g_hash_table_remove (priv->clients, where_the_object_was);
}

static void
remove_client (NMDHCPManager *self, NMDHCPClient *client, gboolean force)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (self);
	struct client_data *client_data;
	gboolean owns_client;

	client_data = g_hash_table_lookup (priv->clients, client);

	g_return_if_fail (client_data);
	g_return_if_fail (client_data->client == client);

	owns_client = client_data->owns_client;
	if (owns_client) {
		g_signal_handler_disconnect (client, client_data->remove_id);
		g_signal_handler_disconnect (client, client_data->timeout_id);
		client_data->remove_id = 0;
		client_data->timeout_id = 0;
		client_data->owns_client = FALSE;
	}

	/* Stopping the client is left up to the controlling device
	 * explicitly since we may want to quit NetworkManager but not terminate
	 * the DHCP client.
	 */

	if (force) {
		if (!owns_client)
			g_object_weak_unref (G_OBJECT (client), dispose_client_cb, self);
		g_hash_table_remove (priv->clients, client);
		nm_log_dbg (LOGD_DHCP, "DHCP manager: client %p: removed", client);
		if (owns_client)
			g_object_unref (client);
	} else if (owns_client) {
		g_object_weak_ref (G_OBJECT (client), dispose_client_cb, self);
		g_object_unref (client);
		if (nm_logging_enabled (LOGL_DEBUG, LOGD_DHCP)) {
			if (g_hash_table_lookup (priv->clients, client))
				nm_log_dbg (LOGD_DHCP, "DHCP manager: client %p: removed but has zombie reference", client);
			else
				nm_log_dbg (LOGD_DHCP, "DHCP manager: client %p: removed without zombie reference", client);
		}
	}
}

static void
remove_client_cb (NMDHCPManager *self, NMDHCPClient *client)
{
	remove_client (self, client, FALSE);
}

static struct client_data *
add_client (NMDHCPManager *self, NMDHCPClient *client)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (self);
	struct client_data *client_data;
	static guint global_instance_counter = 0;

	client_data = g_new0 (struct client_data, 1);

	client_data->client = g_object_ref (client);
	client_data->owns_client = TRUE;
	client_data->remove_id = g_signal_connect_swapped (client, NM_DHCP_CLIENT_SIGNAL_REMOVE, G_CALLBACK (remove_client_cb), self);
	client_data->timeout_id = g_signal_connect_swapped (client, NM_DHCP_CLIENT_SIGNAL_TIMEOUT, G_CALLBACK (remove_client_cb), self);
	client_data->ipv6 = !!nm_dhcp_client_get_ipv6 (client);
	client_data->iface = g_strdup (nm_dhcp_client_get_iface (client));
	client_data->instance_counter = ++global_instance_counter;

	nm_log_dbg (LOGD_DHCP, "DHCP manager: client %p: add IPv%c, %s",
	            client, client_data->ipv6 ? '6' : '4', client_data->iface);

	g_hash_table_insert (priv->clients, client, client_data);

	return client_data;
}

static NMDHCPClient *
client_start (NMDHCPManager *self,
              const char *iface,
              const GByteArray *hwaddr,
              const char *uuid,
              gboolean ipv6,
              const char *dhcp_client_id,
              guint32 timeout,
              GByteArray *dhcp_anycast_addr,
              const char *hostname,
              gboolean info_only)
{
	NMDHCPManagerPrivate *priv;
	NMDHCPClient *client;
	gboolean has_zombie_clients = FALSE;
	struct client_data *client_data;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (uuid != NULL, NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	/* Ensure we have a usable DHCP client */
	g_return_val_if_fail (priv->client_type != 0, NULL);

	/* Kill any old client instance */
	has_zombie_clients = dispose_old_clients (self, iface, ipv6);

	/* And make a new one */
	client = g_object_new (priv->client_type,
	                       NM_DHCP_CLIENT_INTERFACE, iface,
	                       NM_DHCP_CLIENT_HWADDR, hwaddr,
	                       NM_DHCP_CLIENT_IPV6, ipv6,
	                       NM_DHCP_CLIENT_UUID, uuid,
	                       NM_DHCP_CLIENT_TIMEOUT, timeout ? timeout : DHCP_TIMEOUT,
	                       NULL);
	g_return_val_if_fail (client != NULL, NULL);
	client_data = add_client (self, client);

	if (!has_zombie_clients) {
		if (!start_client (self, client_data, dhcp_client_id, dhcp_anycast_addr, hostname, info_only)) {
			g_object_unref (client);
			client = NULL;
		}
	} else {
		client_data->dhcp_client_id = g_strdup (dhcp_client_id);
		if (dhcp_anycast_addr) {
			client_data->dhcp_anycast_addr = g_byte_array_new ();
			g_byte_array_append (client_data->dhcp_anycast_addr, dhcp_anycast_addr->data, dhcp_anycast_addr->len);
		}
		client_data->hostname = g_strdup (hostname);
		client_data->info_only = info_only;
		nm_log_dbg (LOGD_DHCP, "DHCP manager: client %p: not start yet, because there are concurrent clients", client);
	}

	return client;
}

/* Caller owns a reference to the NMDHCPClient on return */
NMDHCPClient *
nm_dhcp_manager_start_ip4 (NMDHCPManager *self,
                           const char *iface,
                           const GByteArray *hwaddr,
                           const char *uuid,
                           NMSettingIP4Config *s_ip4,
                           guint32 timeout,
                           GByteArray *dhcp_anycast_addr)
{
	NMDHCPManagerPrivate *priv;
	const char *hostname, *method;
	gboolean send_hostname;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	method = nm_setting_ip4_config_get_method (s_ip4);
	g_return_val_if_fail (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0, NULL);

	send_hostname = nm_setting_ip4_config_get_dhcp_send_hostname (s_ip4);
	if (send_hostname) {
		hostname = nm_setting_ip4_config_get_dhcp_hostname (s_ip4);

		/* If we're supposed to send the hostname to the DHCP server but
		 * the user didn't specify one, then use the hostname from the
		 * hostname provider if there is one, otherwise use the persistent
		 * hostname.
		 */
		if (!hostname && priv->hostname_provider) {
			hostname = nm_hostname_provider_get_hostname (priv->hostname_provider);
			if (   hostname
			    && (!strcmp (hostname, "localhost.localdomain") ||
			        !strcmp (hostname, "localhost6.localdomain6")))
				hostname = NULL;
		}
	} else
		hostname = NULL;

	return client_start (self, iface, hwaddr, uuid, FALSE, nm_setting_ip4_config_get_dhcp_client_id (s_ip4), timeout, dhcp_anycast_addr, hostname, FALSE);
}

/* Caller owns a reference to the NMDHCPClient on return */
NMDHCPClient *
nm_dhcp_manager_start_ip6 (NMDHCPManager *self,
                           const char *iface,
                           const GByteArray *hwaddr,
                           const char *uuid,
                           NMSettingIP6Config *s_ip6,
                           guint32 timeout,
                           GByteArray *dhcp_anycast_addr,
                           gboolean info_only)
{
	NMDHCPManagerPrivate *priv;
	const char *hostname;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	hostname = nm_setting_ip6_config_get_dhcp_hostname (s_ip6);
	if (!hostname && priv->hostname_provider) {
		hostname = nm_hostname_provider_get_hostname (priv->hostname_provider);
		if (   g_strcmp0 (hostname, "localhost.localdomain") == 0
		    || g_strcmp0 (hostname, "localhost6.localdomain6") == 0)
			hostname = NULL;
	}

	return client_start (self, iface, hwaddr, uuid, TRUE, NULL, timeout, dhcp_anycast_addr, hostname, info_only);
}

static void
hostname_provider_destroyed (gpointer data, GObject *destroyed_object)
{
	NM_DHCP_MANAGER_GET_PRIVATE (data)->hostname_provider = NULL;
}

void
nm_dhcp_manager_set_hostname_provider (NMDHCPManager *manager,
									   NMHostnameProvider *provider)
{
	NMDHCPManagerPrivate *priv;

	g_return_if_fail (NM_IS_DHCP_MANAGER (manager));

	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	if (priv->hostname_provider) {
		g_object_weak_unref (G_OBJECT (priv->hostname_provider), hostname_provider_destroyed, manager);
		priv->hostname_provider = NULL;
	}

	if (provider) {
		priv->hostname_provider = provider;
		g_object_weak_ref (G_OBJECT (provider), hostname_provider_destroyed, manager);
	}
}

GSList *
nm_dhcp_manager_get_lease_ip_configs (NMDHCPManager *self,
                                      const char *iface,
                                      const char *uuid,
                                      gboolean ipv6)
{
	NMDHCPManagerPrivate *priv;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (self), NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (uuid != NULL, NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (self);

	if (priv->get_lease_ip_configs_func)
		return priv->get_lease_ip_configs_func (iface, uuid, ipv6);
	return NULL;
}

NMIP4Config *
nm_dhcp_manager_test_ip4_options_to_config (const char *dhcp_client,
                                            const char *iface,
                                            GHashTable *options,
                                            const char *reason)
{
	NMDHCPClient *client;
	NMIP4Config *config;
	GType client_type;
	GError *error = NULL;

	client_type = get_client_type (dhcp_client, &error);
	if (!client_type) {
		nm_log_err (LOGD_DHCP4, "error: %s", error ? error->message : "(unknown)");
		g_clear_error (&error);
		return NULL;
	}

	client = (NMDHCPClient *) g_object_new (client_type,
	                                        NM_DHCP_CLIENT_INTERFACE, iface,
	                                        NULL);
	g_return_val_if_fail (client != NULL, NULL);
	nm_dhcp_client_new_options (client, options, reason);
	config = nm_dhcp_client_get_ip4_config (client, TRUE);
	g_object_unref (client);

	return config;
}

/***************************************************/

static void
nm_dhcp_manager_init (NMDHCPManager *manager)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	/* Maps DBusGConnection :: DBusGProxy */
	priv->proxies = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_object_unref);
}

static void
dispose (GObject *object)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (object);
	GList *values, *iter;

	if (priv->clients) {
		values = g_hash_table_get_values (priv->clients);
		for (iter = values; iter; iter = g_list_next (iter))
			remove_client (NM_DHCP_MANAGER (object), NM_DHCP_CLIENT (iter->data), TRUE);
		g_list_free (values);
	}

	if (priv->new_conn_id) {
		g_signal_handler_disconnect (priv->dbus_mgr, priv->new_conn_id);
		priv->new_conn_id = 0;
	}
	if (priv->dis_conn_id) {
		g_signal_handler_disconnect (priv->dbus_mgr, priv->dis_conn_id);
		priv->dis_conn_id = 0;
	}
	priv->dbus_mgr = NULL;

	if (priv->proxies) {
		g_hash_table_destroy (priv->proxies);
		priv->proxies = NULL;
	}
	if (priv->proxy)
		g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_dhcp_manager_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (object);

	if (priv->hostname_provider) {
		g_object_weak_unref (G_OBJECT (priv->hostname_provider), hostname_provider_destroyed, object);
		priv->hostname_provider = NULL;
	}

	if (priv->clients)
		g_hash_table_destroy (priv->clients);

	G_OBJECT_CLASS (nm_dhcp_manager_parent_class)->finalize (object);
}

static void
nm_dhcp_manager_class_init (NMDHCPManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMDHCPManagerPrivate));

	/* virtual methods */
	object_class->finalize = finalize;
	object_class->dispose = dispose;
}
