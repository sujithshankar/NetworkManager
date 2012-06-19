/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
 *
 * Dan Williams <dcbw@redhat.com>
 * Søren Sandmann <sandmann@daimi.au.dk>
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
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#include <config.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#include <gmodule.h>
#include <glib-object.h>
#include <glib/gi18n.h>
#include <gio/gio.h>

#include <nm-setting-connection.h>

#include "common.h"
#include "plugin.h"
#include "nm-system-config-interface.h"
#include "nm-settings-error.h"

#include "nm-ifcfg-connection.h"
#include "nm-inotify-helper.h"
#include "shvar.h"
#include "writer.h"
#include "utils.h"

#include "nm-ifcfg-rh-generated.h"

#define NM_IFCFG_RH_SERVICE_NAME "com.redhat.ifcfgrh1"
#define NM_IFCFG_RH_OBJECT_PATH "/com/redhat/ifcfgrh1"

#define HOSTNAMED_SERVICE_NAME      "org.freedesktop.hostname1"
#define HOSTNAMED_SERVICE_PATH      "/org/freedesktop/hostname1"
#define HOSTNAMED_SERVICE_INTERFACE "org.freedesktop.hostname1"

static void connection_new_or_changed (SCPluginIfcfg *plugin,
                                       const char *path,
                                       NMIfcfgConnection *existing);

static void system_config_interface_init (NMSystemConfigInterface *system_config_interface_class);

G_DEFINE_TYPE_EXTENDED (SCPluginIfcfg, sc_plugin_ifcfg, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE,
											   system_config_interface_init))

#define SC_PLUGIN_IFCFG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_IFCFG, SCPluginIfcfgPrivate))


typedef struct {
	GHashTable *connections;

	GDBusProxy *hostnamed;
	char *hostname;

	GFileMonitor *ifcfg_monitor;
	guint ifcfg_monitor_id;

	GDBusConnection *bus;
	guint owner_id;
	NMIfcfgRH *dbus_ifcfg;
} SCPluginIfcfgPrivate;


static void
connection_unmanaged_changed (NMIfcfgConnection *connection,
                              GParamSpec *pspec,
                              gpointer user_data)
{
	g_signal_emit_by_name (SC_PLUGIN_IFCFG (user_data), NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
}

static void
connection_ifcfg_changed (NMIfcfgConnection *connection, gpointer user_data)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (user_data);
	const char *path;

	path = nm_ifcfg_connection_get_path (connection);
	g_return_if_fail (path != NULL);

	connection_new_or_changed (plugin, path, connection);
}

static NMIfcfgConnection *
_internal_new_connection (SCPluginIfcfg *self,
                          const char *path,
                          NMConnection *source,
                          GError **error)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	NMIfcfgConnection *connection;
	const char *cid;
	GError *local = NULL;
	gboolean ignore_error = FALSE;

	if (!source) {
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "parsing %s ... ", path);
	}

	connection = nm_ifcfg_connection_new (path, source, &local, &ignore_error);
	if (!connection) {
		if (!ignore_error) {
			PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    error: %s",
			              (local && local->message) ? local->message : "(unknown)");
		}
		g_propagate_error (error, local);
		return NULL;
	}

	cid = nm_connection_get_id (NM_CONNECTION (connection));
	g_assert (cid);

	g_hash_table_insert (priv->connections,
	                     (gpointer) nm_ifcfg_connection_get_path (connection),
	                     connection);
	PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    read connection '%s'", cid);

	if (nm_ifcfg_connection_get_unmanaged_spec (connection)) {
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "Ignoring connection '%s' and its "
		              "device due to NM_CONTROLLED/BRIDGE/VLAN.", cid);
	} else {
		/* Wait for the connection to become unmanaged once it knows the
		 * hardware IDs of its device, if/when the device gets plugged in.
		 */
		g_signal_connect (G_OBJECT (connection), "notify::" NM_IFCFG_CONNECTION_UNMANAGED,
		                  G_CALLBACK (connection_unmanaged_changed), self);
	}

	/* watch changes of ifcfg hardlinks */
	g_signal_connect (G_OBJECT (connection), "ifcfg-changed",
	                  G_CALLBACK (connection_ifcfg_changed), self);

	return connection;
}

static void
read_connections (SCPluginIfcfg *plugin)
{
	GDir *dir;
	GError *err = NULL;

	dir = g_dir_open (IFCFG_DIR, 0, &err);
	if (dir) {
		const char *item;

		while ((item = g_dir_read_name (dir))) {
			char *full_path;

			if (utils_should_ignore_file (item, TRUE))
				continue;

			full_path = g_build_filename (IFCFG_DIR, item, NULL);
			if (utils_get_ifcfg_name (full_path, TRUE))
				_internal_new_connection (plugin, full_path, NULL, NULL);
			g_free (full_path);
		}

		g_dir_close (dir);
	} else {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Can not read directory '%s': %s", IFCFG_DIR, err->message);
		g_error_free (err);
	}
}

/* Monitoring */

/* Callback for nm_settings_connection_replace_and_commit. Report any errors
 * encountered when commiting connection settings updates. */
static void
commit_cb (NMSettingsConnection *connection, GError *error, gpointer unused) 
{
	if (error) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    error updating: %s",
	             	 (error && error->message) ? error->message : "(unknown)");
	}
}

static void
remove_connection (SCPluginIfcfg *self, NMIfcfgConnection *connection)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (self);
	gboolean managed = FALSE;
	const char *path;

	g_return_if_fail (self != NULL);
	g_return_if_fail (connection != NULL);

	managed = !nm_ifcfg_connection_get_unmanaged_spec (connection);
	path = nm_ifcfg_connection_get_path (connection);

	g_object_ref (connection);
	g_hash_table_remove (priv->connections, path);
	nm_settings_connection_signal_remove (NM_SETTINGS_CONNECTION (connection));
	g_object_unref (connection);

	/* Emit unmanaged changes _after_ removing the connection */
	if (managed == FALSE)
		g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
}

static void
connection_new_or_changed (SCPluginIfcfg *self,
                           const char *path,
                           NMIfcfgConnection *existing)
{
	NMIfcfgConnection *new;
	GError *error = NULL;
	gboolean ignore_error = FALSE;
	const char *new_unmanaged = NULL, *old_unmanaged = NULL;

	g_return_if_fail (self != NULL);
	g_return_if_fail (path != NULL);

	if (!existing) {
		/* Completely new connection */
		new = _internal_new_connection (self, path, NULL, NULL);
		if (new) {
			if (nm_ifcfg_connection_get_unmanaged_spec (new)) {
				g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
			} else {
				/* Only managed connections are announced to the settings service */
				g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, new);
			}
		}
		return;
	}

	new = (NMIfcfgConnection *) nm_ifcfg_connection_new (path, NULL, &error, &ignore_error);
	if (!new) {
		/* errors reading connection; remove it */
		if (!ignore_error) {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    error: %s",
			             (error && error->message) ? error->message : "(unknown)");
		}
		g_clear_error (&error);

		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "removed %s.", path);
		remove_connection (self, existing);
		return;
	}

	/* Successfully read connection changes */

	old_unmanaged = nm_ifcfg_connection_get_unmanaged_spec (NM_IFCFG_CONNECTION (existing));
	new_unmanaged = nm_ifcfg_connection_get_unmanaged_spec (NM_IFCFG_CONNECTION (new));

	/* When interface is unmanaged or the connections and unmanaged specs are the same
	 * there's nothing to do */
	if (   (g_strcmp0 (old_unmanaged, new_unmanaged) == 0 && new_unmanaged != NULL)
	    || (   nm_connection_compare (NM_CONNECTION (existing),
	                                  NM_CONNECTION (new),
	                                  NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS |
	                                    NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS)
	        && g_strcmp0 (old_unmanaged, new_unmanaged) == 0)) {

		g_object_unref (new);
		return;
	}

	PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "updating %s", path);

	if (new_unmanaged) {
		if (!old_unmanaged) {
			/* Unexport the connection by telling the settings service it's
			 * been removed, and notify the settings service by signalling that
			 * unmanaged specs have changed.
			 */
			nm_settings_connection_signal_remove (NM_SETTINGS_CONNECTION (existing));
			/* Remove the path so that claim_connection() doesn't complain later when
			 * interface gets managed and connection is re-added. */
			nm_connection_set_path (NM_CONNECTION (existing), NULL);

			g_object_set (existing, NM_IFCFG_CONNECTION_UNMANAGED, new_unmanaged, NULL);
			g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
		}
	} else {
		if (old_unmanaged) {  /* now managed */
			const char *cid;

			cid = nm_connection_get_id (NM_CONNECTION (new));
			g_assert (cid);

			PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "Managing connection '%s' and its "
			              "device because NM_CONTROLLED was true.", cid);
			g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, existing);
		}

		nm_settings_connection_replace_and_commit (NM_SETTINGS_CONNECTION (existing),
		                                           NM_CONNECTION (new),
		                                           commit_cb, NULL);

		/* Update unmanaged status */
		g_object_set (existing, NM_IFCFG_CONNECTION_UNMANAGED, new_unmanaged, NULL);
		g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
	}
	g_object_unref (new);
}

static void
ifcfg_dir_changed (GFileMonitor *monitor,
                   GFile *file,
                   GFile *other_file,
                   GFileMonitorEvent event_type,
                   gpointer user_data)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (user_data);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	char *path, *name;
	NMIfcfgConnection *connection;

	path = g_file_get_path (file);
	if (utils_should_ignore_file (path, FALSE)) {
		g_free (path);
		return;
	}

	/* Given any ifcfg, keys, or routes file, get the ifcfg file path */
	name = utils_get_ifcfg_path (path);
	g_free (path);
	if (name) {
		connection = g_hash_table_lookup (priv->connections, name);
		switch (event_type) {
		case G_FILE_MONITOR_EVENT_DELETED:
			PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "removed %s.", name);
			if (connection)
				remove_connection (plugin, connection);
			break;
		case G_FILE_MONITOR_EVENT_CREATED:
		case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
			/* Update or new */
			connection_new_or_changed (plugin, name, connection);
			break;
		default:
			break;
		}
		g_free (name);
	}
}

static void
setup_ifcfg_monitoring (SCPluginIfcfg *plugin)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GFile *file;
	GFileMonitor *monitor;

	priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);

	file = g_file_new_for_path (IFCFG_DIR "/");
	monitor = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);

	if (monitor) {
		priv->ifcfg_monitor_id = g_signal_connect (monitor, "changed",
		                                           G_CALLBACK (ifcfg_dir_changed), plugin);
		priv->ifcfg_monitor = monitor;
	}
}

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GSList *list = NULL;
	GHashTableIter iter;
	gpointer value;

	if (!priv->connections) {
		setup_ifcfg_monitoring (plugin);
		read_connections (plugin);
	}

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		NMIfcfgConnection *exported = NM_IFCFG_CONNECTION (value);

		if (!nm_ifcfg_connection_get_unmanaged_spec (exported))
			list = g_slist_prepend (list, value);
	}

	return list;
}

static void
check_unmanaged (gpointer key, gpointer data, gpointer user_data)
{
	GSList **list = (GSList **) user_data;
	NMIfcfgConnection *connection = NM_IFCFG_CONNECTION (data);
	const char *unmanaged_spec;
	GSList *iter;

	unmanaged_spec = nm_ifcfg_connection_get_unmanaged_spec (connection);
	if (!unmanaged_spec)
		return;

	/* Just return if the unmanaged spec is already in the list */
	for (iter = *list; iter; iter = g_slist_next (iter)) {
		if (!strcmp ((char *) iter->data, unmanaged_spec))
			return;
	}

	*list = g_slist_prepend (*list, g_strdup (unmanaged_spec));
}

static GSList *
get_unmanaged_specs (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (config);
	GSList *list = NULL;

	if (!priv->connections) {
		setup_ifcfg_monitoring (plugin);
		read_connections (plugin);
	}

	g_hash_table_foreach (priv->connections, check_unmanaged, &list);
	return list;
}

static NMSettingsConnection *
add_connection (NMSystemConfigInterface *config,
                NMConnection *connection,
                GError **error)
{
	SCPluginIfcfg *self = SC_PLUGIN_IFCFG (config);
	NMIfcfgConnection *added = NULL;
	char *path = NULL;

	/* Write it out first, then add the connection to our internal list */
	if (writer_new_connection (connection, IFCFG_DIR, &path, error)) {
		added = _internal_new_connection (self, path, connection, error);
		g_free (path);
	}
	return (NMSettingsConnection *) added;
}

static char *
plugin_get_hostname (SCPluginIfcfg *plugin)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);

	return g_strdup (priv->hostname);
}

static gboolean
plugin_set_hostname (SCPluginIfcfg *plugin, const char *hostname)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GVariant *ret;
	GError *error = NULL;

	ret = g_dbus_proxy_call_sync (priv->hostnamed,
	                              "SetHostname",
	                              g_variant_new ("(sb)",
	                                             hostname,
	                                             FALSE),
	                              G_DBUS_CALL_FLAGS_NONE,
	                              -1,
	                              NULL,
	                              &error);
	if (ret)
		g_variant_unref (ret);

	if (error) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Could not set hostname: %s", error->message);
		g_error_free (error);
		return FALSE;
	}

	g_free (priv->hostname);
	priv->hostname = g_strdup (hostname);

	return TRUE;
}

static void
hostnamed_properties_changed (GDBusProxy *proxy,
                              GVariant *changed_properties,
                              char **invalidated_properties,
                              gpointer user_data)
{
	SCPluginIfcfg *plugin = user_data;
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GVariant *v_hostname;
	const char *hostname;

	v_hostname = g_dbus_proxy_get_cached_property (priv->hostnamed, "StaticHostname");
	if (!v_hostname)
		return;

	hostname = g_variant_get_string (v_hostname, NULL);
	if (g_strcmp0 (priv->hostname, hostname) != 0) {
		priv->hostname = g_strdup (hostname);
		g_object_notify (G_OBJECT (plugin), NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
	}

	g_variant_unref (v_hostname);
}

static void
hostname_changed_cb (GFileMonitor *monitor,
                     GFile *file,
                     GFile *other_file,
                     GFileMonitorEvent event_type,
                     gpointer user_data)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (user_data);

	hostname_maybe_changed (plugin);
}

static gboolean
handle_get_ifcfg_details (NMIfcfgRH *object,
                          GDBusMethodInvocation *invocation,
                          const gchar *ifcfg,
                          gpointer user_data)
{
	SCPluginIfcfg *plugin = user_data;
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	NMIfcfgConnection *connection;
	NMSettingConnection *s_con;
	const char *uuid;
	const char *path;

	if (!g_path_is_absolute (ifcfg)) {
		g_dbus_method_invocation_return_error (invocation,
		                                       NM_SETTINGS_ERROR,
		                                       NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                                       "ifcfg path '%s' is not absolute", ifcfg);
		return TRUE;
	}

	connection = g_hash_table_lookup (priv->connections, ifcfg);
	if (!connection || nm_ifcfg_connection_get_unmanaged_spec (connection)) {
		g_dbus_method_invocation_return_error (invocation,
		                                       NM_SETTINGS_ERROR,
		                                       NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                                       "ifcfg file '%s' unknown", ifcfg);
		return TRUE;
	}

	s_con = nm_connection_get_setting_connection (NM_CONNECTION (connection));
	if (!s_con) {
		g_dbus_method_invocation_return_error (invocation,
		                                       NM_SETTINGS_ERROR,
		                                       NM_SETTINGS_ERROR_INTERNAL_ERROR,
		                                       "unable to retrieve the connection setting");
		return TRUE;
	}

	uuid = nm_setting_connection_get_uuid (s_con);
	if (!uuid) {
		g_dbus_method_invocation_return_error (invocation,
		                                       NM_SETTINGS_ERROR,
		                                       NM_SETTINGS_ERROR_INTERNAL_ERROR,
		                                       "unable to get the UUID");
		return TRUE;
	}
	
	path = nm_connection_get_path (NM_CONNECTION (connection));
	if (!path) {
		g_dbus_method_invocation_return_error (invocation,
		                                       NM_SETTINGS_ERROR,
		                                       NM_SETTINGS_ERROR_INTERNAL_ERROR,
		                                       "unable to get the connection D-Bus path");
		return TRUE;
	}

	nm_ifcfg_rh_complete_get_ifcfg_details (object, invocation, uuid, path);
	return TRUE;
}

static void
init (NMSystemConfigInterface *config)
{
}

static gboolean ever_acquired_name = FALSE;

static void
on_name_acquired (GDBusConnection *connection,
                  const gchar     *name,
                  gpointer         user_data)
{
	PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "Acquired D-Bus name '%s'", NM_IFCFG_RH_SERVICE_NAME);
	ever_acquired_name = TRUE;
}

static void
on_name_lost (GDBusConnection *connection,
              const gchar     *name,
              gpointer         user_data)
{
	if (ever_acquired_name)
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Lost D-Bus name '%s'", NM_IFCFG_RH_SERVICE_NAME);
	else
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Could not acquire D-Bus name '%s'", NM_IFCFG_RH_SERVICE_NAME);
}

static void
got_hostnamed_proxy (GObject *object, GAsyncResult *result, gpointer user_data)
{
	SCPluginIfcfg *plugin = user_data;
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GError *error = NULL;

	priv->hostnamed = g_dbus_proxy_new_finish (result, &error);
	if (!priv->hostnamed) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Could not contact hostnamed");
		g_object_unref (plugin);
		return;
	}

	g_signal_connect (priv->hostnamed, "g-properties-changed",
	                  G_CALLBACK (hostnamed_properties_changed), plugin);
	hostnamed_properties_changed (priv->hostnamed, NULL, NULL, plugin);

	g_object_unref (plugin);
}

static void
got_bus (GObject *object, GAsyncResult *result, gpointer user_data)
{
	SCPluginIfcfg *plugin = user_data;
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GError *error = NULL;

	priv->bus = g_bus_get_finish (result, &error);
	if (!priv->bus) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Could not connect to D-Bus: %s", error->message);
		g_error_free (error);
		return;
	}

	g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (priv->dbus_ifcfg),
	                                  priv->bus,
	                                  NM_IFCFG_RH_OBJECT_PATH, &error);
	if (error) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Couldn't export NMIfcfgRH object: %s",
		             error->message);
		g_error_free (error);
	}

	priv->owner_id = g_bus_own_name_on_connection (priv->bus,
	                                               NM_IFCFG_RH_SERVICE_NAME,
	                                               0,
	                                               on_name_acquired,
	                                               on_name_lost,
	                                               plugin, NULL);

	g_dbus_proxy_new (priv->bus, 0, NULL,
	                  HOSTNAMED_SERVICE_NAME,
	                  HOSTNAMED_SERVICE_PATH,
	                  HOSTNAMED_SERVICE_INTERFACE,
	                  NULL,
	                  got_hostnamed_proxy,
	                  g_object_ref (plugin));
}

static void
sc_plugin_ifcfg_init (SCPluginIfcfg *plugin)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);

	priv->dbus_ifcfg = nm_ifcfg_rh_skeleton_new ();
	g_signal_connect (priv->dbus_ifcfg, "handle-get-ifcfg-details",
	                  G_CALLBACK (handle_get_ifcfg_details), plugin);

	g_bus_get (G_BUS_TYPE_SYSTEM, NULL, got_bus, plugin);
}

static void
dispose (GObject *object)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (object);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	NMInotifyHelper *ih;

	if (priv->owner_id) {
		g_bus_unown_name (priv->owner_id);
		priv->owner_id = 0;
	}

	if (priv->dbus_ifcfg) {
		g_signal_handlers_disconnect_by_func (priv->dbus_ifcfg,
		                                      G_CALLBACK (handle_get_ifcfg_details),
		                                      plugin);
		g_object_unref (priv->dbus_ifcfg);
		priv->dbus_ifcfg = NULL;
	}

	if (priv->hostnamed) {
		g_signal_handlers_disconnect_by_func (priv->hostnamed,
		                                      G_CALLBACK (hostnamed_properties_changed),
		                                      plugin);
		g_object_unref (priv->hostnamed);
		priv->hostnamed = NULL;
	}

	if (priv->bus) {
		g_object_unref (priv->bus);
		priv->bus = NULL;
	}

	g_free (priv->hostname);
	priv->hostname = NULL;

	if (priv->connections) {
		g_hash_table_destroy (priv->connections);
		priv->connections = NULL;
	}

	if (priv->ifcfg_monitor) {
		if (priv->ifcfg_monitor_id)
			g_signal_handler_disconnect (priv->ifcfg_monitor, priv->ifcfg_monitor_id);

		g_file_monitor_cancel (priv->ifcfg_monitor);
		g_object_unref (priv->ifcfg_monitor);
		priv->ifcfg_monitor = NULL;
	}

	G_OBJECT_CLASS (sc_plugin_ifcfg_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	G_OBJECT_CLASS (sc_plugin_ifcfg_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (object);

	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME:
		g_value_set_string (value, IFCFG_PLUGIN_NAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO:
		g_value_set_string (value, IFCFG_PLUGIN_INFO);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES:
		g_value_set_uint (value, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS | NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		g_value_set_string (value, priv->hostname);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	const char *hostname;

	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		hostname = g_value_get_string (value);
		if (hostname && strlen (hostname) < 1)
			hostname = NULL;
		plugin_set_hostname (SC_PLUGIN_IFCFG (object), hostname);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
sc_plugin_ifcfg_class_init (SCPluginIfcfgClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (SCPluginIfcfgPrivate));

	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME,
	                                  NM_SYSTEM_CONFIG_INTERFACE_NAME);

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO,
	                                  NM_SYSTEM_CONFIG_INTERFACE_INFO);

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES,
	                                  NM_SYSTEM_CONFIG_INTERFACE_CAPABILITIES);

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME,
	                                  NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
}

static void
system_config_interface_init (NMSystemConfigInterface *system_config_interface_class)
{
	/* interface implementation */
	system_config_interface_class->get_connections = get_connections;
	system_config_interface_class->add_connection = add_connection;
	system_config_interface_class->get_unmanaged_specs = get_unmanaged_specs;
	system_config_interface_class->init = init;
}

G_MODULE_EXPORT GObject *
nm_system_config_factory (void)
{
	static SCPluginIfcfg *singleton = NULL;

	if (!singleton) {
		singleton = SC_PLUGIN_IFCFG (g_object_new (SC_TYPE_PLUGIN_IFCFG, NULL));
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "Acquired D-Bus service %s", NM_IFCFG_RH_SERVICE_NAME);
	} else
		g_object_ref (singleton);

	return G_OBJECT (singleton);
}
