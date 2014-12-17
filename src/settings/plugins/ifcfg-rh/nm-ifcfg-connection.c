/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>

#include <glib/gstdio.h>

#include <nm-dbus-interface.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-gsm.h>
#include <nm-setting-cdma.h>
#include <nm-setting-pppoe.h>
#include <nm-setting-wireless-security.h>
#include <nm-setting-8021x.h>

#include "common.h"
#include "nm-config.h"
#include "nm-ifcfg-connection.h"
#include "reader.h"
#include "writer.h"
#include "nm-inotify-helper.h"
#include "utils.h"

G_DEFINE_TYPE (NMIfcfgConnection, nm_ifcfg_connection, NM_TYPE_SETTINGS_CONNECTION)

#define NM_IFCFG_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IFCFG_CONNECTION, NMIfcfgConnectionPrivate))

typedef struct {
	gulong ih_event_id;

	int file_wd;

	char *keyfile;
	int keyfile_wd;

	char *routefile;
	int routefile_wd;

	char *route6file;
	int route6file_wd;

	char *unmanaged_spec;
	char *unrecognized_spec;
} NMIfcfgConnectionPrivate;

enum {
	PROP_0,
	PROP_UNMANAGED_SPEC,
	PROP_UNRECOGNIZED_SPEC,
	LAST_PROP
};

/* Signals */
enum {
	IFCFG_CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void
files_changed_cb (NMInotifyHelper *ih,
                  struct inotify_event *evt,
                  const char *path,
                  gpointer user_data)
{
	NMIfcfgConnection *self = NM_IFCFG_CONNECTION (user_data);
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (self);

	if (   (evt->wd != priv->file_wd)
	    && (evt->wd != priv->keyfile_wd)
	    && (evt->wd != priv->routefile_wd)
	    && (evt->wd != priv->route6file_wd))
		return;

	/* push the event up to the plugin */
	g_signal_emit (self, signals[IFCFG_CHANGED], 0);
}

NMIfcfgConnection *
nm_ifcfg_connection_new (NMConnection *source,
                         const char *full_path,
                         GError **error)
{
	GObject *object;
	NMConnection *tmp;
	char *unhandled_spec = NULL;
	const char *unmanaged_spec = NULL, *unrecognized_spec = NULL;
	gboolean update_unsaved = TRUE;

	g_assert (source || full_path);

	/* If we're given a connection already, prefer that instead of re-reading */
	if (source)
		tmp = g_object_ref (source);
	else {
		tmp = connection_from_file (full_path,
		                            &unhandled_spec,
		                            error);
		if (!tmp)
			return NULL;

		/* If we just read the connection from disk, it's clearly not Unsaved */
		update_unsaved = FALSE;
	}

	if (unhandled_spec && g_str_has_prefix (unhandled_spec, "unmanaged:"))
		unmanaged_spec = unhandled_spec + strlen ("unmanaged:");
	else if (unhandled_spec && g_str_has_prefix (unhandled_spec, "unrecognized:"))
		unrecognized_spec = unhandled_spec + strlen ("unrecognized:");

	object = (GObject *) g_object_new (NM_TYPE_IFCFG_CONNECTION,
	                                   NM_SETTINGS_CONNECTION_FILENAME, full_path,
	                                   NM_IFCFG_CONNECTION_UNMANAGED_SPEC, unmanaged_spec,
	                                   NM_IFCFG_CONNECTION_UNRECOGNIZED_SPEC, unrecognized_spec,
	                                   NULL);
	/* Update our settings with what was read from the file */
	if (!nm_settings_connection_replace_settings (NM_SETTINGS_CONNECTION (object),
	                                              tmp,
	                                              update_unsaved,
	                                              error))
		g_clear_object (&object);

	g_object_unref (tmp);
	g_free (unhandled_spec);
	return (NMIfcfgConnection *) object;
}

static void
path_watch_stop (NMIfcfgConnection *self)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (self);
	NMInotifyHelper *ih;

	ih = nm_inotify_helper_get ();

	if (priv->ih_event_id) {
		g_signal_handler_disconnect (ih, priv->ih_event_id);
		priv->ih_event_id = 0;
	}

	if (priv->file_wd >= 0) {
		nm_inotify_helper_remove_watch (ih, priv->file_wd);
		priv->file_wd = -1;
	}

	g_free (priv->keyfile);
	priv->keyfile = NULL;
	if (priv->keyfile_wd >= 0) {
		nm_inotify_helper_remove_watch (ih, priv->keyfile_wd);
		priv->keyfile_wd = -1;
	}

	g_free (priv->routefile);
	priv->routefile = NULL;
	if (priv->routefile_wd >= 0) {
		nm_inotify_helper_remove_watch (ih, priv->routefile_wd);
		priv->routefile_wd = -1;
	}

	g_free (priv->route6file);
	priv->route6file = NULL;
	if (priv->route6file_wd >= 0) {
		nm_inotify_helper_remove_watch (ih, priv->route6file_wd);
		priv->route6file_wd = -1;
	}
}

static void
filename_changed (GObject *object,
                  GParamSpec *pspec,
                  gpointer user_data)
{
	NMIfcfgConnection *self = NM_IFCFG_CONNECTION (object);
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (self);
	const char *ifcfg_path;

	path_watch_stop (self);

	ifcfg_path = nm_settings_connection_get_filename (NM_SETTINGS_CONNECTION (self));
	if (!ifcfg_path)
		return;

	priv->keyfile = utils_get_keys_path (ifcfg_path);
	priv->routefile = utils_get_route_path (ifcfg_path);
	priv->route6file = utils_get_route6_path (ifcfg_path);

	if (nm_config_get_monitor_connection_files (nm_config_get ())) {
		NMInotifyHelper *ih = nm_inotify_helper_get ();

		priv->ih_event_id = g_signal_connect (ih, "event", G_CALLBACK (files_changed_cb), self);
		priv->file_wd = nm_inotify_helper_add_watch (ih, ifcfg_path);
		priv->keyfile_wd = nm_inotify_helper_add_watch (ih, priv->keyfile);
		priv->routefile_wd = nm_inotify_helper_add_watch (ih, priv->routefile);
		priv->route6file_wd = nm_inotify_helper_add_watch (ih, priv->route6file);
	}
}

const char *
nm_ifcfg_connection_get_unmanaged_spec (NMIfcfgConnection *self)
{
	g_return_val_if_fail (NM_IS_IFCFG_CONNECTION (self), NULL);

	return NM_IFCFG_CONNECTION_GET_PRIVATE (self)->unmanaged_spec;
}

const char *
nm_ifcfg_connection_get_unrecognized_spec (NMIfcfgConnection *self)
{
	g_return_val_if_fail (NM_IS_IFCFG_CONNECTION (self), NULL);

	return NM_IFCFG_CONNECTION_GET_PRIVATE (self)->unrecognized_spec;
}

static void
replace_and_commit (NMSettingsConnection *connection,
                    NMConnection *new_connection,
                    NMSettingsConnectionCommitFunc callback,
                    gpointer user_data)
{
	const char *filename;
	GError *error = NULL;

	filename = nm_settings_connection_get_filename (connection);
	if (filename && utils_has_complex_routes (filename)) {
		if (callback) {
			error = g_error_new_literal (NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			                             "Cannot modify a connection that has an associated 'rule-' or 'rule6-' file");
			callback (connection, error, user_data);
			g_clear_error (&error);
		}
	}

	NM_SETTINGS_CONNECTION_CLASS (nm_ifcfg_connection_parent_class)->replace_and_commit (connection, new_connection, callback, user_data);
}

static void
commit_changes (NMSettingsConnection *connection,
                NMSettingsConnectionCommitFunc callback,
                gpointer user_data)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (connection);
	GError *error = NULL;
	NMConnection *reread;
	gboolean same = FALSE, success = FALSE;
	char *ifcfg_path = NULL;
	const char *filename;

	/* To ensure we don't rewrite files that are only changed from other
	 * processes on-disk, read the existing connection back in and only rewrite
	 * it if it's really changed.
	 */
	filename = nm_settings_connection_get_filename (connection);
	if (filename) {
		reread = connection_from_file (filename, NULL, NULL);
		if (reread) {
			same = nm_connection_compare (NM_CONNECTION (connection),
			                              reread,
			                              NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS |
			                                 NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS);
			g_object_unref (reread);

			/* Don't bother writing anything out if in-memory and on-disk data are the same */
			if (same) {
				/* But chain up to parent to handle success - emits updated signal */
				NM_SETTINGS_CONNECTION_CLASS (nm_ifcfg_connection_parent_class)->commit_changes (connection, callback, user_data);
				return;
			}
		}

		success = writer_update_connection (NM_CONNECTION (connection),
		                                    IFCFG_DIR,
		                                    filename,
		                                    priv->keyfile,
		                                    &error);
	} else {
		success = writer_new_connection (NM_CONNECTION (connection),
		                                 IFCFG_DIR,
		                                 &ifcfg_path,
		                                 &error);
		if (success) {
			nm_settings_connection_set_filename (connection, ifcfg_path);
			g_free (ifcfg_path);
		}
	}

	if (success) {
		/* Chain up to parent to handle success */
		NM_SETTINGS_CONNECTION_CLASS (nm_ifcfg_connection_parent_class)->commit_changes (connection, callback, user_data);
	} else {
		/* Otherwise immediate error */
		callback (connection, error, user_data);
		g_error_free (error);
	}
}

static void
do_delete (NMSettingsConnection *connection,
	       NMSettingsConnectionDeleteFunc callback,
	       gpointer user_data)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (connection);
	const char *filename;

	filename = nm_settings_connection_get_filename (connection);
	if (filename) {
		g_unlink (filename);
		if (priv->keyfile)
			g_unlink (priv->keyfile);
		if (priv->routefile)
			g_unlink (priv->routefile);
		if (priv->route6file)
			g_unlink (priv->route6file);
	}

	NM_SETTINGS_CONNECTION_CLASS (nm_ifcfg_connection_parent_class)->delete (connection, callback, user_data);
}

/* GObject */

static void
nm_ifcfg_connection_init (NMIfcfgConnection *connection)
{
	g_signal_connect (connection, "notify::" NM_SETTINGS_CONNECTION_FILENAME,
	                  G_CALLBACK (filename_changed), NULL);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_UNMANAGED_SPEC:
		priv->unmanaged_spec = g_value_dup_string (value);
		break;
	case PROP_UNRECOGNIZED_SPEC:
		priv->unrecognized_spec = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_UNMANAGED_SPEC:
		g_value_set_string (value, priv->unmanaged_spec);
		break;
	case PROP_UNRECOGNIZED_SPEC:
		g_value_set_string (value, priv->unrecognized_spec);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	path_watch_stop (NM_IFCFG_CONNECTION (object));

	G_OBJECT_CLASS (nm_ifcfg_connection_parent_class)->dispose (object);
}

static void
nm_ifcfg_connection_class_init (NMIfcfgConnectionClass *ifcfg_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ifcfg_connection_class);
	NMSettingsConnectionClass *settings_class = NM_SETTINGS_CONNECTION_CLASS (ifcfg_connection_class);

	g_type_class_add_private (ifcfg_connection_class, sizeof (NMIfcfgConnectionPrivate));

	/* Virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose      = dispose;
	settings_class->delete = do_delete;
	settings_class->replace_and_commit = replace_and_commit;
	settings_class->commit_changes = commit_changes;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_UNMANAGED_SPEC,
		 g_param_spec_string (NM_IFCFG_CONNECTION_UNMANAGED_SPEC, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_UNRECOGNIZED_SPEC,
		 g_param_spec_string (NM_IFCFG_CONNECTION_UNRECOGNIZED_SPEC, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	signals[IFCFG_CHANGED] =
		g_signal_new ("ifcfg-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              0, NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);
}

