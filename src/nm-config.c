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
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2013 Thomas Bechtold <thomasbechtold@jpberlin.de>
 */

#include <config.h>
#include <string.h>
#include <stdio.h>

#include "nm-config.h"
#include "nm-logging.h"
#include "nm-utils.h"
#include "nm-glib-compat.h"
#include "nm-device.h"
#include "NetworkManagerUtils.h"

#include <gio/gio.h>
#include <glib/gi18n.h>

#define NM_DEFAULT_SYSTEM_CONF_FILE    NMCONFDIR "/NetworkManager.conf"
#define NM_DEFAULT_SYSTEM_CONF_DIR     NMCONFDIR "/conf.d"
#define NM_OLD_SYSTEM_CONF_FILE        NMCONFDIR "/nm-system-settings.conf"
#define NM_NO_AUTO_DEFAULT_STATE_FILE  NMSTATEDIR "/no-auto-default.state"

typedef struct {
	char *nm_conf_path;
	char *config_dir;
	char *config_description;
	char *no_auto_default_file;
	GKeyFile *keyfile;

	char **no_auto_default;
	char **ignore_carrier;

	/* Config from CLI, never changes */
	NMConfigData *cli_data;

	/* Changes when configuration is reloaded */
	NMConfigData *config_data;
} NMConfigPrivate;

enum {
	SIGNAL_CONFIG_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static NMConfig *singleton = NULL;

G_DEFINE_TYPE (NMConfig, nm_config, G_TYPE_OBJECT)

#define NM_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CONFIG, NMConfigPrivate))

/************************************************************************/

const char *
nm_config_get_path (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->nm_conf_path;
}

const char *
nm_config_get_description (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->config_description;
}

const char **
nm_config_get_plugins (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return nm_config_data_get_plugins (NM_CONFIG_GET_PRIVATE (config)->config_data);
}

gboolean
nm_config_get_monitor_connection_files (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, FALSE);

	return nm_config_data_get_monitor_connection_files (NM_CONFIG_GET_PRIVATE (config)->config_data);
}

const char *
nm_config_get_dhcp_client (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return nm_config_data_get_dhcp_client (NM_CONFIG_GET_PRIVATE (config)->config_data);
}

const char *
nm_config_get_dns_mode (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return nm_config_data_get_dns_mode (NM_CONFIG_GET_PRIVATE (config)->config_data);
}

const char *
nm_config_get_log_level (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return nm_config_data_get_log_level (NM_CONFIG_GET_PRIVATE (config)->config_data);
}

const char *
nm_config_get_log_domains (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return nm_config_data_get_log_domains (NM_CONFIG_GET_PRIVATE (config)->config_data);
}

const char *
nm_config_get_debug (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return nm_config_data_get_debug (NM_CONFIG_GET_PRIVATE (config)->config_data);
}

const char *
nm_config_get_connectivity_uri (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return nm_config_data_get_connectivity_uri (NM_CONFIG_GET_PRIVATE (config)->config_data);
}

guint
nm_config_get_connectivity_interval (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return nm_config_data_get_connectivity_interval (NM_CONFIG_GET_PRIVATE (config)->config_data);
}

const char *
nm_config_get_connectivity_response (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return nm_config_data_get_connectivity_response (NM_CONFIG_GET_PRIVATE (config)->config_data);
}

char *
nm_config_get_value (NMConfig *config, const char *group, const char *key, GError **error)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);

	return g_key_file_get_string (priv->keyfile, group, key, error);
}

gboolean
nm_config_get_ignore_carrier (NMConfig *config, NMDevice *device)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);
	GSList *specs = NULL;
	int i;
	gboolean match;

	if (!priv->ignore_carrier)
		return FALSE;

	for (i = 0; priv->ignore_carrier[i]; i++)
		specs = g_slist_prepend (specs, priv->ignore_carrier[i]);

	match = nm_device_spec_match_list (device, specs);

	g_slist_free (specs);
	return match;
}

/************************************************************************/

static void
merge_no_auto_default_state (NMConfig *config)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);
	GPtrArray *updated;
	char **list;
	int i, j;
	char *data;

	/* If the config already matches everything, we don't need to do anything else. */
	if (priv->no_auto_default && !g_strcmp0 (priv->no_auto_default[0], "*"))
		return;

	updated = g_ptr_array_new ();
	if (priv->no_auto_default) {
		for (i = 0; priv->no_auto_default[i]; i++)
			g_ptr_array_add (updated, priv->no_auto_default[i]);
		g_free (priv->no_auto_default);
	}

	if (g_file_get_contents (priv->no_auto_default_file, &data, NULL, NULL)) {
		list = g_strsplit (data, "\n", -1);
		for (i = 0; list[i]; i++) {
			if (!*list[i])
				continue;
			for (j = 0; j < updated->len; j++) {
				if (!strcmp (list[i], updated->pdata[j]))
					break;
			}
			if (j == updated->len)
				g_ptr_array_add (updated, list[i]);
		}
		g_free (list);
		g_free (data);
	}

	g_ptr_array_add (updated, NULL);
	priv->no_auto_default = (char **) g_ptr_array_free (updated, FALSE);
}

gboolean
nm_config_get_ethernet_can_auto_default (NMConfig *config, NMDevice *device)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);
	GSList *specs = NULL;
	int i;
	gboolean match;

	for (i = 0; priv->no_auto_default[i]; i++)
		specs = g_slist_prepend (specs, priv->no_auto_default[i]);

	match = nm_device_spec_match_list (device, specs);

	g_slist_free (specs);
	return !match;
}

void
nm_config_set_ethernet_no_auto_default (NMConfig *config, NMDevice *device)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);
	char *current;
	GString *updated;
	GError *error = NULL;

	if (!nm_config_get_ethernet_can_auto_default (config, device))
		return;

	updated = g_string_new (NULL);
	if (g_file_get_contents (priv->no_auto_default_file, &current, NULL, NULL)) {
		g_string_append (updated, current);
		g_free (current);
		if (updated->str[updated->len - 1] != '\n')
			g_string_append_c (updated, '\n');
	}

	g_string_append (updated, nm_device_get_hw_address (device));
	g_string_append_c (updated, '\n');

	if (!g_file_set_contents (priv->no_auto_default_file, updated->str, updated->len, &error)) {
		nm_log_warn (LOGD_SETTINGS, "Could not update no-auto-default.state file: %s",
		             error->message);
		g_error_free (error);
	}

	g_string_free (updated, TRUE);

	merge_no_auto_default_state (config);
}

/************************************************************************/

static char *cli_config_path;
static char *cli_config_dir;
static char *cli_no_auto_default_file;

static GOptionEntry config_options[] = {
	{ "config", 0, 0, G_OPTION_ARG_FILENAME, &cli_config_path, N_("Config file location"), N_("/path/to/config.file") },
	{ "config-dir", 0, 0, G_OPTION_ARG_FILENAME, &cli_config_dir, N_("Config directory location"), N_("/path/to/config/dir") },
	{ "no-auto-default", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_FILENAME, &cli_no_auto_default_file, "no-auto-default.state location", NULL },
	{NULL}
};

GOptionEntry *
nm_config_get_options (void)
{
	return config_options;
}

/************************************************************************/

static gboolean
read_config (GKeyFile *keyfile, const char *path, GError **error)
{
	GKeyFile *kf;
	char **groups, **keys;
	gsize ngroups, nkeys;
	int g, k;

	if (g_file_test (path, G_FILE_TEST_EXISTS) == FALSE) {
		g_set_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND, "file %s not found", path);
		return FALSE;
	}

	nm_log_dbg (LOGD_SETTINGS, "Reading config file '%s'", path);

	kf = g_key_file_new ();
	g_key_file_set_list_separator (kf, ',');
	if (!g_key_file_load_from_file (kf, path, G_KEY_FILE_NONE, error)) {
		g_key_file_free (kf);
		return FALSE;
	}

	/* Override the current settings with the new ones */
	groups = g_key_file_get_groups (kf, &ngroups);
	for (g = 0; groups[g]; g++) {
		keys = g_key_file_get_keys (kf, groups[g], &nkeys, NULL);
		if (!keys)
			continue;
		for (k = 0; keys[k]; k++) {
			int len = strlen (keys[k]);
			if (keys[k][len - 1] == '+') {
				char *base_key = g_strndup (keys[k], len - 1);
				const char *old_val = g_key_file_get_value (keyfile, groups[g], base_key, NULL);
				const char *new_val = g_key_file_get_value (kf, groups[g], keys[k], NULL);

				if (old_val && *old_val) {
					char *combined = g_strconcat (old_val, ",", new_val, NULL);

					g_key_file_set_value (keyfile, groups[g], base_key, combined);
					g_free (combined);
				} else
					g_key_file_set_value (keyfile, groups[g], base_key, new_val);

				g_free (base_key);
				continue;
			}

			g_key_file_set_value (keyfile, groups[g], keys[k],
			                      g_key_file_get_value (kf, groups[g], keys[k], NULL));
		}
	}
	g_key_file_free (kf);

	return TRUE;
}

static gboolean
find_base_config (NMConfig *config, GError **error)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);
	GError *my_error = NULL;

	/* Try a user-specified config file first */
	if (cli_config_path) {
		/* Bad user-specific config file path is a hard error */
		if (read_config (priv->keyfile, cli_config_path, error)) {
			priv->nm_conf_path = g_strdup (cli_config_path);
			return TRUE;
		} else
			return FALSE;
	}

	/* Even though we prefer NetworkManager.conf, we need to check the
	 * old nm-system-settings.conf first to preserve compat with older
	 * setups.  In package managed systems dropping a NetworkManager.conf
	 * onto the system would make NM use it instead of nm-system-settings.conf,
	 * changing behavior during an upgrade.  We don't want that.
	 */

	/* Try deprecated nm-system-settings.conf first */
	if (read_config (priv->keyfile, NM_OLD_SYSTEM_CONF_FILE, &my_error)) {
		priv->nm_conf_path = g_strdup (NM_OLD_SYSTEM_CONF_FILE);
		return TRUE;
	}

	if (!g_error_matches (my_error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND)) {
		nm_log_warn (LOGD_CORE, "Old default config file %s invalid: %s\n",
		             NM_OLD_SYSTEM_CONF_FILE,
		             my_error->message);
	}
	g_clear_error (&my_error);

	/* Try the standard config file location next */
	if (read_config (priv->keyfile, NM_DEFAULT_SYSTEM_CONF_FILE, &my_error)) {
		priv->nm_conf_path = g_strdup (NM_DEFAULT_SYSTEM_CONF_FILE);
		return TRUE;
	}

	if (!g_error_matches (my_error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND)) {
		nm_log_warn (LOGD_CORE, "Default config file %s invalid: %s\n",
		             NM_DEFAULT_SYSTEM_CONF_FILE,
		             my_error->message);
		g_propagate_error (error, my_error);
		return FALSE;
	}
	g_clear_error (&my_error);

	/* If for some reason no config file exists, use the default
	 * config file path.
	 */
	priv->nm_conf_path = g_strdup (NM_DEFAULT_SYSTEM_CONF_FILE);
	nm_log_info (LOGD_CORE, "No config file found or given; using %s\n",
	             NM_DEFAULT_SYSTEM_CONF_FILE);
	return TRUE;
}

/************************************************************************/

static int
sort_asciibetically (gconstpointer a, gconstpointer b)
{
	const char *s1 = *(const char **)a;
	const char *s2 = *(const char **)b;

	return strcmp (s1, s2);
}

/* Updates keyfile with new merged values from config files */
static gboolean
reload_config_files (GKeyFile *keyfile,
                     const char *conf_path,
                     const char *config_dir,
                     char **out_config_description,
                     GError **error)
{
	GFile *dir;
	GFileEnumerator *direnum;
	GFileInfo *info;
	GPtrArray *confs;
	const char *name;
	int i;
	GString *config_description;
	gboolean success = TRUE;

	confs = g_ptr_array_new_with_free_func (g_free);
	config_description = g_string_new (conf_path);
	dir = g_file_new_for_path (config_dir);
	direnum = g_file_enumerate_children (dir, G_FILE_ATTRIBUTE_STANDARD_NAME, 0, NULL, NULL);
	if (direnum) {
		while ((info = g_file_enumerator_next_file (direnum, NULL, NULL))) {
			name = g_file_info_get_name (info);
			if (g_str_has_suffix (name, ".conf")) {
				g_ptr_array_add (confs, g_build_filename (config_dir, name, NULL));
				if (confs->len == 1)
					g_string_append (config_description, " and conf.d: ");
				else
					g_string_append (config_description, ", ");
				g_string_append (config_description, name);
			}
			g_object_unref (info);
		}
		g_object_unref (direnum);
	}
	g_object_unref (dir);

	g_ptr_array_sort (confs, sort_asciibetically);
	if (out_config_description)
		*out_config_description = g_string_free (config_description, FALSE);
	else
		g_string_free (config_description, TRUE);

	for (i = 0; i < confs->len; i++) {
		if (!read_config (keyfile, confs->pdata[i], error)) {
			success = FALSE;
			break;
		}
	}
	g_ptr_array_unref (confs);
	return success;
}

void
nm_config_reload (NMConfig *self)
{
	NMConfigPrivate *priv;
	GError *error = NULL;
	GHashTable *changes;
	NMConfigData *new_data = NULL;
	GKeyFile *new_kf;
	char *config_desc = NULL;

	g_return_if_fail (NM_IS_CONFIG (self));

	priv = NM_CONFIG_GET_PRIVATE (self);

	new_kf = g_key_file_new ();
	g_key_file_set_list_separator (new_kf, ',');
	if (!reload_config_files (new_kf,
	                          priv->nm_conf_path,
	                          priv->config_dir,
	                          &config_desc,
	                          &error))
		goto fail;

	new_data = nm_config_data_new_keyfile (new_kf, priv->cli_data, &error);
	if (!new_data)
		goto fail;

	changes = nm_config_data_diff (priv->config_data, new_data);
	if (g_hash_table_size (changes)) {
		NMConfigData *old_data = priv->config_data;

		g_object_unref (priv->keyfile);
		priv->keyfile = new_kf;
		g_free (priv->config_description);
		priv->config_description = config_desc;

		priv->config_data = new_data;
		g_signal_emit (self, signals[SIGNAL_CONFIG_CHANGED], 0, changes, old_data);
		g_object_unref (old_data);
	} else {
		g_key_file_unref (new_kf);
		g_object_unref (new_data);
		g_free (config_desc);
	}
	g_hash_table_destroy (changes);
	return;

fail:
	if (error) {
		nm_log_warn (LOGD_SETTINGS, "failed to read configuation: (%s) %s",
		             g_quark_to_string (error->domain), error->message);
		g_error_free (error);
	}
	g_key_file_unref (new_kf);
	g_free (config_desc);
}

/* call this function only once! */
NMConfig *
nm_config_new (const char *cli_log_level,
               const char *cli_log_domains,
               GError **error)
{
	NMConfigPrivate *priv;

	g_assert (!singleton);
	singleton = NM_CONFIG (g_object_new (NM_TYPE_CONFIG, NULL));
	priv = NM_CONFIG_GET_PRIVATE (singleton);

	/* First read the base config file */
	if (!find_base_config (singleton, error))
		goto fail;

	/* Read command-line overrides */
	priv->cli_data = nm_config_data_new_cli (cli_log_level, cli_log_domains, error);
	if (!priv->cli_data)
		goto fail;

	/* Now read the overrides in the config dir */
	if (cli_config_dir)
		priv->config_dir = g_strdup (cli_config_dir);
	else
		priv->config_dir = g_strdup (NM_DEFAULT_SYSTEM_CONF_DIR);

	if (!reload_config_files (priv->keyfile,
	                          priv->nm_conf_path,
	                          priv->config_dir,
	                          &priv->config_description,
	                          error))
		goto fail;

	priv->config_data = nm_config_data_new_keyfile (priv->keyfile,
	                                                priv->cli_data,
	                                                error);
	if (!priv->config_data)
		goto fail;

	/* Handle no-auto-default key and state file */
	priv->no_auto_default = g_key_file_get_string_list (priv->keyfile, "main", "no-auto-default", NULL, NULL);
	if (cli_no_auto_default_file)
		priv->no_auto_default_file = g_strdup (cli_no_auto_default_file);
	else
		priv->no_auto_default_file = g_strdup (NM_NO_AUTO_DEFAULT_STATE_FILE);
	merge_no_auto_default_state (singleton);

	priv->ignore_carrier = g_key_file_get_string_list (priv->keyfile, "main", "ignore-carrier", NULL, NULL);

	return singleton;

fail:
	g_object_unref (singleton);
	singleton = NULL;
	return NULL;
}

NMConfig *
nm_config_get (void)
{
	g_assert (singleton);
	return singleton;
}

static void
nm_config_init (NMConfig *config)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);

	priv->keyfile = g_key_file_new ();
	g_key_file_set_list_separator (priv->keyfile, ',');
}

static void
dispose (GObject *gobject)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (gobject);

	g_clear_object (&priv->cli_data);
	g_clear_object (&priv->config_data);

	G_OBJECT_CLASS (nm_config_parent_class)->dispose (gobject);
}

static void
finalize (GObject *gobject)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (gobject);

	g_free (priv->nm_conf_path);
	g_free (priv->config_dir);
	g_free (priv->config_description);
	g_free (priv->no_auto_default_file);
	g_clear_pointer (&priv->keyfile, g_key_file_unref);
	g_strfreev (priv->no_auto_default);
	g_strfreev (priv->ignore_carrier);
	g_clear_pointer (&cli_config_path, g_free);
	g_clear_pointer (&cli_config_dir, g_free);
	g_clear_pointer (&cli_no_auto_default_file, g_free);

	singleton = NULL;

	G_OBJECT_CLASS (nm_config_parent_class)->finalize (gobject);
}


static void
nm_config_class_init (NMConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMConfigPrivate));
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	signals[SIGNAL_CONFIG_CHANGED] =
	    g_signal_new (NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  G_STRUCT_OFFSET (NMConfigClass, config_changed),
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_HASH_TABLE, NM_TYPE_CONFIG_DATA);
}

