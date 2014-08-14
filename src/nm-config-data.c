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

#include <glib/gi18n.h>

#include "gsystem-local-alloc.h"

#include "nm-config-data.h"
#include "nm-logging.h"

typedef struct {
	struct {
		char *uri;
		char *response;
		guint interval;
	} connectivity;

	struct {
		char *level;
		char *domains;
	} log;

	char **plugins;
	gboolean monitor_connection_files;
	char *dhcp_client;
	char *dns_mode;

	char *debug;
} NMConfigDataPrivate;


enum {
	PROP_0,
	PROP_PLUGINS,
	PROP_MONITOR_CONNECTION_FILES,
	PROP_DHCP_CLIENT,
	PROP_DNS_MODE,
	PROP_DEBUG,
	PROP_LOG_LEVEL,
	PROP_LOG_DOMAINS,
	PROP_CONNECTIVITY_URI,
	PROP_CONNECTIVITY_INTERVAL,
	PROP_CONNECTIVITY_RESPONSE,

	LAST_PROP
};

G_DEFINE_TYPE (NMConfigData, nm_config_data, G_TYPE_OBJECT)

#define NM_CONFIG_DATA_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CONFIG_DATA, NMConfigDataPrivate))

/************************************************************************/

const char *
nm_config_data_get_connectivity_uri (NMConfigData *self)
{
	g_return_val_if_fail (self, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->connectivity.uri;
}

const guint
nm_config_data_get_connectivity_interval (NMConfigData *self)
{
	g_return_val_if_fail (self, 0);

	return MAX (NM_CONFIG_DATA_GET_PRIVATE (self)->connectivity.interval, 0);
}

const char *
nm_config_data_get_connectivity_response (NMConfigData *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->connectivity.response;
}

const char **
nm_config_data_get_plugins (NMConfigData *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return (const char **) NM_CONFIG_DATA_GET_PRIVATE (self)->plugins;
}

gboolean
nm_config_data_get_monitor_connection_files (NMConfigData *self)
{
	g_return_val_if_fail (self != NULL, FALSE);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->monitor_connection_files;
}

const char *
nm_config_data_get_dhcp_client (NMConfigData *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->dhcp_client;
}

const char *
nm_config_data_get_dns_mode (NMConfigData *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->dns_mode;
}

const char *
nm_config_data_get_log_level (NMConfigData *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->log.level;
}

const char *
nm_config_data_get_log_domains (NMConfigData *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->log.domains;
}

const char *
nm_config_data_get_debug (NMConfigData *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->debug;
}

/************************************************************************/

static char *cli_plugins;
static char *cli_connectivity_uri;
static int cli_connectivity_interval = -1;
static char *cli_connectivity_response;
static gboolean cli_debug;

static GOptionEntry config_options[] = {
	{ "plugins", 0, 0, G_OPTION_ARG_STRING, &cli_plugins, N_("List of plugins separated by ','"), N_("plugin1,plugin2") },
	{ "debug", 'd', 0, G_OPTION_ARG_NONE, &cli_debug, N_("Don't become a daemon, and log to stderr"), NULL },

	/* These three are hidden for now, and should eventually just go away. */
	{ "connectivity-uri", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &cli_connectivity_uri, N_("An http(s) address for checking internet connectivity"), "http://example.com" },
	{ "connectivity-interval", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_INT, &cli_connectivity_interval, N_("The interval between connectivity checks (in seconds)"), "60" },
	{ "connectivity-response", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &cli_connectivity_response, N_("The expected start of the response"), N_("Bingo!") },
	{NULL}
};

GOptionEntry *
nm_config_data_get_options (void)
{
	return config_options;
}

#define IGNORE_EMPTY(s) (s && s[0] ? s : NULL)

NMConfigData *
nm_config_data_new_cli (const char *cli_log_level,
                        const char *cli_log_domains,
                        GError **error)
{
	gs_strfreev char **plugins = NULL;

	if (cli_plugins && cli_plugins[0])
		plugins = g_strsplit (cli_plugins, ",", -1);

	return g_object_new (NM_TYPE_CONFIG_DATA,
	                     NM_CONFIG_DATA_PLUGINS,               plugins,
	                     NM_CONFIG_DATA_DEBUG,                 cli_debug ? "debug" : NULL,
	                     NM_CONFIG_DATA_LOG_LEVEL,             IGNORE_EMPTY (cli_log_level),
	                     NM_CONFIG_DATA_LOG_DOMAINS,           IGNORE_EMPTY (cli_log_domains),
	                     NM_CONFIG_DATA_CONNECTIVITY_URI,      IGNORE_EMPTY (cli_connectivity_uri),
	                     NM_CONFIG_DATA_CONNECTIVITY_INTERVAL, cli_connectivity_interval,
	                     NM_CONFIG_DATA_CONNECTIVITY_RESPONSE, IGNORE_EMPTY (cli_connectivity_response),
	                     NULL);
}

NMConfigData *
nm_config_data_new_keyfile (GKeyFile *keyfile,
                            NMConfigData *override,
                            GError **error)
{
	NMConfigData *self;
	char **plugins = NULL;
	char *dhcp_client = NULL, *dns_mode = NULL, *debug = NULL;
	char *con_uri = NULL, *con_response = NULL, *log_level = NULL, *log_domains = NULL;
	gboolean monitor_connection_files = FALSE;
	guint con_interval = 0;
	char *value;

	if (nm_config_data_get_plugins (override))
		plugins = g_strdupv ((gchar **) nm_config_data_get_plugins (override));
	else
		plugins = g_key_file_get_string_list (keyfile, "main", "plugins", NULL, NULL);

	monitor_connection_files = nm_config_data_get_monitor_connection_files (override);
	if (!monitor_connection_files) {
		value = g_key_file_get_value (keyfile, "main", "monitor-connection-files", NULL);
		if (value) {
			if (!strcmp (value, "true") || !strcmp (value, "yes") || !strcmp (value, "on"))
				monitor_connection_files = TRUE;
			else if (!strcmp (value, "false") || !strcmp (value, "no") || !strcmp (value, "off"))
				monitor_connection_files = FALSE;
			else
				nm_log_warn (LOGD_CORE, "Unrecognized value for main.monitor-connection-files: %s. Assuming 'false'", value);
			g_free (value);
		}
	}

	if (nm_config_data_get_dhcp_client (override))
		dhcp_client = g_strdup (nm_config_data_get_dhcp_client (override));
	else
		dhcp_client = g_key_file_get_value (keyfile, "main", "dhcp", NULL);

	if (nm_config_data_get_dhcp_client (override))
		dns_mode = g_strdup (nm_config_data_get_dns_mode (override));
	else
		dns_mode = g_key_file_get_value (keyfile, "main", "dns", NULL);

	if (nm_config_data_get_debug (override))
		debug = g_strdup (nm_config_data_get_debug (override));
	else
		debug = g_key_file_get_value (keyfile, "main", "debug", NULL);

	if (nm_config_data_get_log_level (override))
		log_level = g_strdup (nm_config_data_get_log_level (override));
	else
		log_level = g_key_file_get_value (keyfile, "logging", "level", NULL);

	if (nm_config_data_get_log_domains (override))
		log_domains = g_strdup (nm_config_data_get_log_domains (override));
	else
		log_domains = g_key_file_get_value (keyfile, "logging", "domains", NULL);

	if (nm_config_data_get_connectivity_uri (override))
		con_uri = g_strdup (nm_config_data_get_connectivity_uri (override));
	else
		con_uri = g_key_file_get_value (keyfile, "connectivity", "uri", NULL);

	con_interval = nm_config_data_get_connectivity_interval (override);
	if (!con_interval)
		con_interval = (guint) g_key_file_get_integer (keyfile, "connectivity", "interval", NULL);\
	con_interval = CLAMP (con_interval, 0, G_MAXINT32);

	if (nm_config_data_get_connectivity_response (override))
		con_response = g_strdup (nm_config_data_get_connectivity_response (override));
	else
		con_response = g_key_file_get_value (keyfile, "connectivity", "response", NULL);

	self = g_object_new (NM_TYPE_CONFIG_DATA,
	                     NM_CONFIG_DATA_PLUGINS,               plugins,
	                     NM_CONFIG_DATA_DHCP_CLIENT,           IGNORE_EMPTY (dhcp_client),
	                     NM_CONFIG_DATA_DNS_MODE,              IGNORE_EMPTY (dns_mode),
	                     NM_CONFIG_DATA_DEBUG,                 IGNORE_EMPTY (debug),
	                     NM_CONFIG_DATA_LOG_LEVEL,             IGNORE_EMPTY (log_level),
	                     NM_CONFIG_DATA_LOG_DOMAINS,           IGNORE_EMPTY (log_domains),
	                     NM_CONFIG_DATA_CONNECTIVITY_URI,      IGNORE_EMPTY (con_uri),
	                     NM_CONFIG_DATA_CONNECTIVITY_INTERVAL, con_interval,
	                     NM_CONFIG_DATA_CONNECTIVITY_RESPONSE, IGNORE_EMPTY (con_response),
	                     NULL);

	g_strfreev (plugins);
	g_free (dhcp_client);
	g_free (dns_mode);
	g_free (debug);
	g_free (con_uri);
	g_free (con_response);
	return self;
}

/************************************************************************/

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMConfigData *self = NM_CONFIG_DATA (object);

	switch (prop_id) {
	case PROP_PLUGINS:
		g_value_set_boxed (value, nm_config_data_get_plugins (self));
		break;
	case PROP_MONITOR_CONNECTION_FILES:
		g_value_set_boolean (value, nm_config_data_get_monitor_connection_files (self));
		break;
	case PROP_DHCP_CLIENT:
		g_value_set_string (value, nm_config_data_get_dhcp_client (self));
		break;
	case PROP_DNS_MODE:
		g_value_set_string (value, nm_config_data_get_dns_mode (self));
		break;
	case PROP_DEBUG:
		g_value_set_string (value, nm_config_data_get_debug (self));
		break;
	case PROP_LOG_LEVEL:
		g_value_set_string (value, nm_config_data_get_log_level (self));
		break;
	case PROP_LOG_DOMAINS:
		g_value_set_string (value, nm_config_data_get_log_domains (self));
		break;
	case PROP_CONNECTIVITY_URI:
		g_value_set_string (value, nm_config_data_get_connectivity_uri (self));
		break;
	case PROP_CONNECTIVITY_INTERVAL:
		g_value_set_uint (value, nm_config_data_get_connectivity_interval (self));
		break;
	case PROP_CONNECTIVITY_RESPONSE:
		g_value_set_string (value, nm_config_data_get_connectivity_response (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	NMConfigData *self = NM_CONFIG_DATA (object);
	NMConfigDataPrivate *priv = NM_CONFIG_DATA_GET_PRIVATE (self);

	/* This type is immutable. All properties are construct only. */
	switch (prop_id) {
	case PROP_PLUGINS:
		priv->plugins = g_value_dup_boxed (value);
		break;
	case PROP_MONITOR_CONNECTION_FILES:
		priv->monitor_connection_files = g_value_get_boolean (value);
		break;
	case PROP_DHCP_CLIENT:
		priv->dhcp_client = g_value_dup_string (value);
		break;
	case PROP_DNS_MODE:
		priv->dns_mode = g_value_dup_string (value);
		break;
	case PROP_DEBUG:
		priv->debug = g_value_dup_string (value);
		break;
	case PROP_LOG_LEVEL:
		priv->log.level = g_value_dup_string (value);
		break;
	case PROP_LOG_DOMAINS:
		priv->log.domains = g_value_dup_string (value);
		break;
	case PROP_CONNECTIVITY_URI:
		priv->connectivity.uri = g_value_dup_string (value);
		break;
	case PROP_CONNECTIVITY_INTERVAL:
		priv->connectivity.interval = g_value_get_uint (value);
		break;
	case PROP_CONNECTIVITY_RESPONSE:
		priv->connectivity.response = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *gobject)
{
	NMConfigDataPrivate *priv = NM_CONFIG_DATA_GET_PRIVATE (gobject);

	g_free (priv->connectivity.uri);
	g_free (priv->connectivity.response);
	g_free (priv->log.level);
	g_free (priv->log.domains);
	g_clear_pointer (&priv->plugins, g_strfreev);
	g_free (priv->dhcp_client);
	g_free (priv->dns_mode);
	g_free (priv->debug);

	G_OBJECT_CLASS (nm_config_data_parent_class)->finalize (gobject);
}

static void
nm_config_data_init (NMConfigData *self)
{
}

static void
nm_config_data_class_init (NMConfigDataClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMConfigDataPrivate));

	object_class->finalize = finalize;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	g_object_class_install_property
	    (object_class, PROP_PLUGINS,
	     g_param_spec_boxed (NM_CONFIG_DATA_PLUGINS, "", "",
	                         G_TYPE_STRV,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_MONITOR_CONNECTION_FILES,
	     g_param_spec_boolean (NM_CONFIG_DATA_MONITOR_CONNECTION_FILES, "", "",
	                           FALSE,
	                           G_PARAM_READWRITE |
	                           G_PARAM_CONSTRUCT_ONLY |
	                           G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_DHCP_CLIENT,
	     g_param_spec_string (NM_CONFIG_DATA_DHCP_CLIENT, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_DNS_MODE,
	     g_param_spec_string (NM_CONFIG_DATA_DNS_MODE, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_DEBUG,
	     g_param_spec_string (NM_CONFIG_DATA_DEBUG, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_LOG_LEVEL,
	     g_param_spec_string (NM_CONFIG_DATA_LOG_LEVEL, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_LOG_DOMAINS,
	     g_param_spec_string (NM_CONFIG_DATA_LOG_DOMAINS, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_CONNECTIVITY_URI,
	     g_param_spec_string (NM_CONFIG_DATA_CONNECTIVITY_URI, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_CONNECTIVITY_INTERVAL,
	     g_param_spec_uint (NM_CONFIG_DATA_CONNECTIVITY_INTERVAL, "", "",
	                        0, G_MAXUINT, 0,
	                        G_PARAM_READWRITE |
	                        G_PARAM_CONSTRUCT_ONLY |
	                        G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_CONNECTIVITY_RESPONSE,
	     g_param_spec_string (NM_CONFIG_DATA_CONNECTIVITY_RESPONSE, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

}

