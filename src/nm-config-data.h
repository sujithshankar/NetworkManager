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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef NM_CONFIG_DATA_H
#define NM_CONFIG_DATA_H

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define NM_TYPE_CONFIG_DATA            (nm_config_data_get_type ())
#define NM_CONFIG_DATA(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONFIG_DATA, NMConfigData))
#define NM_CONFIG_DATA_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_CONFIG_DATA, NMConfigDataClass))
#define NM_IS_CONFIG_DATA(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONFIG_DATA))
#define NM_IS_CONFIG_DATA_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_CONFIG_DATA))
#define NM_CONFIG_DATA_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_CONFIG_DATA, NMConfigDataClass))

#define NM_CONFIG_DATA_PLUGINS                  "plugins"
#define NM_CONFIG_DATA_MONITOR_CONNECTION_FILES "monitor-connection-files"
#define NM_CONFIG_DATA_DHCP_CLIENT              "dhcp-client"
#define NM_CONFIG_DATA_DNS_MODE                 "dns-mode"
#define NM_CONFIG_DATA_DEBUG                    "debug"
#define NM_CONFIG_DATA_LOG_LEVEL                "log-level"
#define NM_CONFIG_DATA_LOG_DOMAINS              "log-domains"
#define NM_CONFIG_DATA_CONNECTIVITY_URI         "connectivity-uri"
#define NM_CONFIG_DATA_CONNECTIVITY_INTERVAL    "connectivity-interval"
#define NM_CONFIG_DATA_CONNECTIVITY_RESPONSE    "connectivity-response"

typedef struct {
	GObject parent;
} NMConfigData;

typedef struct {
	GObjectClass parent;
} NMConfigDataClass;

GType nm_config_data_get_type (void);

const char **nm_config_data_get_plugins                  (NMConfigData *self);
gboolean     nm_config_data_get_monitor_connection_files (NMConfigData *self);
const char * nm_config_data_get_dhcp_client              (NMConfigData *self);
const char * nm_config_data_get_dns_mode                 (NMConfigData *self);
const char * nm_config_data_get_log_level                (NMConfigData *self);
const char * nm_config_data_get_log_domains              (NMConfigData *self);
const char * nm_config_data_get_debug                    (NMConfigData *self);

const char * nm_config_data_get_connectivity_uri         (NMConfigData *self);
const guint  nm_config_data_get_connectivity_interval    (NMConfigData *self);
const char * nm_config_data_get_connectivity_response    (NMConfigData *self);

/* for main.c only */
GOptionEntry *nm_config_data_get_options (void);

NMConfigData *nm_config_data_new_cli (const char *cli_log_level,
                                      const char *cli_log_domains,
                                      GError **error);
NMConfigData *nm_config_data_new_keyfile (GKeyFile *keyfile,
                                          NMConfigData *override,
                                          GError **error);

G_END_DECLS

#endif /* NM_CONFIG_DATA_H */

