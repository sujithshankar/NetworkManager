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
 * Copyright (C) 2005 - 2013 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include <glib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>

#include "nm-dbus-interface.h"
#include "nm-vpn-dbus-interface.h"
#include "nm-vpn-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-vpn.h"
#include "nm-setting-ip4-config.h"
#include "nm-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-ip6-config.h"
#include "nm-dbus-manager.h"
#include "nm-platform.h"
#include "nm-logging.h"
#include "nm-utils.h"
#include "nm-active-connection.h"
#include "NetworkManagerUtils.h"
#include "nm-glib-compat.h"
#include "settings/nm-settings-connection.h"
#include "nm-dispatcher.h"
#include "nm-agent-manager.h"

#include "nmdbus-vpn-connection.h"

G_DEFINE_TYPE (NMVpnConnection, nm_vpn_connection, NM_TYPE_ACTIVE_CONNECTION)

typedef enum {
	/* Only system secrets */
	SECRETS_REQ_SYSTEM = 0,
	/* All existing secrets including agent secrets */
	SECRETS_REQ_EXISTING = 1,
	/* New secrets required; ask an agent */
	SECRETS_REQ_NEW = 2,
	/* Plugin requests secrets interactively */
	SECRETS_REQ_INTERACTIVE = 3,
	/* Placeholder for bounds checking */
	SECRETS_REQ_LAST
} SecretsReq;

/* Internal VPN states, private to NMVpnConnection */
typedef enum {
	STATE_UNKNOWN = 0,
	STATE_WAITING,
	STATE_PREPARE,
	STATE_NEED_AUTH,
	STATE_CONNECT,
	STATE_IP_CONFIG_GET,
	STATE_PRE_UP,
	STATE_ACTIVATED,
	STATE_DEACTIVATING,
	STATE_DISCONNECTED,
	STATE_FAILED,
} VpnState;

typedef struct {
	NMConnection *connection;

	guint32 secrets_id;
	SecretsReq secrets_idx;
	char *username;

	VpnState vpn_state;
	guint dispatcher_id;
	NMVpnConnectionStateReason failure_reason;

	GDBusProxy *proxy;
	GVariant *connect_dict;
	guint connect_timeout;
	gboolean has_ip4;
	NMIP4Config *ip4_config;
	guint32 ip4_internal_gw;
	guint32 ip4_external_gw;
	gboolean has_ip6;
	NMIP6Config *ip6_config;
	struct in6_addr *ip6_internal_gw;
	struct in6_addr *ip6_external_gw;
	char *ip_iface;
	int ip_ifindex;
	char *banner;
	guint32 mtu;
} NMVpnConnectionPrivate;

#define NM_VPN_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_CONNECTION, NMVpnConnectionPrivate))

enum {
	VPN_STATE_CHANGED,
	INTERNAL_STATE_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_VPN_STATE,
	PROP_BANNER,
	PROP_IP4_CONFIG,
	PROP_IP6_CONFIG,
	PROP_MASTER = 2000,

	LAST_PROP
};

static void get_secrets (NMVpnConnection *self,
                         SecretsReq secrets_idx,
                         const char **hints);

static void plugin_interactive_secrets_required (NMVpnConnection *connection,
                                                 const char *message,
                                                 const char **secrets);

static void _set_vpn_state (NMVpnConnection *connection,
                            VpnState vpn_state,
                            NMVpnConnectionStateReason reason,
                            gboolean quitting);

/*********************************************************************/

static NMVpnConnectionState
_state_to_nm_vpn_state (VpnState state)
{
	switch (state) {
	case STATE_WAITING:
	case STATE_PREPARE:
		return NM_VPN_CONNECTION_STATE_PREPARE;
	case STATE_NEED_AUTH:
		return NM_VPN_CONNECTION_STATE_NEED_AUTH;
	case STATE_CONNECT:
		return NM_VPN_CONNECTION_STATE_CONNECT;
	case STATE_IP_CONFIG_GET:
	case STATE_PRE_UP:
		return NM_VPN_CONNECTION_STATE_IP_CONFIG_GET;
	case STATE_ACTIVATED:
		return NM_VPN_CONNECTION_STATE_ACTIVATED;
	case STATE_DEACTIVATING: {
		/* Map DEACTIVATING to ACTIVATED to preserve external API behavior,
		 * since our API has no DEACTIVATING state of its own.  Since this can
		 * take some time, and the VPN isn't actually disconnected until it
		 * hits the DISCONNECTED state, to clients it should still appear
		 * connected.
		 */
		return NM_VPN_CONNECTION_STATE_ACTIVATED;
	}
	case STATE_DISCONNECTED:
		return NM_VPN_CONNECTION_STATE_DISCONNECTED;
	case STATE_FAILED:
		return NM_VPN_CONNECTION_STATE_FAILED;
	default:
		return NM_VPN_CONNECTION_STATE_UNKNOWN;
	}
}

static NMActiveConnectionState
_state_to_ac_state (VpnState vpn_state)
{
	/* Set the NMActiveConnection state based on VPN state */
	switch (vpn_state) {
	case STATE_WAITING:
	case STATE_PREPARE:
	case STATE_NEED_AUTH:
	case STATE_CONNECT:
	case STATE_IP_CONFIG_GET:
	case STATE_PRE_UP:
		return NM_ACTIVE_CONNECTION_STATE_ACTIVATING;
	case STATE_ACTIVATED:
		return NM_ACTIVE_CONNECTION_STATE_ACTIVATED;
	case STATE_DEACTIVATING:
		return NM_ACTIVE_CONNECTION_STATE_DEACTIVATING;
	case STATE_DISCONNECTED:
	case STATE_FAILED:
		return NM_ACTIVE_CONNECTION_STATE_DEACTIVATED;
	default:
		break;
	}
	return NM_ACTIVE_CONNECTION_STATE_UNKNOWN;
}

static void
call_plugin_disconnect (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	GError *error = NULL;

	if (priv->proxy) {
		GVariant *ret;

		ret = g_dbus_proxy_call_sync (priv->proxy,
		                              "Disconnect",
		                              NULL,
		                              G_DBUS_CALL_FLAGS_NONE, -1,
		                              NULL, &error);
		if (ret)
			g_variant_unref (ret);
		else {
			nm_log_warn (LOGD_VPN, "error disconnecting VPN: %s", error->message);
			g_error_free (error);
		}

		g_object_unref (priv->proxy);
		priv->proxy = NULL;
	}
}

static void
vpn_cleanup (NMVpnConnection *connection, NMDevice *parent_dev)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	if (priv->ip_ifindex) {
		nm_platform_link_set_down (priv->ip_ifindex);
		nm_platform_route_flush (priv->ip_ifindex);
		nm_platform_address_flush (priv->ip_ifindex);
	}

	nm_device_set_vpn4_config (parent_dev, NULL);
	nm_device_set_vpn6_config (parent_dev, NULL);

	g_free (priv->banner);
	priv->banner = NULL;

	g_free (priv->ip_iface);
	priv->ip_iface = NULL;
	priv->ip_ifindex = 0;

	/* Clear out connection secrets to ensure that the settings service
	 * gets asked for them next time the connection is activated.
	 */
	if (priv->connection)
		nm_connection_clear_secrets (priv->connection);
}

static void
dispatcher_pre_down_done (guint call_id, gpointer user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	priv->dispatcher_id = 0;
	_set_vpn_state (self, STATE_DISCONNECTED, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);
}

static void
dispatcher_pre_up_done (guint call_id, gpointer user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	priv->dispatcher_id = 0;
	_set_vpn_state (self, STATE_ACTIVATED, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);
}

static void
dispatcher_cleanup (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	if (priv->dispatcher_id) {
		nm_dispatcher_call_cancel (priv->dispatcher_id);
		priv->dispatcher_id = 0;
	}
}

static void
_set_vpn_state (NMVpnConnection *connection,
                VpnState vpn_state,
                NMVpnConnectionStateReason reason,
                gboolean quitting)
{
	NMVpnConnectionPrivate *priv;
	VpnState old_vpn_state;
	NMVpnConnectionState new_external_state, old_external_state;
	NMDevice *parent_dev = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (connection));

	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	if (vpn_state == priv->vpn_state)
		return;

	old_vpn_state = priv->vpn_state;
	priv->vpn_state = vpn_state;

	/* The device gets destroyed by active connection when it enters
	 * the deactivated state, so we need to ref it for usage below.
	 */
	if (parent_dev)
		g_object_ref (parent_dev);

	/* Update active connection base class state */
	nm_active_connection_set_state (NM_ACTIVE_CONNECTION (connection),
	                                _state_to_ac_state (vpn_state));

	/* Clear any in-progress secrets request */
	if (priv->secrets_id) {
		nm_settings_connection_cancel_secrets (NM_SETTINGS_CONNECTION (priv->connection), priv->secrets_id);
		priv->secrets_id = 0;
	}

	dispatcher_cleanup (connection);

	/* The connection gets destroyed by the VPN manager when it enters the
	 * disconnected/failed state, but we need to keep it around for a bit
	 * to send out signals and handle the dispatcher.  So ref it.
	 */
	g_object_ref (connection);

	old_external_state = _state_to_nm_vpn_state (old_vpn_state);
	new_external_state = _state_to_nm_vpn_state (priv->vpn_state);
	if (new_external_state != old_external_state) {
		g_signal_emit (connection, signals[VPN_STATE_CHANGED], 0, new_external_state, reason);
		g_signal_emit (connection, signals[INTERNAL_STATE_CHANGED], 0,
		               new_external_state,
		               old_external_state,
		               reason);
		g_object_notify (G_OBJECT (connection), NM_VPN_CONNECTION_VPN_STATE);
	}

	switch (vpn_state) {
	case STATE_NEED_AUTH:
		/* Do nothing; not part of 'default' because we don't want to touch
		 * priv->secrets_req as NEED_AUTH is re-entered during interactive
		 * secrets.
		 */
		break;
	case STATE_PRE_UP:
		if (!nm_dispatcher_call_vpn (DISPATCHER_ACTION_VPN_PRE_UP,
		                             priv->connection,
		                             parent_dev,
		                             priv->ip_iface,
		                             priv->ip4_config,
		                             priv->ip6_config,
		                             dispatcher_pre_up_done,
		                             connection,
		                             &priv->dispatcher_id)) {
			/* Just proceed on errors */
			dispatcher_pre_up_done (0, connection);
		}
		break;
	case STATE_ACTIVATED:
		/* Secrets no longer needed now that we're connected */
		nm_connection_clear_secrets (priv->connection);

		/* Let dispatcher scripts know we're up and running */
		nm_dispatcher_call_vpn (DISPATCHER_ACTION_VPN_UP,
		                        priv->connection,
		                        parent_dev,
		                        priv->ip_iface,
		                        priv->ip4_config,
		                        priv->ip6_config,
		                        NULL,
		                        NULL,
		                        NULL);
		break;
	case STATE_DEACTIVATING:
		if (quitting) {
			nm_dispatcher_call_vpn_sync (DISPATCHER_ACTION_VPN_PRE_DOWN,
			                             priv->connection,
			                             parent_dev,
			                             priv->ip_iface,
			                             priv->ip4_config,
			                             priv->ip6_config);
		} else {
			if (!nm_dispatcher_call_vpn (DISPATCHER_ACTION_VPN_PRE_DOWN,
			                             priv->connection,
			                             parent_dev,
			                             priv->ip_iface,
			                             priv->ip4_config,
			                             priv->ip6_config,
			                             dispatcher_pre_down_done,
			                             connection,
			                             &priv->dispatcher_id)) {
				/* Just proceed on errors */
				dispatcher_pre_down_done (0, connection);
			}
		}
		break;
	case STATE_FAILED:
	case STATE_DISCONNECTED:
		if (   old_vpn_state >= STATE_ACTIVATED
		    && old_vpn_state <= STATE_DEACTIVATING) {
			/* Let dispatcher scripts know we're about to go down */
			if (quitting) {
				nm_dispatcher_call_vpn_sync (DISPATCHER_ACTION_VPN_DOWN,
				                             priv->connection,
				                             parent_dev,
				                             priv->ip_iface,
				                             NULL,
				                             NULL);
			} else {
				nm_dispatcher_call_vpn (DISPATCHER_ACTION_VPN_DOWN,
				                        priv->connection,
				                        parent_dev,
				                        priv->ip_iface,
				                        NULL,
				                        NULL,
				                        NULL,
				                        NULL,
				                        NULL);
			}
		}

		/* Tear down and clean up the connection */
		call_plugin_disconnect (connection);
		vpn_cleanup (connection, parent_dev);
		/* Fall through */
	default:
		priv->secrets_idx = SECRETS_REQ_SYSTEM;
		break;
	}

	g_object_unref (connection);
	if (parent_dev)
		g_object_unref (parent_dev);
}

static void
device_state_changed (NMActiveConnection *active,
                      NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state)
{
	if (new_state <= NM_DEVICE_STATE_DISCONNECTED) {
		_set_vpn_state (NM_VPN_CONNECTION (active),
		                STATE_DISCONNECTED,
		                NM_VPN_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED,
		                FALSE);
	} else if (new_state == NM_DEVICE_STATE_FAILED) {
		_set_vpn_state (NM_VPN_CONNECTION (active),
		                STATE_FAILED,
		                NM_VPN_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED,
		                FALSE);
	}

	/* FIXME: map device DEACTIVATING state to VPN DEACTIVATING state and
	 * block device deactivation on VPN deactivation.
	 */
}

static void
add_ip4_vpn_gateway_route (NMIP4Config *config, NMDevice *parent_device, guint32 vpn_gw)
{
	NMIP4Config *parent_config;
	guint32 parent_gw;
	NMPlatformIP4Route route;

	g_return_if_fail (NM_IS_IP4_CONFIG (config));
	g_return_if_fail (NM_IS_DEVICE (parent_device));
	g_return_if_fail (vpn_gw != 0);

	/* Set up a route to the VPN gateway's public IP address through the default
	 * network device if the VPN gateway is on a different subnet.
	 */

	parent_config = nm_device_get_ip4_config (parent_device);
	g_return_if_fail (parent_config != NULL);
	parent_gw = nm_ip4_config_get_gateway (parent_config);
	if (!parent_gw)
		return;

	memset (&route, 0, sizeof (route));
	route.network = vpn_gw;
	route.plen = 32;
	route.gateway = parent_gw;

	/* If the VPN gateway is in the same subnet as one of the parent device's
	 * IP addresses, don't add the host route to it, but a route through the
	 * parent device.
	 */
	if (nm_ip4_config_destination_is_direct (parent_config, vpn_gw, 32))
		route.gateway = 0;

	route.source = NM_PLATFORM_SOURCE_VPN;
	route.metric = nm_device_get_priority (parent_device);
	nm_ip4_config_add_route (config, &route);

	/* Ensure there's a route to the parent device's gateway through the
	 * parent device, since if the VPN claims the default route and the VPN
	 * routes include a subnet that matches the parent device's subnet,
	 * the parent device's gateway would get routed through the VPN and fail.
	 */
	memset (&route, 0, sizeof (route));
	route.network = parent_gw;
	route.plen = 32;
	route.source = NM_PLATFORM_SOURCE_VPN;
	route.metric = nm_device_get_priority (parent_device);

	nm_ip4_config_add_route (config, &route);
}

static void
add_ip6_vpn_gateway_route (NMIP6Config *config,
                           NMDevice *parent_device,
                           const struct in6_addr *vpn_gw)
{
	NMIP6Config *parent_config;
	const struct in6_addr *parent_gw;
	NMPlatformIP6Route route;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));
	g_return_if_fail (NM_IS_DEVICE (parent_device));
	g_return_if_fail (vpn_gw != NULL);

	parent_config = nm_device_get_ip6_config (parent_device);
	g_return_if_fail (parent_config != NULL);
	parent_gw = nm_ip6_config_get_gateway (parent_config);
	if (!parent_gw)
		return;

	memset (&route, 0, sizeof (route));
	route.network = *vpn_gw;
	route.plen = 128;
	route.gateway = *parent_gw;

	/* If the VPN gateway is in the same subnet as one of the parent device's
	 * IP addresses, don't add the host route to it, but a route through the
	 * parent device.
	 */
	if (nm_ip6_config_destination_is_direct (parent_config, vpn_gw, 128))
		route.gateway = in6addr_any;

	route.source = NM_PLATFORM_SOURCE_VPN;
	route.metric = nm_device_get_priority (parent_device);
	nm_ip6_config_add_route (config, &route);

	/* Ensure there's a route to the parent device's gateway through the
	 * parent device, since if the VPN claims the default route and the VPN
	 * routes include a subnet that matches the parent device's subnet,
	 * the parent device's gateway would get routed through the VPN and fail.
	 */
	memset (&route, 0, sizeof (route));
	route.network = *parent_gw;
	route.plen = 128;
	route.source = NM_PLATFORM_SOURCE_VPN;
	route.metric = nm_device_get_priority (parent_device);

	nm_ip6_config_add_route (config, &route);
}

NMVpnConnection *
nm_vpn_connection_new (NMConnection *connection,
                       NMDevice *parent_device,
                       const char *specific_object,
                       NMAuthSubject *subject)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (NM_IS_DEVICE (parent_device), NULL);

	return (NMVpnConnection *) g_object_new (NM_TYPE_VPN_CONNECTION,
	                                         NM_ACTIVE_CONNECTION_INT_CONNECTION, connection,
	                                         NM_ACTIVE_CONNECTION_INT_DEVICE, parent_device,
	                                         NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT, specific_object,
	                                         NM_ACTIVE_CONNECTION_INT_SUBJECT, subject,
	                                         NM_ACTIVE_CONNECTION_VPN, TRUE,
	                                         NULL);
}

static const char *
nm_vpn_connection_get_service (NMVpnConnection *connection)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	NMSettingVpn *s_vpn;

	s_vpn = nm_connection_get_setting_vpn (priv->connection);
	return nm_setting_vpn_get_service_type (s_vpn);
}

static const char *
vpn_plugin_failure_to_string (NMVpnPluginFailure failure)
{
	switch (failure) {
	case NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED:
		return "login-failed";
	case NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED:
		return "connect-failed";
	case NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG:
		return "bad-ip-config";
	default:
		break;
	}
	return "unknown";
}

static void
plugin_failed (NMVpnConnection *self,
               NMVpnPluginFailure plugin_failure)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	nm_log_warn (LOGD_VPN, "VPN plugin failed: %s (%d)",
	             vpn_plugin_failure_to_string (plugin_failure), plugin_failure);

	switch (plugin_failure) {
	case NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED:
		priv->failure_reason = NM_VPN_CONNECTION_STATE_REASON_LOGIN_FAILED;
		break;
	case NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG:
		priv->failure_reason = NM_VPN_CONNECTION_STATE_REASON_IP_CONFIG_INVALID;
		break;
	default:
		priv->failure_reason = NM_VPN_CONNECTION_STATE_REASON_UNKNOWN;
	}
}

static const char *
vpn_service_state_to_string (NMVpnServiceState state)
{
	switch (state) {
	case NM_VPN_SERVICE_STATE_INIT:
		return "init";
	case NM_VPN_SERVICE_STATE_SHUTDOWN:
		return "shutdown";
	case NM_VPN_SERVICE_STATE_STARTING:
		return "starting";
	case NM_VPN_SERVICE_STATE_STARTED:
		return "started";
	case NM_VPN_SERVICE_STATE_STOPPING:
		return "stopping";
	case NM_VPN_SERVICE_STATE_STOPPED:
		return "stopped";
	default:
		break;
	}
	return "unknown";
}

static const char *state_table[] = {
	[STATE_UNKNOWN]       = "unknown",
	[STATE_WAITING]       = "waiting",
	[STATE_PREPARE]       = "prepare",
	[STATE_NEED_AUTH]     = "need-auth",
	[STATE_CONNECT]       = "connect",
	[STATE_IP_CONFIG_GET] = "ip-config-get",
	[STATE_PRE_UP]        = "pre-up",
	[STATE_ACTIVATED]     = "activated",
	[STATE_DEACTIVATING]  = "deactivating",
	[STATE_DISCONNECTED]  = "disconnected",
	[STATE_FAILED]        = "failed",
};

static const char *
vpn_state_to_string (VpnState state)
{
	if ((gsize) state < G_N_ELEMENTS (state_table))
		return state_table[state];
	return "unknown";
}

static const char *
vpn_reason_to_string (NMVpnConnectionStateReason reason)
{
	switch (reason) {
	case NM_VPN_CONNECTION_STATE_REASON_NONE:
		return "none";
	case NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED:
		return "user-disconnected";
	case NM_VPN_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED:
		return "device-disconnected";
	case NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED:
		return "service-stopped";
	case NM_VPN_CONNECTION_STATE_REASON_IP_CONFIG_INVALID:
		return "ip-config-invalid";
	case NM_VPN_CONNECTION_STATE_REASON_CONNECT_TIMEOUT:
		return "connect-timeout";
	case NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT:
		return "service-start-timeout";
	case NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED:
		return "service-start-failed";
	case NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS:
		return "no-secrets";
	case NM_VPN_CONNECTION_STATE_REASON_LOGIN_FAILED:
		return "login-failed";
	case NM_VPN_CONNECTION_STATE_REASON_CONNECTION_REMOVED:
		return "connection-removed";
	default:
		break;
	}
	return "unknown";
}

static void
plugin_state_changed (NMVpnConnection *connection,
                      NMVpnServiceState state)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	nm_log_info (LOGD_VPN, "VPN plugin state changed: %s (%d)",
	             vpn_service_state_to_string (state), state);

	if (state == NM_VPN_SERVICE_STATE_STOPPED) {
		/* Clear connection secrets to ensure secrets get requested each time the
		 * connection is activated.
		 */
		nm_connection_clear_secrets (priv->connection);

		if ((priv->vpn_state >= STATE_WAITING) && (priv->vpn_state <= STATE_ACTIVATED)) {
			nm_log_info (LOGD_VPN, "VPN plugin state change reason: %s (%d)",
			             vpn_reason_to_string (priv->failure_reason), priv->failure_reason);
			_set_vpn_state (connection, STATE_FAILED, priv->failure_reason, FALSE);

			/* Reset the failure reason */
			priv->failure_reason = NM_VPN_CONNECTION_STATE_REASON_UNKNOWN;
		}
	}
}

static void
print_vpn_config (NMVpnConnection *connection)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	const NMPlatformIP4Address *address4;
	const NMPlatformIP6Address *address6;
	char *dns_domain = NULL;
	guint32 num, i;
	char buf[NM_UTILS_INET_ADDRSTRLEN];

	if (priv->ip4_external_gw) {
		nm_log_info (LOGD_VPN, "VPN Gateway: %s",
		             nm_utils_inet4_ntop (priv->ip4_external_gw, NULL));
	} else if (priv->ip6_external_gw) {
		nm_log_info (LOGD_VPN, "VPN Gateway: %s",
		             nm_utils_inet6_ntop (priv->ip6_external_gw, NULL));
	}

	nm_log_info (LOGD_VPN, "Tunnel Device: %s", priv->ip_iface ? priv->ip_iface : "(none)");

	if (priv->ip4_config) {
		nm_log_info (LOGD_VPN, "IPv4 configuration:");

		address4 = nm_ip4_config_get_address (priv->ip4_config, 0);

		if (priv->ip4_internal_gw)
			nm_log_info (LOGD_VPN, "  Internal Gateway: %s", nm_utils_inet4_ntop (priv->ip4_internal_gw, NULL));
		nm_log_info (LOGD_VPN, "  Internal Address: %s", nm_utils_inet4_ntop (address4->address, NULL));
		nm_log_info (LOGD_VPN, "  Internal Prefix: %d", address4->plen);
		nm_log_info (LOGD_VPN, "  Internal Point-to-Point Address: %s", nm_utils_inet4_ntop (address4->peer_address, NULL));
		nm_log_info (LOGD_VPN, "  Maximum Segment Size (MSS): %d", nm_ip4_config_get_mss (priv->ip4_config));

		num = nm_ip4_config_get_num_routes (priv->ip4_config);
		for (i = 0; i < num; i++) {
			const NMPlatformIP4Route *route = nm_ip4_config_get_route (priv->ip4_config, i);

			nm_log_info (LOGD_VPN, "  Static Route: %s/%d   Next Hop: %s",
			             nm_utils_inet4_ntop (route->network, NULL),
			             route->plen,
			             nm_utils_inet4_ntop (route->gateway, buf));
		}

		nm_log_info (LOGD_VPN, "  Forbid Default Route: %s",
		             nm_ip4_config_get_never_default (priv->ip4_config) ? "yes" : "no");

		num = nm_ip4_config_get_num_nameservers (priv->ip4_config);
		for (i = 0; i < num; i++) {
			nm_log_info (LOGD_VPN, "  Internal DNS: %s",
			             nm_utils_inet4_ntop (nm_ip4_config_get_nameserver (priv->ip4_config, i), NULL));
		}

		if (nm_ip4_config_get_num_domains (priv->ip4_config) > 0)
			dns_domain = (char *) nm_ip4_config_get_domain (priv->ip4_config, 0);

		nm_log_info (LOGD_VPN, "  DNS Domain: '%s'", dns_domain ? dns_domain : "(none)");
	} else
		nm_log_info (LOGD_VPN, "No IPv4 configuration");

	if (priv->ip6_config) {
		nm_log_info (LOGD_VPN, "IPv6 configuration:");

		address6 = nm_ip6_config_get_address (priv->ip6_config, 0);

		if (priv->ip6_internal_gw)
			nm_log_info (LOGD_VPN, "  Internal Gateway: %s", nm_utils_inet6_ntop (priv->ip6_internal_gw, NULL));
		nm_log_info (LOGD_VPN, "  Internal Address: %s", nm_utils_inet6_ntop (&address6->address, NULL));
		nm_log_info (LOGD_VPN, "  Internal Prefix: %d", address6->plen);
		nm_log_info (LOGD_VPN, "  Internal Point-to-Point Address: %s", nm_utils_inet6_ntop (&address6->peer_address, NULL));
		nm_log_info (LOGD_VPN, "  Maximum Segment Size (MSS): %d", nm_ip6_config_get_mss (priv->ip6_config));

		num = nm_ip6_config_get_num_routes (priv->ip6_config);
		for (i = 0; i < num; i++) {
			const NMPlatformIP6Route *route = nm_ip6_config_get_route (priv->ip6_config, i);

			nm_log_info (LOGD_VPN, "  Static Route: %s/%d   Next Hop: %s",
			             nm_utils_inet6_ntop (&route->network, NULL),
			             route->plen,
			             nm_utils_inet6_ntop (&route->gateway, buf));
		}

		nm_log_info (LOGD_VPN, "  Forbid Default Route: %s",
		             nm_ip6_config_get_never_default (priv->ip6_config) ? "yes" : "no");

		num = nm_ip6_config_get_num_nameservers (priv->ip6_config);
		for (i = 0; i < num; i++) {
			nm_log_info (LOGD_VPN, "  Internal DNS: %s",
			             nm_utils_inet6_ntop (nm_ip6_config_get_nameserver (priv->ip6_config, i), NULL));
		}

		if (nm_ip6_config_get_num_domains (priv->ip6_config) > 0)
			dns_domain = (char *) nm_ip6_config_get_domain (priv->ip6_config, 0);

		nm_log_info (LOGD_VPN, "  DNS Domain: '%s'", dns_domain ? dns_domain : "(none)");
	} else
		nm_log_info (LOGD_VPN, "No IPv6 configuration");

	if (priv->banner && strlen (priv->banner)) {
		nm_log_info (LOGD_VPN, "Login Banner:");
		nm_log_info (LOGD_VPN, "-----------------------------------------");
		nm_log_info (LOGD_VPN, "%s", priv->banner);
		nm_log_info (LOGD_VPN, "-----------------------------------------");
	}
}

static gboolean
nm_vpn_connection_apply_config (NMVpnConnection *connection)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	NMDevice *parent_dev = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (connection));
	NMIP4Config *vpn4_parent_config = NULL;
	NMIP6Config *vpn6_parent_config = NULL;

	if (priv->ip_ifindex > 0) {
		nm_platform_link_set_up (priv->ip_ifindex);

		if (priv->ip4_config) {
			if (!nm_ip4_config_commit (priv->ip4_config, priv->ip_ifindex))
				return FALSE;
		}

		if (priv->ip6_config) {
			if (!nm_ip6_config_commit (priv->ip6_config, priv->ip_ifindex))
				return FALSE;
		}

		if (priv->ip4_config)
			vpn4_parent_config = nm_ip4_config_new ();
		if (priv->ip6_config)
			vpn6_parent_config = nm_ip6_config_new ();
	} else {
		/* If the VPN didn't return a network interface, it is a route-based
		 * VPN (like kernel IPSec) and all IP addressing and routing should
		 * be done on the parent interface instead.
		 */

		if (priv->ip4_config)
			vpn4_parent_config = g_object_ref (priv->ip4_config);
		if (priv->ip6_config)
			vpn6_parent_config = g_object_ref (priv->ip6_config);
	}

	if (vpn4_parent_config) {
		/* Add any explicit route to the VPN gateway through the parent device */
		if (priv->ip4_external_gw)
			add_ip4_vpn_gateway_route (vpn4_parent_config, parent_dev, priv->ip4_external_gw);

		nm_device_set_vpn4_config (parent_dev, vpn4_parent_config);
		g_object_unref (vpn4_parent_config);
	}
	if (vpn6_parent_config) {
		/* Add any explicit route to the VPN gateway through the parent device */
		if (priv->ip6_external_gw)
			add_ip6_vpn_gateway_route (vpn6_parent_config, parent_dev, priv->ip6_external_gw);

		nm_device_set_vpn6_config (parent_dev, vpn6_parent_config);
		g_object_unref (vpn6_parent_config);
	}

	nm_log_info (LOGD_VPN, "VPN connection '%s' (IP Config Get) complete.",
	             nm_connection_get_id (priv->connection));
	_set_vpn_state (connection, STATE_PRE_UP, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);
	return TRUE;
}

static void
nm_vpn_connection_config_maybe_complete (NMVpnConnection *connection,
                                         gboolean         success)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	if (priv->connect_timeout == 0) {
		/* config_complete() was already called with an error;
		 * ignore further calls.
		 */
		return;
	}

	if (success) {
		if (   (priv->has_ip4 && !priv->ip4_config)
		    || (priv->has_ip6 && !priv->ip6_config)) {
			/* Need to wait for other config */
			return;
		}
	}

	g_source_remove (priv->connect_timeout);
	priv->connect_timeout = 0;

	if (success) {
		print_vpn_config (connection);

		if (nm_vpn_connection_apply_config (connection))
			return;
	}

	g_clear_object (&priv->ip4_config);
	g_clear_object (&priv->ip6_config);

	nm_log_warn (LOGD_VPN, "VPN connection '%s' did not receive valid IP config information.",
	             nm_connection_get_id (priv->connection));
	_set_vpn_state (connection, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_IP_CONFIG_INVALID, FALSE);
}

#define LOG_INVALID_ARG(property) \
    nm_log_dbg (LOGD_VPN, "VPN connection '%s' has invalid argument %s", \
                          nm_connection_get_id (priv->connection), property)

static gboolean
process_generic_config (NMVpnConnection *connection,
                        GVariant *config_dict)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	const char *tundev;
	GVariant *val;
	guint32 mtu;

	g_clear_pointer (&priv->ip_iface, g_free);
	if (g_variant_lookup (config_dict, NM_VPN_PLUGIN_CONFIG_TUNDEV, "&s", &tundev)) {
		/* Backwards compat with NM-openswan */
		if (g_strcmp0 (tundev, "_none_") != 0)
			priv->ip_iface = g_strdup (tundev);
	}

	if (priv->ip_iface) {
		/* Grab the interface index for address/routing operations */
		priv->ip_ifindex = nm_platform_link_get_ifindex (priv->ip_iface);
		if (!priv->ip_ifindex) {
			nm_log_err (LOGD_VPN, "(%s): failed to look up VPN interface index", priv->ip_iface);
			nm_vpn_connection_config_maybe_complete (connection, FALSE);
			return FALSE;
		}
	}

	g_clear_pointer (&priv->banner, g_free);
	g_variant_lookup (config_dict, NM_VPN_PLUGIN_CONFIG_BANNER, "&s", &priv->banner);

	/* External world-visible address of the VPN server */
	priv->ip4_external_gw = 0;
	g_clear_pointer (&priv->ip6_external_gw, g_free);
	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, NULL);
	if (val) {
		const guint8 *data;
		gsize length;

		if (g_variant_is_of_type (val, G_VARIANT_TYPE_UINT32)) {
			priv->ip4_external_gw = g_variant_get_uint32 (val);
		} else if (   g_variant_is_of_type (val, G_VARIANT_TYPE_BYTESTRING)
		           && (data = g_variant_get_fixed_array (val, &length, 1))
		           && length == sizeof (struct in6_addr)) {
			priv->ip6_external_gw = g_memdup (data, length);
		} else {
			nm_log_err (LOGD_VPN, "(%s): VPN gateway is neither IPv4 nor IPv6", priv->ip_iface);
			nm_vpn_connection_config_maybe_complete (connection, FALSE);
			g_variant_unref (val);
			return FALSE;
		}
		g_variant_unref (val);
	}

	/* MTU; this is a per-connection value, though NM's API treats it
	 * like it's IP4-specific. So we store it for now and retrieve it
	 * later in ip4_config_get.
	 */
	priv->mtu = 0;
	if (g_variant_lookup (config_dict, NM_VPN_PLUGIN_CONFIG_MTU, "u", &mtu))
		priv->mtu = mtu;

	return TRUE;
}

static void
nm_vpn_connection_config_get (NMVpnConnection *connection,
                              GVariant *config_dict)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	nm_log_info (LOGD_VPN, "VPN connection '%s' (IP Config Get) reply received.",
	             nm_connection_get_id (priv->connection));

	if (priv->vpn_state == STATE_CONNECT)
		_set_vpn_state (connection, STATE_IP_CONFIG_GET, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);

	if (!process_generic_config (connection, config_dict))
		return;

	/* Note whether to expect IPv4 and IPv6 configs */
	priv->has_ip4 = FALSE;
	g_clear_object (&priv->ip4_config);
	g_variant_lookup (config_dict, NM_VPN_PLUGIN_CONFIG_HAS_IP4, "b", &priv->has_ip4);

	priv->has_ip6 = FALSE;
	g_clear_object (&priv->ip6_config);
	g_variant_lookup (config_dict, NM_VPN_PLUGIN_CONFIG_HAS_IP6, "b", &priv->has_ip6);
}

static guint
vpn_routing_metric (NMVpnConnection *connection)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	if (priv->ip_ifindex)
		return NM_PLATFORM_ROUTE_METRIC_DEFAULT;
	else {
		NMDevice *parent_dev = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (connection));

		return nm_device_get_priority (parent_dev);
	}
}

static void
nm_vpn_connection_ip4_config_get (NMVpnConnection *connection,
                                  GVariant *config_dict)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	NMPlatformIP4Address address;
	NMIP4Config *config;
	GVariant *val;
	int i;

	if (priv->vpn_state == STATE_CONNECT)
		_set_vpn_state (connection, STATE_IP_CONFIG_GET, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);

	if (priv->has_ip4) {
		nm_log_info (LOGD_VPN, "VPN connection '%s' (IP4 Config Get) reply received.",
		             nm_connection_get_id (priv->connection));

		if (g_variant_n_children (config_dict) == 0) {
			priv->has_ip4 = FALSE;
			nm_vpn_connection_config_maybe_complete (connection, TRUE);
			return;
		}
	} else {
		nm_log_info (LOGD_VPN, "VPN connection '%s' (IP4 Config Get) reply received from old-style plugin.",
		             nm_connection_get_id (priv->connection));

		/* In the old API, the generic and IPv4 configuration items
		 * were mixed together.
		 */
		if (!process_generic_config (connection, config_dict))
			return;

		priv->has_ip4 = TRUE;
		priv->has_ip6 = FALSE;
	}

	config = nm_ip4_config_new ();

	memset (&address, 0, sizeof (address));
	address.plen = 24;
	if (priv->ip4_external_gw)
		nm_ip4_config_set_gateway (config, priv->ip4_external_gw);

	/* Internal address of the VPN subnet's gateway */
	g_variant_lookup (config_dict, NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY, "u", &priv->ip4_internal_gw);

	g_variant_lookup (config_dict, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, "u", &address.address);
	g_variant_lookup (config_dict, NM_VPN_PLUGIN_IP4_CONFIG_PTP, "u", &address.peer_address);
	g_variant_lookup (config_dict, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, "u", &address.plen);

	if (address.address && address.plen) {
		address.source = NM_PLATFORM_SOURCE_VPN;
		nm_ip4_config_add_address (config, &address);
	} else {
		nm_log_err (LOGD_VPN, "invalid IP4 config received!");
		g_object_unref (config);
		nm_vpn_connection_config_maybe_complete (connection, FALSE);
		return;
	}

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP4_CONFIG_DNS, G_VARIANT_TYPE ("au"));
	if (val) {
		const guint32 *array;
		gsize length;

		array = g_variant_get_fixed_array (val, &length, sizeof (guint32));

		for (i = 0; i < length; i++)
			nm_ip4_config_add_nameserver (config, array[i]);
	}

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP4_CONFIG_NBNS, G_VARIANT_TYPE ("au"));
	if (val) {
		const guint32 *array;
		gsize length;

		array = g_variant_get_fixed_array (val, &length, sizeof (guint32));

		for (i = 0; i < length; i++)
			nm_ip4_config_add_wins (config, array[i]);
	}

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP4_CONFIG_MSS, G_VARIANT_TYPE_UINT32);
	if (val) {
		nm_ip4_config_set_mss (config, g_variant_get_uint32 (val));
		g_variant_unref (val);
	}

	if (priv->mtu)
		nm_ip4_config_set_mtu (config, priv->mtu);

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN, G_VARIANT_TYPE_STRING);
	if (val) {
		nm_ip4_config_add_domain (config, g_variant_get_string (val, NULL));
		g_variant_unref (val);
	}

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP4_CONFIG_DOMAINS, G_VARIANT_TYPE_STRING_ARRAY);
	if (val) {
		char **domains = g_variant_dup_strv (val, NULL);
		char **domain;

		for (domain = domains; domain && *domain; domain++)
			nm_ip4_config_add_domain (config, *domain);

		g_strfreev (domains);
		g_variant_unref (val);
	}

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP4_CONFIG_ROUTES, G_VARIANT_TYPE ("aau"));
	if (val) {
		GValue gval = { 0, };
		GPtrArray *routes;

		g_value_init (&gval, G_TYPE_PTR_ARRAY);
		_nm_utils_ip4_addresses_from_dbus (val, &gval);
		routes = g_value_get_boxed (&gval);

		for (i = 0; i < routes->len; i++) {
			NMIP4Route *item = routes->pdata[i];
			NMPlatformIP4Route route;

			memset (&route, 0, sizeof (route));
			route.network = nm_ip4_route_get_dest (item);
			route.plen = nm_ip4_route_get_prefix (item);
			route.gateway = nm_ip4_route_get_next_hop (item);
			route.source = NM_PLATFORM_SOURCE_VPN;
			route.metric = vpn_routing_metric (connection);

			/* Ignore host routes to the VPN gateway since NM adds one itself
			 * below.  Since NM knows more about the routing situation than
			 * the VPN server, we want to use the NM created route instead of
			 * whatever the server provides.
			 */
			if (priv->ip4_external_gw && route.network == priv->ip4_external_gw && route.plen == 32)
				continue;

			/* Otherwise accept the VPN-provided route */
			nm_ip4_config_add_route (config, &route);
		}

		g_ptr_array_unref (routes);
		g_value_unset (&gval);
		g_variant_unref (val);
	}

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT, G_VARIANT_TYPE_BOOLEAN);
	if (val) {
		nm_ip4_config_set_never_default (config, g_variant_get_boolean (val));
		g_variant_unref (val);
	}

	/* Merge in user overrides from the NMConnection's IPv4 setting */
	nm_ip4_config_merge_setting (config,
	                             nm_connection_get_setting_ip4_config (priv->connection),
	                             vpn_routing_metric (connection));

	priv->ip4_config = config;
	nm_ip4_config_export (config);
	g_object_notify (G_OBJECT (connection), NM_ACTIVE_CONNECTION_IP4_CONFIG);
	nm_vpn_connection_config_maybe_complete (connection, TRUE);
}

static void
nm_vpn_connection_ip6_config_get (NMVpnConnection *connection,
                                  GVariant *config_dict)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	NMPlatformIP6Address address;
	NMIP6Config *config;
	GVariant *val;

	nm_log_info (LOGD_VPN, "VPN connection '%s' (IP6 Config Get) reply received.",
	             nm_connection_get_id (priv->connection));

	if (priv->vpn_state == STATE_CONNECT)
		_set_vpn_state (connection, STATE_IP_CONFIG_GET, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);

	if (g_variant_n_children (config_dict) == 0) {
		priv->has_ip6 = FALSE;
		nm_vpn_connection_config_maybe_complete (connection, TRUE);
		return;
	}

	config = nm_ip6_config_new ();

	memset (&address, 0, sizeof (address));
	address.plen = 128;
	if (priv->ip6_external_gw)
		nm_ip6_config_set_gateway (config, priv->ip6_external_gw);

	/* Internal address of the VPN subnet's gateway */
	g_clear_pointer (&priv->ip6_internal_gw, g_free);
	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP6_CONFIG_INT_GATEWAY, G_VARIANT_TYPE_BYTESTRING);
	if (val) {
		const guint8 *data;
		gsize length;

		data = g_variant_get_fixed_array (val, &length, 1);
		if (length == sizeof (struct in6_addr))
			priv->ip6_internal_gw = g_memdup (data, length);
		g_variant_unref (val);
	}

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP6_CONFIG_ADDRESS, G_VARIANT_TYPE_BYTESTRING);
	if (val) {
		const guint8 *data;
		gsize length;

		data = g_variant_get_fixed_array (val, &length, 1);
		if (length == sizeof (struct in6_addr))
			memcpy (&address.address, data, length);
		g_variant_unref (val);
	}

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP6_CONFIG_PTP, G_VARIANT_TYPE_BYTESTRING);
	if (val) {
		const guint8 *data;
		gsize length;

		data = g_variant_get_fixed_array (val, &length, 1);
		if (length == sizeof (struct in6_addr))
			memcpy (&address.peer_address, data, length);
		g_variant_unref (val);
	}

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP6_CONFIG_PREFIX, G_VARIANT_TYPE_UINT32);
	if (val) {
		address.plen = g_variant_get_uint32 (val);
		g_variant_unref (val);
	}

	if (!IN6_IS_ADDR_UNSPECIFIED (&address.address) && address.plen) {
		address.source = NM_PLATFORM_SOURCE_VPN;
		nm_ip6_config_add_address (config, &address);
	} else {
		nm_log_err (LOGD_VPN, "invalid IP6 config received!");
		g_object_unref (config);
		nm_vpn_connection_config_maybe_complete (connection, FALSE);
		return;
	}

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP6_CONFIG_DNS, G_VARIANT_TYPE ("aay"));
	if (val) {
		GVariantIter iter;
		GVariant *addr;
		const guint8 *data;
		gsize length;

		g_variant_iter_init (&iter, val);
		while (g_variant_iter_next (&iter, "@ay", &addr)) {
			data = g_variant_get_fixed_array (addr, &length, 1);
			if (length == sizeof (struct in6_addr))
				nm_ip6_config_add_nameserver (config, (struct in6_addr *)data);
			g_variant_unref (addr);
		}

		g_variant_unref (val);
	}

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP6_CONFIG_MSS, G_VARIANT_TYPE_UINT32);
	if (val) {
		nm_ip6_config_set_mss (config, g_variant_get_uint32 (val));
		g_variant_unref (val);
	}

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP6_CONFIG_DOMAIN, G_VARIANT_TYPE_STRING);
	if (val) {
		nm_ip6_config_add_domain (config, g_variant_get_string (val, NULL));
		g_variant_unref (val);
	}

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP6_CONFIG_DOMAINS, G_VARIANT_TYPE_STRING_ARRAY);
	if (val) {
		char **domains = g_variant_dup_strv (val, NULL);
		char **domain;

		for (domain = domains; domain && *domain; domain++)
			nm_ip6_config_add_domain (config, *domain);
		g_free (domains);

		g_variant_unref (val);
	}

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP6_CONFIG_ROUTES, G_VARIANT_TYPE ("a(ayuayu)"));
	if (val) {
		GValue gval = { 0, };
		GPtrArray *routes;
		int i;

		g_value_init (&gval, G_TYPE_PTR_ARRAY);
		_nm_utils_ip6_addresses_from_dbus (val, &gval);
		routes = g_value_get_boxed (&gval);

		for (i = 0; i < routes->len; i++) {
			NMIP6Route *item = routes->pdata[i];
			NMPlatformIP6Route route;

			memset (&route, 0, sizeof (route));
			route.network = *nm_ip6_route_get_dest (item);
			route.plen = nm_ip6_route_get_prefix (item);
			route.gateway = *nm_ip6_route_get_next_hop (item);
			route.source = NM_PLATFORM_SOURCE_VPN;
			route.metric = vpn_routing_metric (connection);

			/* Ignore host routes to the VPN gateway since NM adds one itself
			 * below.  Since NM knows more about the routing situation than
			 * the VPN server, we want to use the NM created route instead of
			 * whatever the server provides.
			 */
			if (priv->ip6_external_gw && IN6_ARE_ADDR_EQUAL (&route.network, priv->ip6_external_gw) && route.plen == 128)
				continue;

			/* Otherwise accept the VPN-provided route */
			nm_ip6_config_add_route (config, &route);
		}

		g_ptr_array_unref (routes);
		g_value_unset (&gval);
		g_variant_unref (val);
	}

	val = g_variant_lookup_value (config_dict, NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT, G_VARIANT_TYPE_BOOLEAN);
	if (val) {
		nm_ip6_config_set_never_default (config, g_variant_get_boolean (val));
		g_variant_unref (val);
	}

	/* Merge in user overrides from the NMConnection's IPv6 setting */
	nm_ip6_config_merge_setting (config,
	                             nm_connection_get_setting_ip6_config (priv->connection),
	                             vpn_routing_metric (connection));

	priv->ip6_config = config;
	nm_ip6_config_export (config);
	g_object_notify (G_OBJECT (connection), NM_ACTIVE_CONNECTION_IP6_CONFIG);
	nm_vpn_connection_config_maybe_complete (connection, TRUE);
}

static void
proxy_signal (GDBusProxy *proxy,
              const char *sender_name,
              const char *signal_name,
              GVariant   *parameters,
              gpointer    user_data)
{
	NMVpnConnection *connection = user_data;

	if (   !strcmp (signal_name, "Config")
	    && g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(a{sv})"))) {
		GVariant *props;

		g_variant_get (parameters, "(@a{sv})", &props);
		nm_vpn_connection_config_get (connection, props);
		g_variant_unref (props);
	} else if (   !strcmp (signal_name, "Ip4Config")
	           && g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(a{sv})"))) {
		GVariant *props;

		g_variant_get (parameters, "(@a{sv})", &props);
		nm_vpn_connection_ip4_config_get (connection, props);
		g_variant_unref (props);
	} else if (   !strcmp (signal_name, "Ip6Config")
	           && g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(a{sv})"))) {
		GVariant *props;

		g_variant_get (parameters, "(@a{sv})", &props);
		nm_vpn_connection_ip6_config_get (connection, props);
		g_variant_unref (props);
	} else if (   !strcmp (signal_name, "Failure")
	           && g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(u)"))) {
		guint32 reason;

		g_variant_get (parameters, "(u)", &reason);
		plugin_failed (connection, reason);
	} else if (   !strcmp (signal_name, "StateChanged")
	           && g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(u)"))) {
		guint32 state;

		g_variant_get (parameters, "(u)", &state);
		plugin_state_changed (connection, state);
	} else if (   !strcmp (signal_name, "SecretsRequired")
	           && g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sas)"))) {
		const char *message;
		char **secrets;

		g_variant_get (parameters, "(&s^as)", &message, &secrets);
		plugin_interactive_secrets_required (connection, message, (const char **) secrets);
		g_strfreev (secrets);
	} else {
		nm_log_warn (LOGD_VPN, "unknown %s signal received (%s %s)",
		             NM_VPN_DBUS_PLUGIN_INTERFACE, signal_name,
		             g_variant_get_type_string (parameters));
	}
}

static gboolean
connect_timeout_cb (gpointer user_data)
{
	NMVpnConnection *connection = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	priv->connect_timeout = 0;

	/* Cancel activation if it's taken too long */
	if (priv->vpn_state == STATE_CONNECT ||
	    priv->vpn_state == STATE_IP_CONFIG_GET) {
		nm_log_warn (LOGD_VPN, "VPN connection '%s' connect timeout exceeded.",
		             nm_connection_get_id (priv->connection));
		_set_vpn_state (connection, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_CONNECT_TIMEOUT, FALSE);
	}

	return FALSE;
}

static void
connect_success (NMVpnConnection *connection)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	/* 40 second timeout waiting for IP config signal from VPN service */
	priv->connect_timeout = g_timeout_add_seconds (40, connect_timeout_cb, connection);

	g_variant_unref (priv->connect_dict);
	priv->connect_dict = NULL;
}

static void
connect_cb (GObject *proxy, GAsyncResult *result, void *user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	GVariant *ret;
	GError *err = NULL;

	nm_log_info (LOGD_VPN, "VPN connection '%s' (Connect) reply received.",
	             nm_connection_get_id (priv->connection));

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &err);
	if (ret) {
		g_variant_unref (ret);
		connect_success (self);
		return;
	}

	nm_log_warn (LOGD_VPN, "VPN connection '%s' failed to connect: '%s'.",
	             nm_connection_get_id (priv->connection), err->message);
	g_error_free (err);
	_set_vpn_state (self, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED, FALSE);
}

static void
connect_interactive_cb (GObject *proxy, GAsyncResult *result, void *user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	GVariant *ret;
	GError *err = NULL;
	char *remote_error;

	nm_log_info (LOGD_VPN, "VPN connection '%s' (ConnectInteractive) reply received.",
	             nm_connection_get_id (priv->connection));

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &err);
	if (ret) {
		g_variant_unref (ret);
		connect_success (self);
		return;
	}

	remote_error = g_dbus_error_get_remote_error (err);
	if (!g_strcmp0 (remote_error, NM_DBUS_VPN_ERROR_PREFIX "." NM_DBUS_VPN_INTERACTIVE_NOT_SUPPORTED)) {
		/* Fall back to Connect() */
		g_dbus_proxy_call (priv->proxy,
		                   "Connect",
		                   g_variant_new ("(@a{sv})", priv->connect_dict),
		                   G_DBUS_CALL_FLAGS_NONE, -1,
		                   NULL,
		                   connect_cb, self);
	} else {
		nm_log_warn (LOGD_VPN, "VPN connection '%s' failed to connect interactively: '%s'.",
		             nm_connection_get_id (priv->connection), err->message);
		_set_vpn_state (self, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED, FALSE);
	}

	g_error_free (err);
	g_free (remote_error);
}

/* Add a username to a serialized connection */
static GVariant *
_dict_with_username (NMConnection *connection, const char *username)
{
	NMConnection *dup;
	NMSettingVpn *s_vpn;
	GVariant *dict;
	const char *existing;

	/* Shortcut if we weren't given a username or if there already was one in
	 * the VPN setting; don't bother duplicating the connection and everything.
	 */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);
	existing = nm_setting_vpn_get_user_name (s_vpn);
	if (username == NULL || existing) {
		dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);
		hash = nm_utils_connection_dict_to_hash (dict);
		g_variant_unref (dict);
		return hash;
	}

	dup = nm_simple_connection_new_clone (connection);
	g_assert (dup);
	s_vpn = nm_connection_get_setting_vpn (dup);
	g_assert (s_vpn);
	g_object_set (s_vpn, NM_SETTING_VPN_USER_NAME, username, NULL);
	dict = nm_connection_to_dbus (dup, NM_CONNECTION_SERIALIZE_ALL);
	g_object_unref (dup);
	return dict;
}

static void
really_activate (NMVpnConnection *connection, const char *username)
{
	NMVpnConnectionPrivate *priv;
	NMAgentManager *agent_mgr;
	GVariant *details;

	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	g_return_if_fail (priv->vpn_state == STATE_NEED_AUTH);

	g_signal_connect (priv->proxy, "g-signal",
	                  G_CALLBACK (proxy_signal), connection);

	if (priv->connect_dict)
		g_variant_unref (priv->connect_dict);
	priv->connect_dict = _dict_with_username (priv->connection, username);
	g_variant_ref_sink (priv->connect_dict);

	/* If at least one agent doesn't support VPN hints, then we can't use
	 * ConnectInteractive(), because that agent won't be able to pass hints
	 * from the VPN plugin's interactive secrets requests to the VPN authentication
	 * dialog and we won't get the secrets we need.  In this case fall back to
	 * the old Connect() call.
	 */
	agent_mgr = nm_agent_manager_get ();
	if (nm_agent_manager_all_agents_have_capability (agent_mgr,
	                                                 nm_active_connection_get_subject (NM_ACTIVE_CONNECTION (connection)),
	                                                 NM_SECRET_AGENT_CAPABILITY_VPN_HINTS)) {
		nm_log_dbg (LOGD_VPN, "Allowing interactive secrets as all agents have that capability");
		details = g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0);
		g_dbus_proxy_call (priv->proxy,
		                   "ConnectInteractive",
		                   g_variant_new ("(a{sa{sv}}a{sv})", priv->connect_dict, details),
		                   G_DBUS_CALL_FLAGS_NONE, -1,
		                   NULL,
		                   connect_interactive_cb, connection);
	} else {
		nm_log_dbg (LOGD_VPN, "Calling old Connect function as not all agents support interactive secrets");
		g_dbus_proxy_call (priv->proxy,
		                   "Connect",
		                   g_variant_new ("(a{sa{sv}})", priv->connect_dict),
		                   G_DBUS_CALL_FLAGS_NONE, -1,
		                   NULL,
		                   connect_cb, connection);
	}
	g_object_unref (agent_mgr);

	_set_vpn_state (connection, STATE_CONNECT, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);
}

void
nm_vpn_connection_activate (NMVpnConnection *connection)
{
	NMVpnConnectionPrivate *priv;
	GDBusConnection *bus;

	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	_set_vpn_state (connection, STATE_PREPARE, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);

	bus = nm_dbus_manager_get_connection (nm_dbus_manager_get ());
	priv->proxy = g_dbus_proxy_new_sync (bus,
	                                     G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                                     NULL,
	                                     nm_vpn_connection_get_service (connection),
	                                     NM_VPN_DBUS_PLUGIN_PATH,
	                                     NM_VPN_DBUS_PLUGIN_INTERFACE,
	                                     NULL, NULL);

	g_signal_connect (priv->proxy, "g-signal",
	                  G_CALLBACK (proxy_signal), connection);

	_set_vpn_state (connection, STATE_NEED_AUTH, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);

	/* Kick off the secrets requests; first we get existing system secrets
	 * and ask the plugin if these are sufficient, next we get all existing
	 * secrets from system and from user agents and ask the plugin again,
	 * and last we ask the user for new secrets if required.
	 */
	get_secrets (connection, SECRETS_REQ_SYSTEM, NULL);
}

NMConnection *
nm_vpn_connection_get_connection (NMVpnConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->connection;
}

NMVpnConnectionState
nm_vpn_connection_get_vpn_state (NMVpnConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NM_VPN_CONNECTION_STATE_UNKNOWN);

	return _state_to_nm_vpn_state (NM_VPN_CONNECTION_GET_PRIVATE (connection)->vpn_state);
}

const char *
nm_vpn_connection_get_banner (NMVpnConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->banner;
}

NMIP4Config *
nm_vpn_connection_get_ip4_config (NMVpnConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->ip4_config;
}

NMIP6Config *
nm_vpn_connection_get_ip6_config (NMVpnConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->ip6_config;
}

const char *
nm_vpn_connection_get_ip_iface (NMVpnConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->ip_iface;
}

int
nm_vpn_connection_get_ip_ifindex (NMVpnConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), -1);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->ip_ifindex;
}

guint32
nm_vpn_connection_get_ip4_internal_gateway (NMVpnConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), 0);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->ip4_internal_gw;
}

struct in6_addr *
nm_vpn_connection_get_ip6_internal_gateway (NMVpnConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), 0);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->ip6_internal_gw;
}

void
nm_vpn_connection_disconnect (NMVpnConnection *connection,
                              NMVpnConnectionStateReason reason,
                              gboolean quitting)
{
	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));

	_set_vpn_state (connection, STATE_DISCONNECTED, reason, quitting);
}

gboolean
nm_vpn_connection_deactivate (NMVpnConnection *connection,
                              NMVpnConnectionStateReason reason,
                              gboolean quitting)
{
	NMVpnConnectionPrivate *priv;
	gboolean success = FALSE;

	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), FALSE);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	if (priv->vpn_state > STATE_UNKNOWN && priv->vpn_state <= STATE_DEACTIVATING) {
		_set_vpn_state (connection, STATE_DEACTIVATING, reason, quitting);
		success = TRUE;
	}
	return success;
}

/******************************************************************************/

static void
plugin_need_secrets_cb  (GObject *proxy, GAsyncResult *result, void *user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	GVariant *ret;
	GError *error = NULL;
	const char *setting_name;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &error);
	if (error) {
		nm_log_err (LOGD_VPN, "(%s/%s) plugin NeedSecrets request #%d failed: %s %s",
		            nm_connection_get_uuid (priv->connection),
		            nm_connection_get_id (priv->connection),
		            priv->secrets_idx + 1,
		            g_quark_to_string (error->domain),
		            error->message);
		_set_vpn_state (self, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
		g_error_free (error);
		return;
	}

	g_variant_get (ret, "(&s)", &setting_name);
	if (*setting_name) {
		/* More secrets required */

		if (priv->secrets_idx == SECRETS_REQ_NEW) {
			nm_log_err (LOGD_VPN, "(%s/%s) final secrets request failed to provide sufficient secrets",
			            nm_connection_get_uuid (priv->connection),
			            nm_connection_get_id (priv->connection));
			_set_vpn_state (self, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
		} else {
			nm_log_dbg (LOGD_VPN, "(%s/%s) service indicated additional secrets required",
			            nm_connection_get_uuid (priv->connection),
			            nm_connection_get_id (priv->connection));

			get_secrets (self, priv->secrets_idx + 1, NULL);
		}

		g_variant_unref (ret);
	}

	g_variant_unref (ret);
	nm_log_dbg (LOGD_VPN, "(%s/%s) service indicated no additional secrets required",
	            nm_connection_get_uuid (priv->connection),
	            nm_connection_get_id (priv->connection));

	/* No secrets required; we can start the VPN */
	really_activate (self, priv->username);
}

static void
plugin_new_secrets_cb  (GObject *proxy, GAsyncResult *result, void *user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	GVariant *ret;
	GError *error = NULL;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &error);
	if (!ret) {
		nm_log_err (LOGD_VPN, "(%s/%s) sending new secrets to the plugin failed: %s %s",
		            nm_connection_get_uuid (priv->connection),
		            nm_connection_get_id (priv->connection),
		            g_quark_to_string (error->domain),
		            error->message);
		_set_vpn_state (self, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
		g_error_free (error);
	}

	g_variant_unref (ret);
}

static void
get_secrets_cb (NMSettingsConnection *connection,
                guint32 call_id,
                const char *agent_username,
                const char *setting_name,
                GError *error,
                gpointer user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	GVariant *dict;

	g_return_if_fail (NM_CONNECTION (connection) == priv->connection);
	g_return_if_fail (call_id == priv->secrets_id);

	priv->secrets_id = 0;

	if (error) {
		nm_log_err (LOGD_VPN, "Failed to request VPN secrets #%d: (%d) %s",
		            priv->secrets_idx + 1, error->code, error->message);
		_set_vpn_state (self, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
	} else {
		/* Cache the username for later */
		if (agent_username) {
			g_free (priv->username);
			priv->username = g_strdup (agent_username);
		}

		dict = _dict_with_username (priv->connection, priv->username);

		if (priv->secrets_idx == SECRETS_REQ_INTERACTIVE) {
			nm_log_dbg (LOGD_VPN, "(%s/%s) sending secrets to the plugin",
			            nm_connection_get_uuid (priv->connection),
			            nm_connection_get_id (priv->connection));

			/* Send the secrets back to the plugin */
			g_dbus_proxy_call (priv->proxy,
			                   "NewSecrets",
			                   g_variant_new ("(@a{sv})", dict),
			                   G_DBUS_CALL_FLAGS_NONE, -1,
			                   NULL,
			                   plugin_new_secrets_cb, self);
		} else {
			nm_log_dbg (LOGD_VPN, "(%s/%s) asking service if additional secrets are required",
			            nm_connection_get_uuid (priv->connection),
			            nm_connection_get_id (priv->connection));

			/* Ask the VPN service if more secrets are required */
			g_dbus_proxy_call (priv->proxy,
			                   "NeedSecrets",
			                   g_variant_new ("(@a{sv})", dict),
			                   G_DBUS_CALL_FLAGS_NONE, -1,
			                   NULL,
			                   plugin_need_secrets_cb, self);
		}
	}
}

static void
get_secrets (NMVpnConnection *self,
             SecretsReq secrets_idx,
             const char **hints)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	NMSecretAgentGetSecretsFlags flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_NONE;
	GError *error = NULL;

	g_return_if_fail (secrets_idx < SECRETS_REQ_LAST);
	priv->secrets_idx = secrets_idx;

	nm_log_dbg (LOGD_VPN, "(%s/%s) requesting VPN secrets pass #%d",
	            nm_connection_get_uuid (priv->connection),
	            nm_connection_get_id (priv->connection),
	            priv->secrets_idx + 1);

	switch (priv->secrets_idx) {
	case SECRETS_REQ_SYSTEM:
		flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ONLY_SYSTEM;
		break;
	case SECRETS_REQ_EXISTING:
		flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_NONE;
		break;
	case SECRETS_REQ_NEW:
	case SECRETS_REQ_INTERACTIVE:
		flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;
		break;
	default:
		g_assert_not_reached ();
	}

	if (nm_active_connection_get_user_requested (NM_ACTIVE_CONNECTION (self)))
		flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_USER_REQUESTED;

	priv->secrets_id = nm_settings_connection_get_secrets (NM_SETTINGS_CONNECTION (priv->connection),
	                                                       nm_active_connection_get_subject (NM_ACTIVE_CONNECTION (self)),
	                                                       NM_SETTING_VPN_SETTING_NAME,
	                                                       flags,
	                                                       hints,
	                                                       get_secrets_cb,
	                                                       self,
	                                                       &error);
	if (!priv->secrets_id) {
		if (error) {
			nm_log_err (LOGD_VPN, "failed to request VPN secrets #%d: (%d) %s",
			            priv->secrets_idx + 1, error->code, error->message);
		}
		_set_vpn_state (self, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
		g_clear_error (&error);
	}
}

static void
plugin_interactive_secrets_required (NMVpnConnection *connection,
                                     const char *message,
                                     const char **secrets)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	guint32 secrets_len = secrets ? g_strv_length ((char **) secrets) : 0;
	char **hints;
	guint32 i;

	nm_log_info (LOGD_VPN, "VPN plugin requested secrets; state %s (%d)",
	             vpn_state_to_string (priv->vpn_state), priv->vpn_state);

	g_return_if_fail (priv->vpn_state == STATE_CONNECT ||
	                  priv->vpn_state == STATE_NEED_AUTH);

	priv->secrets_idx = SECRETS_REQ_INTERACTIVE;
	_set_vpn_state (connection, STATE_NEED_AUTH, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);

	/* Copy hints and add message to the end */
	hints = g_malloc0 (sizeof (char *) * (secrets_len + 2));
	for (i = 0; i < secrets_len; i++)
		hints[i] = g_strdup (secrets[i]);
	if (message)
		hints[i] = g_strdup_printf ("x-vpn-message:%s", message);

	get_secrets (connection, SECRETS_REQ_INTERACTIVE, (const char **) hints);
	g_strfreev (hints);
}

/******************************************************************************/

static void
nm_vpn_connection_init (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	priv->vpn_state = STATE_WAITING;
	priv->secrets_idx = SECRETS_REQ_SYSTEM;
}

static void
constructed (GObject *object)
{
	NMConnection *connection;

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->constructed (object);

	connection = nm_active_connection_get_connection (NM_ACTIVE_CONNECTION (object));
	NM_VPN_CONNECTION_GET_PRIVATE (object)->connection = g_object_ref (connection);
}

static void
dispose (GObject *object)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);

	g_clear_pointer (&priv->connect_dict, g_variant_unref);

	if (priv->connect_timeout) {
		g_source_remove (priv->connect_timeout);
		priv->connect_timeout = 0;
	}

	dispatcher_cleanup (NM_VPN_CONNECTION (object));

	if (priv->secrets_id) {
		nm_settings_connection_cancel_secrets (NM_SETTINGS_CONNECTION (priv->connection),
		                                       priv->secrets_id);
		priv->secrets_id = 0;
	}

	g_clear_object (&priv->ip4_config);
	g_clear_object (&priv->ip6_config);
	g_clear_object (&priv->proxy);
	g_clear_object (&priv->connection);

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);

	g_free (priv->banner);
	g_free (priv->ip_iface);
	g_free (priv->username);
	g_free (priv->ip6_internal_gw);
	g_free (priv->ip6_external_gw);

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->finalize (object);
}

static gboolean
ip_config_valid (VpnState state)
{
	return (state == STATE_PRE_UP || state == STATE_ACTIVATED);
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);
	NMDevice *parent_dev;

	switch (prop_id) {
	case PROP_VPN_STATE:
		g_value_set_uint (value, _state_to_nm_vpn_state (priv->vpn_state));
		break;
	case PROP_BANNER:
		g_value_set_string (value, priv->banner ? priv->banner : "");
		break;
	case PROP_IP4_CONFIG:
		if (ip_config_valid (priv->vpn_state) && priv->ip4_config)
			g_value_set_string (value, nm_ip4_config_get_dbus_path (priv->ip4_config));
		else
			g_value_set_string (value, "/");
		break;
	case PROP_IP6_CONFIG:
		if (ip_config_valid (priv->vpn_state) && priv->ip6_config)
			g_value_set_string (value, nm_ip6_config_get_dbus_path (priv->ip6_config));
		else
			g_value_set_string (value, "/");
		break;
	case PROP_MASTER:
		parent_dev = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (object));
		g_value_set_string (value, parent_dev ? nm_device_get_path (parent_dev) : "/");
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_vpn_connection_class_init (NMVpnConnectionClass *connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (connection_class);
	NMActiveConnectionClass *active_class = NM_ACTIVE_CONNECTION_CLASS (connection_class);

	g_type_class_add_private (connection_class, sizeof (NMVpnConnectionPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	active_class->device_state_changed = device_state_changed;

	g_object_class_override_property (object_class, PROP_MASTER, NM_ACTIVE_CONNECTION_MASTER);

	/* properties */
	g_object_class_install_property
		(object_class, PROP_VPN_STATE,
		 g_param_spec_uint (NM_VPN_CONNECTION_VPN_STATE, "", "",
		                    NM_VPN_CONNECTION_STATE_UNKNOWN,
		                    NM_VPN_CONNECTION_STATE_DISCONNECTED,
		                    NM_VPN_CONNECTION_STATE_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_BANNER,
		 g_param_spec_string (NM_VPN_CONNECTION_BANNER, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_override_property (object_class, PROP_IP4_CONFIG,
	                                  NM_ACTIVE_CONNECTION_IP4_CONFIG);
	g_object_class_override_property (object_class, PROP_IP6_CONFIG,
	                                  NM_ACTIVE_CONNECTION_IP6_CONFIG);

	/* signals */
	signals[VPN_STATE_CHANGED] =
		g_signal_new ("vpn-state-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);

	signals[INTERNAL_STATE_CHANGED] =
		g_signal_new (NM_VPN_CONNECTION_INTERNAL_STATE_CHANGED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 3, G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT);

	nm_object_class_add_interface (NM_OBJECT_CLASS (connection_class),
	                               NMDBUS_TYPE_VPN_CONNECTION,
	                               NULL);
}
