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
 * Copyright (C) 2006 - 2012 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "NetworkManagerUtils.h"
#include "nm-supplicant-interface.h"
#include "nm-supplicant-manager.h"
#include "nm-logging.h"
#include "nm-supplicant-config.h"
#include "nm-dbus-manager.h"
#include "nm-glib-compat.h"

#define WPAS_DBUS_IFACE_INTERFACE   WPAS_DBUS_INTERFACE ".Interface"
#define WPAS_DBUS_IFACE_BSS         WPAS_DBUS_INTERFACE ".BSS"
#define WPAS_DBUS_IFACE_NETWORK	    WPAS_DBUS_INTERFACE ".Network"
#define WPAS_ERROR_INVALID_IFACE    WPAS_DBUS_INTERFACE ".InvalidInterface"
#define WPAS_ERROR_EXISTS_ERROR     WPAS_DBUS_INTERFACE ".InterfaceExists"

G_DEFINE_TYPE (NMSupplicantInterface, nm_supplicant_interface, G_TYPE_OBJECT)

static void wpas_iface_get_props (NMSupplicantInterface *self);

static void iface_proxy_signal (GDBusProxy *proxy,
                                const char *sender_name,
                                const char *signal_name,
                                GVariant   *parameters,
                                gpointer    user_data);

#define NM_SUPPLICANT_INTERFACE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                                 NM_TYPE_SUPPLICANT_INTERFACE, \
                                                 NMSupplicantInterfacePrivate))

/* Signals */
enum {
	STATE,               /* change in the interface's state */
	REMOVED,             /* interface was removed by the supplicant */
	NEW_BSS,             /* interface saw a new access point from a scan */
	BSS_UPDATED,         /* a BSS property changed */
	BSS_REMOVED,         /* supplicant removed BSS from its scan list */
	SCAN_DONE,           /* wifi scan is complete */
	CONNECTION_ERROR,    /* an error occurred during a connection request */
	CREDENTIALS_REQUEST, /* 802.1x identity or password requested */
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };


/* Properties */
enum {
	PROP_0 = 0,
	PROP_SCANNING,
	LAST_PROP
};


typedef struct {
	NMSupplicantManager * smgr;
	gulong                smgr_avail_id;
	NMDBusManager *       dbus_mgr;
	char *                dev;
	gboolean              is_wireless;
	gboolean              has_credreq;  /* Whether querying 802.1x credentials is supported */
	ApSupport             ap_support;   /* Lightweight AP mode support */
	gboolean              fast_supported;
	guint32               max_scan_ssids;
	guint32               ready_count;

	char *                object_path;
	guint32               state;
	int                   disconnect_reason;
	GCancellable *        assoc_cancellable;
	GCancellable *        other_cancellable;

	gboolean              scanning;

	GDBusProxy *          wpas_proxy;
	GDBusProxy *          introspect_proxy;
	GDBusProxy *          iface_proxy;
	GDBusProxy *          props_proxy;
	char *                net_path;
	guint32               blobs_left;
	GHashTable *          bss_proxies;

	gint32                last_scan; /* timestamp as returned by nm_utils_get_monotonic_timestamp_s() */

	NMSupplicantConfig *  cfg;

	gboolean              disposed;
} NMSupplicantInterfacePrivate;

static void
emit_error_helper (NMSupplicantInterface *self,
				   GError *err)
{
	char *name = NULL;

	name = g_dbus_error_get_remote_error (err);
	g_dbus_error_strip_remote_error (err);

	g_signal_emit (self, signals[CONNECTION_ERROR], 0, name, err->message);
	g_free (name);
}

static void
signal_new_bss (NMSupplicantInterface *self,
                const char *object_path,
                GVariant *props)
{
	g_signal_emit (self, signals[NEW_BSS], 0, object_path, props);
}

static void
bssid_properties_cb  (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	GError *error = NULL;
	GVariant *ret;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free (error);
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (ret) {
		GVariant *props;

		g_variant_get (ret, "(@a{sv})", &props);
		signal_new_bss (self, g_dbus_proxy_get_object_path (G_DBUS_PROXY (proxy)), props);
		g_variant_unref (props);
		g_variant_unref (ret);
	} else {
		if (!strstr (error->message, "The BSSID requested was invalid")) {
			nm_log_warn (LOGD_SUPPLICANT, "Couldn't retrieve BSSID properties: %s.",
			             error->message);
		}
		g_error_free (error);
	}
}

static void
bss_proxy_signal (GDBusProxy *proxy,
                  const char *sender_name,
                  const char *signal_name,
                  GVariant   *parameters,
                  gpointer    user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (   !strcmp (signal_name, "PropertiesChanged")
	    && g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sa{sv}as)"))) {
		const char *interface;

		if (priv->scanning)
			priv->last_scan = nm_utils_get_monotonic_timestamp_s ();

		g_variant_get (parameters, "(&sa{sv}as)", &interface, NULL, NULL);
		if (g_strcmp0 (interface, WPAS_DBUS_IFACE_BSS) == 0)
			g_signal_emit (self, signals[BSS_UPDATED], 0, g_dbus_proxy_get_object_path (proxy));
	}
}

static void
handle_new_bss (NMSupplicantInterface *self,
                const char *object_path,
                GVariant *props)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GDBusProxy *bss_proxy;

	g_return_if_fail (object_path != NULL);

	if (g_hash_table_lookup (priv->bss_proxies, object_path))
		return;

	bss_proxy = g_dbus_proxy_new_sync (nm_dbus_manager_get_connection (nm_dbus_manager_get ()),
	                                   G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                                   NULL,
	                                   WPAS_DBUS_SERVICE,
	                                   object_path,
	                                   "org.freedesktop.DBus.Properties",
	                                   NULL, NULL);
	g_hash_table_insert (priv->bss_proxies,
	                     (gpointer) g_dbus_proxy_get_object_path (bss_proxy),
	                     bss_proxy);

	// FIXME: let GDBusProxy handle properties
	g_signal_connect (bss_proxy, "g-signal",
	                  G_CALLBACK (bss_proxy_signal), self);

	if (props) {
		signal_new_bss (self, object_path, props);
	} else {
		g_dbus_proxy_call (bss_proxy,
		                   "GetAll",
		                   g_variant_new ("(s)", WPAS_DBUS_IFACE_BSS),
		                   G_DBUS_CALL_FLAGS_NONE, -1,
		                   priv->other_cancellable,
		                   bssid_properties_cb, self);
	}
}

static void
wpas_iface_bss_added (NMSupplicantInterface *self,
                      const char *object_path,
                      GVariant *props)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (priv->scanning)
		priv->last_scan = nm_utils_get_monotonic_timestamp_s ();

	handle_new_bss (self, object_path, props);
}

static void
wpas_iface_bss_removed (NMSupplicantInterface *self,
                        const char *object_path)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	g_signal_emit (self, signals[BSS_REMOVED], 0, object_path);

	g_hash_table_remove (priv->bss_proxies, object_path);
}

static int
wpas_state_string_to_enum (const char *str_state)
{
	if (!strcmp (str_state, "interface_disabled"))
		return NM_SUPPLICANT_INTERFACE_STATE_DISABLED;
	else if (!strcmp (str_state, "disconnected"))
		return NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED;
	else if (!strcmp (str_state, "inactive"))
		return NM_SUPPLICANT_INTERFACE_STATE_INACTIVE;
	else if (!strcmp (str_state, "scanning"))
		return NM_SUPPLICANT_INTERFACE_STATE_SCANNING;
	else if (!strcmp (str_state, "authenticating"))
		return NM_SUPPLICANT_INTERFACE_STATE_AUTHENTICATING;
	else if (!strcmp (str_state, "associating"))
		return NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATING;
	else if (!strcmp (str_state, "associated"))
		return NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATED;
	else if (!strcmp (str_state, "4way_handshake"))
		return NM_SUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE;
	else if (!strcmp (str_state, "group_handshake"))
		return NM_SUPPLICANT_INTERFACE_STATE_GROUP_HANDSHAKE;
	else if (!strcmp (str_state, "completed"))
		return NM_SUPPLICANT_INTERFACE_STATE_COMPLETED;

	nm_log_warn (LOGD_SUPPLICANT, "Unknown supplicant state '%s'", str_state);
	return -1;
}

static void
set_state (NMSupplicantInterface *self, guint32 new_state)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	guint32 old_state = priv->state;

	g_return_if_fail (new_state < NM_SUPPLICANT_INTERFACE_STATE_LAST);

	if (new_state == priv->state)
		return;

	/* DOWN is a terminal state */
	g_return_if_fail (priv->state != NM_SUPPLICANT_INTERFACE_STATE_DOWN);

	/* Cannot regress to READY, STARTING, or INIT from higher states */
	if (priv->state >= NM_SUPPLICANT_INTERFACE_STATE_READY)
		g_return_if_fail (new_state > NM_SUPPLICANT_INTERFACE_STATE_READY);

	if (new_state == NM_SUPPLICANT_INTERFACE_STATE_READY) {
		/* Get properties again to update to the actual wpa_supplicant
		 * interface state.
		 */
		wpas_iface_get_props (self);
	} else if (new_state == NM_SUPPLICANT_INTERFACE_STATE_DOWN) {
		/* Cancel all pending calls when going down */
		g_cancellable_cancel (priv->other_cancellable);
		g_object_unref (priv->other_cancellable);
		priv->other_cancellable = g_cancellable_new ();

		g_cancellable_cancel (priv->assoc_cancellable);
		g_object_unref (priv->assoc_cancellable);
		priv->assoc_cancellable = g_cancellable_new ();

		/* Disconnect supplicant manager state listeners since we're done */
		if (priv->smgr_avail_id) {
			g_signal_handler_disconnect (priv->smgr, priv->smgr_avail_id);
			priv->smgr_avail_id = 0;
		}

		if (priv->iface_proxy) {
			g_signal_handlers_disconnect_by_func (priv->iface_proxy,
			                                      G_CALLBACK (iface_proxy_signal),
			                                      self);
		}
	}

	priv->state = new_state;

	if (   priv->state == NM_SUPPLICANT_INTERFACE_STATE_SCANNING
	    || old_state == NM_SUPPLICANT_INTERFACE_STATE_SCANNING)
		priv->last_scan = nm_utils_get_monotonic_timestamp_s ();

	/* Disconnect reason is no longer relevant when not in the DISCONNECTED state */
	if (priv->state != NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED)
		priv->disconnect_reason = 0;

	g_signal_emit (self, signals[STATE], 0,
	               priv->state,
	               old_state,
	               priv->disconnect_reason);
}

static void
set_state_from_string (NMSupplicantInterface *self, const char *new_state)
{
	int state;

	state = wpas_state_string_to_enum (new_state);
	g_warn_if_fail (state > 0);
	if (state > 0)
		set_state (self, (guint32) state);
}

static void
set_scanning (NMSupplicantInterface *self, gboolean new_scanning)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (priv->scanning != new_scanning) {
		priv->scanning = new_scanning;

		/* Cache time of last scan completion */
		if (priv->scanning == FALSE)
			priv->last_scan = nm_utils_get_monotonic_timestamp_s ();

		g_object_notify (G_OBJECT (self), "scanning");
	}
}

gboolean
nm_supplicant_interface_get_scanning (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv;

	g_return_val_if_fail (self != NULL, FALSE);

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	if (priv->scanning)
		return TRUE;
	if (priv->state == NM_SUPPLICANT_INTERFACE_STATE_SCANNING)
		return TRUE;
	return FALSE;
}

gint32
nm_supplicant_interface_get_last_scan_time (NMSupplicantInterface *self)
{
	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->last_scan;
}

static void
wpas_iface_scan_done (NMSupplicantInterface *self,
                      gboolean success)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Cache last scan completed time */
	priv->last_scan = nm_utils_get_monotonic_timestamp_s ();
	g_signal_emit (self, signals[SCAN_DONE], 0, success);
}

static void
parse_capabilities (NMSupplicantInterface *self, GVariant *props)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	gboolean have_active = FALSE, have_ssid = FALSE;
	char **vals;
	gint32 max_scan_ssid;

	g_return_if_fail (props != NULL);

	if (g_variant_lookup (props, "Scan", "^a&s", &vals)) {
		char **iter = vals;

		while (iter && *iter && (!have_active || !have_ssid)) {
			if (g_strcmp0 (*iter, "active") == 0)
				have_active = TRUE;
			else if (g_strcmp0 (*iter, "ssid") == 0)
				have_ssid = TRUE;
			iter++;
		}

		g_free (vals);
	}

	if (g_variant_lookup (props, "MaxScanSSID", "i", &max_scan_ssid)) {
		/* We need active scan and SSID probe capabilities to care about MaxScanSSIDs */
		if (have_active && have_ssid) {
			/* wpa_supplicant's WPAS_MAX_SCAN_SSIDS value is 16, but for speed
			 * and to ensure we don't disclose too many SSIDs from the hidden
			 * list, we'll limit to 5.
			 */
			priv->max_scan_ssids = CLAMP (max_scan_ssid, 0, 5);
			nm_log_info (LOGD_SUPPLICANT, "(%s) supports %d scan SSIDs",
			             priv->dev, priv->max_scan_ssids);
		}
	}
}

static void
wpas_iface_properties_changed (NMSupplicantInterface *self,
                               GVariant *props)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	gboolean scanning;
	const char *state;
	char **paths;
	GVariant *capabilities;
	gint32 disconnect_reason;

	if (g_variant_lookup (props, "Scanning", "b", &scanning))
		set_scanning (self, scanning);

	if (g_variant_lookup (props, "State", "&s", &state)) {
		if (priv->state >= NM_SUPPLICANT_INTERFACE_STATE_READY) {
			/* Only transition to actual wpa_supplicant interface states (ie,
			 * anything > READY) after the NMSupplicantInterface has had a
			 * chance to initialize, which is signalled by entering the READY
			 * state.
			 */
			set_state_from_string (self, state);
		}
	}

	if (g_variant_lookup (props, "BSSs", "^a&o", &paths)) {
		int i;

		for (i = 0; paths[i]; i++)
			handle_new_bss (self, paths[i], NULL);
		g_free (paths);
	}

	if (g_variant_lookup (props, "Capabilities", "@a{sv}", &capabilities)) {
		parse_capabilities (self, capabilities);
		g_variant_unref (capabilities);
	}

	/* Disconnect reason is currently only given for deauthentication events,
	 * not disassociation; currently they are IEEE 802.11 "reason codes",
	 * defined by (IEEE 802.11-2007, 7.3.1.7, Table 7-22).  Any locally caused
	 * deauthentication will be negative, while authentications caused by the
	 * AP will be positive.
	 */
	if (g_variant_lookup (props, "DisconnectReason", "i", &disconnect_reason)) {
		priv->disconnect_reason = disconnect_reason;
		if (priv->disconnect_reason != 0) {
			nm_log_warn (LOGD_SUPPLICANT, "Connection disconnected (reason %d)",
			             priv->disconnect_reason);
		}
	}
}

static void
iface_check_ready (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (priv->ready_count && priv->state < NM_SUPPLICANT_INTERFACE_STATE_READY) {
		priv->ready_count--;
		if (priv->ready_count == 0)
			set_state (self, NM_SUPPLICANT_INTERFACE_STATE_READY);
	}
}

static void
iface_get_props_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	GVariant *props = NULL;
	GVariant *ret;
	GError *error = NULL;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free (error);
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (ret) {
		g_variant_get (ret, "(@a{sv})", &props);
		wpas_iface_properties_changed (self, props);
		g_variant_unref (props);
		g_variant_unref (ret);
	} else {
		nm_log_warn (LOGD_SUPPLICANT, "could not get interface properties: %s.",
		             error->message);
		g_clear_error (&error);
	}
	iface_check_ready (self);
}

static void
wpas_iface_get_props (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	// FIXME: we should be letting GDBusProxy handle properties

	g_dbus_proxy_call (priv->props_proxy,
	                   "GetAll",
	                   g_variant_new ("(s)", WPAS_DBUS_IFACE_INTERFACE),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   priv->other_cancellable,
	                   iface_get_props_cb, self);
}

gboolean
nm_supplicant_interface_credentials_reply (NMSupplicantInterface *self,
                                           const char *field,
                                           const char *value,
                                           GError **error)
{
	NMSupplicantInterfacePrivate *priv;
	GVariant *ret;

	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	g_return_val_if_fail (priv->has_credreq == TRUE, FALSE);

	/* Need a network block object path */
	g_return_val_if_fail (priv->net_path, FALSE);
	ret = g_dbus_proxy_call_sync (priv->iface_proxy,
	                              "NetworkReply",
	                              g_variant_new ("(oss)", priv->net_path, field, value),
	                              G_DBUS_CALL_FLAGS_NONE, 5000,
	                              NULL, error);
	if (ret) {
		g_variant_unref (ret);
		return TRUE;
	} else
		return FALSE;
}

static void
wpas_iface_network_request (NMSupplicantInterface *self,
                            const char *object_path,
                            const char *field,
                            const char *message)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	g_return_if_fail (priv->has_credreq == TRUE);
	g_return_if_fail (priv->net_path != NULL);
	g_return_if_fail (g_strcmp0 (object_path, priv->net_path) == 0);

	g_signal_emit (self, signals[CREDENTIALS_REQUEST], 0, field, message);
}

static void
iface_check_netreply_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	GVariant *ret;
	GError *error = NULL;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free (error);
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* We know NetworkReply is supported if the NetworkReply method returned
	 * successfully (which is unexpected since we sent a bogus network
	 * object path) or if we got an "InvalidArgs" (which indicates NetworkReply
	 * is supported).  We know it's not supported if we get an
	 * "UnknownMethod" error.
	 */
	if (ret) {
		g_variant_unref (ret);
		priv->has_credreq = TRUE;
	} else {
		char *remote_error;

		remote_error = g_dbus_error_get_remote_error (error);
		if (!g_strcmp0 (remote_error, "fi.w1.wpa_supplicant1.InvalidArgs"))
			priv->has_credreq = TRUE;
		g_free (remote_error);
		g_clear_error (&error);
	}

	nm_log_dbg (LOGD_SUPPLICANT, "Supplicant %s network credentials requests",
	            priv->has_credreq ? "supports" : "does not support");

	iface_check_ready (self);
}

static void
wpas_iface_check_network_reply (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	priv->ready_count++;
	g_dbus_proxy_call (priv->iface_proxy,
	                   "NetworkReply",
	                   g_variant_new ("(oss)",  "/foobaraasdfasdf", "foobar", "foobar"),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   priv->other_cancellable,
	                   iface_check_netreply_cb, self);
}

ApSupport
nm_supplicant_interface_get_ap_support (NMSupplicantInterface *self)
{
	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->ap_support;
}

void
nm_supplicant_interface_set_ap_support (NMSupplicantInterface *self,
                                        ApSupport ap_support)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Use the best indicator of support between the supplicant global
	 * Capabilities property and the interface's introspection data.
	 */
	if (ap_support > priv->ap_support)
		priv->ap_support = ap_support;
}

static void
iface_check_ap_mode_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	GVariant *ret;
	GError *error = NULL;
	const char *data;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free (error);
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* The ProbeRequest method only exists if AP mode has been enabled */
	if (ret) {
		g_variant_get (ret, "(&s)", &data);
		if (strstr (data, "ProbeRequest"))
			priv->ap_support = AP_SUPPORT_YES;
		g_variant_unref (ret);
	}

	iface_check_ready (self);
}

static void
wpas_iface_check_ap_mode (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	priv->ready_count++;

	/* If the global supplicant capabilities property is not present, we can
	 * fall back to checking whether the ProbeRequest method is supported.  If
	 * neither of these works we have no way of determining if AP mode is
	 * supported or not.  hostap 1.0 and earlier don't support either of these.
	 */
	g_dbus_proxy_call (priv->introspect_proxy,
	                   "Introspect",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   priv->other_cancellable,
	                   iface_check_ap_mode_cb, self);
}

static void
iface_proxy_signal (GDBusProxy *proxy,
                    const char *sender_name,
                    const char *signal_name,
                    GVariant   *parameters,
                    gpointer    user_data)
{
	NMSupplicantInterface *self = user_data;

	if (   !strcmp (signal_name, "PropertiesChanged")
	    && g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(a{sv})"))) {
		GVariant *props;

		g_variant_get (parameters, "(@a{sv})", &props);
		wpas_iface_properties_changed (self, props);
		g_variant_unref (props);
	} else if (   !strcmp (signal_name, "ScanDone")
	           && g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(b)"))) {
		gboolean done;

		g_variant_get (parameters, "(b)", &done);
		wpas_iface_scan_done (self, done);
	} else if (   !strcmp (signal_name, "BSSAdded")
	           && g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(oa{sv})"))) {
		const char *path;
		GVariant *props;

		g_variant_get (parameters, "(o@a{sv})", &path, &props);
		wpas_iface_bss_added (self, path, props);
		g_variant_unref (props);
	} else if (   !strcmp (signal_name, "BSSRemoved")
	           && g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(o)"))) {
		const char *path;

		g_variant_get (parameters, "(o)", &path);
		wpas_iface_bss_removed (self, path);
	} else if (   !strcmp (signal_name, "NetworkRequest")
	           && g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(oss)"))) {
		const char *path, *field, *message;

		g_variant_get (parameters, "(oss)", &path, &field, &message);
		wpas_iface_network_request (self, path, field, message);
	} else {
		nm_log_warn (LOGD_SUPPLICANT, "(%s): unknown %s signal received (%s %s)",
		             NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->dev,
		             WPAS_DBUS_IFACE_INTERFACE, signal_name,
		             g_variant_get_type_string (parameters));
	}
}

static void
interface_add_done (NMSupplicantInterface *self, char *path)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GDBusConnection *bus;

	nm_log_dbg (LOGD_SUPPLICANT, "(%s): interface added to supplicant", priv->dev);

	priv->object_path = path;

	bus = nm_dbus_manager_get_connection (nm_dbus_manager_get ());

	priv->iface_proxy = g_dbus_proxy_new_sync (bus,
	                                           G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                                           NULL,
	                                           WPAS_DBUS_SERVICE,
	                                           path,
	                                           WPAS_DBUS_IFACE_INTERFACE,
	                                           NULL, NULL);
	g_signal_connect (priv->iface_proxy, "g-signal",
	                  G_CALLBACK (iface_proxy_signal), self);

	priv->introspect_proxy = g_dbus_proxy_new_sync (bus,
	                                                G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                                                    G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
	                                                NULL,
	                                                WPAS_DBUS_SERVICE,
	                                                priv->object_path,
	                                                "org.freedesktop.DBus.Introspectable",
	                                                NULL, NULL);

	priv->props_proxy = g_dbus_proxy_new_sync (bus,
	                                           G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                                               G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
	                                           NULL,
	                                           WPAS_DBUS_SERVICE,
	                                           path,
	                                           "org.freedesktop.DBus.Properties",
	                                           NULL, NULL);

	/* Get initial properties and check whether NetworkReply is supported */
	priv->ready_count = 1;
	wpas_iface_get_props (self);

	/* These two increment ready_count themselves */
	wpas_iface_check_network_reply (self);
	if (priv->ap_support == AP_SUPPORT_UNKNOWN)
		wpas_iface_check_ap_mode (self);
}

static void
interface_get_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	GVariant *ret;
	GError *error = NULL;
	char *path = NULL;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free (error);
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (ret) {
		g_variant_get (ret, "(o)", &path);
		g_variant_unref (ret);
		interface_add_done (self, path);
	} else {
		nm_log_err (LOGD_SUPPLICANT, "(%s): error getting interface: %s",
		            priv->dev, error->message);
		g_clear_error (&error);
		set_state (self, NM_SUPPLICANT_INTERFACE_STATE_DOWN);
	}
}

static void
interface_get (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	g_dbus_proxy_call (priv->wpas_proxy,
	                   "GetInterface",
	                   g_variant_new ("(s)", priv->dev),
	                   G_DBUS_CALL_FLAGS_NONE, 0,
	                   priv->other_cancellable,
	                   interface_get_cb, self);
}

static void
interface_add_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	GVariant *ret;
	GError *error = NULL;
	char *path = NULL;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free (error);
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (ret) {
		g_variant_get (ret, "(o)", &path);
		g_variant_unref (ret);
		interface_add_done (self, path);
	} else {
		char *remote_error = g_dbus_error_get_remote_error (error);

		if (!g_strcmp0 (remote_error, WPAS_ERROR_EXISTS_ERROR)) {
			/* Interface already added, just get its object path */
			interface_get (self);
		} else if (   g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN)
		           || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SPAWN_EXEC_FAILED)
		           || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SPAWN_FORK_FAILED)
		           || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SPAWN_FAILED)
		           || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_TIMEOUT)
		           || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_NO_REPLY)
		           || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_TIMED_OUT)
		           || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SPAWN_SERVICE_NOT_FOUND)) {
			/* Supplicant wasn't running and could not be launched via service
			 * activation.  Wait for it to start by moving back to the INIT
			 * state.
			 */
			nm_log_dbg (LOGD_SUPPLICANT, "(%s): failed to activate supplicant: %s",
			            priv->dev, error->message);
			set_state (self, NM_SUPPLICANT_INTERFACE_STATE_INIT);
		} else {
			nm_log_err (LOGD_SUPPLICANT, "(%s): error adding interface: %s",
			            priv->dev, error->message);
			set_state (self, NM_SUPPLICANT_INTERFACE_STATE_DOWN);
		}
		g_free (remote_error);
		g_clear_error (&error);
	}
}

#if HAVE_WEXT
#define DEFAULT_WIFI_DRIVER "nl80211,wext"
#else
#define DEFAULT_WIFI_DRIVER "nl80211"
#endif

static void
interface_add (NMSupplicantInterface *self, gboolean is_wireless)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GVariantBuilder param_builder;

	/* Can only start the interface from INIT state */
	g_return_if_fail (priv->state == NM_SUPPLICANT_INTERFACE_STATE_INIT);

	nm_log_dbg (LOGD_SUPPLICANT, "(%s): adding interface to supplicant", priv->dev);

	/* Move to starting to prevent double-calls of interface_add() */
	set_state (self, NM_SUPPLICANT_INTERFACE_STATE_STARTING);

	/* Try to add the interface to the supplicant.  If the supplicant isn't
	 * running, this will start it via D-Bus activation and return the response
	 * when the supplicant has started.
	 */
	g_variant_builder_init (&param_builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&param_builder, "{sv}",
	                       "Driver",
	                       g_variant_new_string (is_wireless ? DEFAULT_WIFI_DRIVER : "wired"));
	g_variant_builder_add (&param_builder, "{sv}",
	                       "Ifname",
	                       g_variant_new_string (priv->dev));

	g_dbus_proxy_call (priv->wpas_proxy,
	                   "CreateInterface",
	                   g_variant_new ("(a{sv})", &param_builder),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   priv->other_cancellable,
	                   interface_add_cb, self);
}

static void
smgr_avail_cb (NMSupplicantManager *smgr,
               GParamSpec *pspec,
               gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (user_data);

	if (nm_supplicant_manager_available (smgr)) {
		/* This can happen if the supplicant couldn't be activated but
		 * for some reason was started after the activation failure.
		 */
		if (priv->state == NM_SUPPLICANT_INTERFACE_STATE_INIT)
			interface_add (self, priv->is_wireless);
	} else {
		/* The supplicant stopped; so we must tear down the interface */
		set_state (self, NM_SUPPLICANT_INTERFACE_STATE_DOWN);
	}
}

static void
remove_network_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	GVariant *ret;
	GError *error = NULL;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &error);
	if (ret)
		g_variant_unref (ret);
	else {
		nm_log_dbg (LOGD_SUPPLICANT, "Couldn't remove network from supplicant interface: %s.",
		            error->message);
		g_clear_error (&error);
	}
}

static void
disconnect_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	GVariant *ret;
	GError *error = NULL;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &error);
	if (ret)
		g_variant_unref (ret);
	else {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't disconnect supplicant interface: %s.",
		             error->message);
		g_clear_error (&error);
	}
}

void
nm_supplicant_interface_disconnect (NMSupplicantInterface * self)
{
	NMSupplicantInterfacePrivate *priv;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Cancel all pending calls related to a prior connection attempt. */
	g_cancellable_cancel (priv->assoc_cancellable);
	g_object_unref (priv->assoc_cancellable);
	priv->assoc_cancellable = g_cancellable_new ();

	/* Don't do anything if there is no connection to the supplicant yet. */
	if (!priv->iface_proxy)
		return;

	/* Disconnect from the current AP */
	if (   (priv->state >= NM_SUPPLICANT_INTERFACE_STATE_SCANNING)
	    && (priv->state <= NM_SUPPLICANT_INTERFACE_STATE_COMPLETED)) {
		g_dbus_proxy_call (priv->iface_proxy,
		                   "Disconnect",
		                   NULL,
		                   G_DBUS_CALL_FLAGS_NONE, -1,
		                   NULL,
		                   disconnect_cb, NULL);
	}

	/* Remove any network that was added by NetworkManager */
	if (priv->net_path) {
		g_dbus_proxy_call (priv->iface_proxy,
		                   "RemoveNetwork",
		                   g_variant_new ("(o)", priv->net_path),
		                   G_DBUS_CALL_FLAGS_NONE, -1,
		                   NULL,
		                   remove_network_cb, NULL);
		g_free (priv->net_path);
		priv->net_path = NULL;
	}
}

static void
select_network_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	GVariant *ret;
	GError *err = NULL;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &err);
	if (g_error_matches (err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free (err);
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (!ret) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't select network config: %s.", err->message);
		emit_error_helper (self, err);
		g_error_free (err);
	} else
		g_variant_unref (ret);
}

static void
call_select_network (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* We only select the network after all blobs (if any) have been set */
	if (priv->blobs_left == 0) {
		g_dbus_proxy_call (priv->iface_proxy,
		                   "SelectNetwork",
		                   g_variant_new ("(o)", priv->net_path),
		                   G_DBUS_CALL_FLAGS_NONE, -1,
		                   priv->assoc_cancellable,
		                   select_network_cb, self);
	}
}

static void
add_blob_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	GVariant *ret;
	GError *err = NULL;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &err);
	if (g_error_matches (err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free (err);
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	priv->blobs_left--;

	if (!ret) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't set network certificates: %s.", err->message);
		emit_error_helper (self, err);
		g_error_free (err);
	} else
		g_variant_unref (ret);

	call_select_network (self);
}

static void
add_network_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	GError *err = NULL;
	GVariant *blobs;
	GVariantIter iter;
	const char *name;
	GVariant *ret, *data;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &err);
	if (g_error_matches (err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free (err);
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (!ret) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't add a network to the supplicant interface: %s.",
		             err->message);
		emit_error_helper (self, err);
		g_error_free (err);
		return;
	}

	g_free (priv->net_path);
	priv->net_path = NULL;
	g_variant_get (ret, "(o)", &priv->net_path);
	g_variant_unref (ret);

	/* Send blobs first; otherwise jump to sending the config settings */
	blobs = nm_supplicant_config_get_blobs (priv->cfg);
	priv->blobs_left = g_variant_n_children (blobs);
	g_variant_iter_init (&iter, blobs);
	while (g_variant_iter_next (&iter, "{&s@ay}", &name, &data)) {
		g_dbus_proxy_call (priv->iface_proxy,
		                   "AddBlob",
		                   g_variant_new ("(s@ay)", name, data),
		                   G_DBUS_CALL_FLAGS_NONE, -1,
		                   priv->assoc_cancellable,
		                   add_blob_cb, self);
		g_variant_unref (data);
	}

	call_select_network (self);
}

static void
set_ap_scan_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	GError *err = NULL;
	GVariant *ret, *config;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &err);
	if (g_error_matches (err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free (err);
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (!ret) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't send AP scan mode to the supplicant interface: %s.",
		             err->message);
		emit_error_helper (self, err);
		g_error_free (err);
		return;
	}

	g_variant_unref (ret);

	nm_log_info (LOGD_SUPPLICANT, "Config: set interface ap_scan to %d",
	             nm_supplicant_config_get_ap_scan (priv->cfg));

	config = nm_supplicant_config_get_config (priv->cfg);
	g_dbus_proxy_call (priv->iface_proxy,
	                   "AddNetwork",
	                   g_variant_new ("(@a{sv})", config),
	                   G_DBUS_CALL_FLAGS_NONE, 0,
	                   priv->assoc_cancellable,
	                   add_network_cb, self);
}

gboolean
nm_supplicant_interface_set_config (NMSupplicantInterface *self,
                                    NMSupplicantConfig *cfg)
{
	NMSupplicantInterfacePrivate *priv;

	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), FALSE);

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	nm_supplicant_interface_disconnect (self);

	/* Make sure the supplicant supports EAP-FAST before trying to send
	 * it an EAP-FAST configuration.
	 */
	if (nm_supplicant_config_fast_required (cfg) && !priv->fast_supported) {
		nm_log_warn (LOGD_SUPPLICANT, "EAP-FAST is not supported by the supplicant");
		return FALSE;
	}

	if (priv->cfg)
		g_object_unref (priv->cfg);
	priv->cfg = cfg;

	if (cfg == NULL)
		return TRUE;

	g_object_ref (priv->cfg);

	g_dbus_proxy_call (priv->props_proxy,
	                   "Set",
	                   g_variant_new ("(ssv)",
	                                  WPAS_DBUS_IFACE_INTERFACE,
	                                  "ApScan",
	                                  g_variant_new_uint32 (nm_supplicant_config_get_ap_scan (priv->cfg))),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   priv->assoc_cancellable,
	                   set_ap_scan_cb, self);
	return TRUE;
}

static void
scan_request_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	GVariant *ret;
	GError *err = NULL;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &err);
	if (g_error_matches (err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free (err);
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);

	if (!ret)
		nm_log_warn (LOGD_SUPPLICANT, "Could not get scan request result: %s", err->message);
	else
		g_variant_unref (ret);

	g_signal_emit (self, signals[SCAN_DONE], 0, err ? FALSE : TRUE);
	g_clear_error (&err);
}

static GVariant *
byte_array_array_to_gvariant (const GPtrArray *array)
{
	GVariantBuilder builder;
	GByteArray *ba;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aay"));
	for (i = 0; i < array->len; i++) {
		ba = array->pdata[i];
		g_variant_builder_add (&builder, "@ay", g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                                                   ba->data,
		                                                                   ba->len,
		                                                                   1));
	}

	return g_variant_builder_end (&builder);
}

void
nm_supplicant_interface_request_scan (NMSupplicantInterface *self, const GPtrArray *ssids)
{
	NMSupplicantInterfacePrivate *priv;
	GVariantBuilder param_builder;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Scan parameters */
	g_variant_builder_init (&param_builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&param_builder, "{sv}", "Type", g_variant_new_string ("active"));
	if (ssids)
		g_variant_builder_add (&param_builder, "{sv}", "SSIDs", byte_array_array_to_gvariant (ssids));

	g_dbus_proxy_call (priv->iface_proxy,
	                   "Scan",
	                   g_variant_new ("a{sv}", &param_builder),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   priv->other_cancellable,
	                   scan_request_cb, self);
}

guint32
nm_supplicant_interface_get_state (NMSupplicantInterface * self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NM_SUPPLICANT_INTERFACE_STATE_DOWN);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->state;
}

const char *
nm_supplicant_interface_state_to_string (guint32 state)
{
	switch (state) {
	case NM_SUPPLICANT_INTERFACE_STATE_INIT:
		return "init";
	case NM_SUPPLICANT_INTERFACE_STATE_STARTING:
		return "starting";
	case NM_SUPPLICANT_INTERFACE_STATE_READY:
		return "ready";
	case NM_SUPPLICANT_INTERFACE_STATE_DISABLED:
		return "disabled";
	case NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED:
		return "disconnected";
	case NM_SUPPLICANT_INTERFACE_STATE_INACTIVE:
		return "inactive";
	case NM_SUPPLICANT_INTERFACE_STATE_SCANNING:
		return "scanning";
	case NM_SUPPLICANT_INTERFACE_STATE_AUTHENTICATING:
		return "authenticating";
	case NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATING:
		return "associating";
	case NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATED:
		return "associated";
	case NM_SUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE:
		return "4-way handshake";
	case NM_SUPPLICANT_INTERFACE_STATE_GROUP_HANDSHAKE:
		return "group handshake";
	case NM_SUPPLICANT_INTERFACE_STATE_COMPLETED:
		return "completed";
	case NM_SUPPLICANT_INTERFACE_STATE_DOWN:
		return "down";
	default:
		break;
	}
	return "unknown";
}

const char *
nm_supplicant_interface_get_device (NMSupplicantInterface * self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NULL);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->dev;
}

const char *
nm_supplicant_interface_get_object_path (NMSupplicantInterface *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NULL);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->object_path;
}

const char *
nm_supplicant_interface_get_ifname (NMSupplicantInterface *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NULL);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->dev;
}

guint
nm_supplicant_interface_get_max_scan_ssids (NMSupplicantInterface *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), 0);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->max_scan_ssids;
}

/*******************************************************************/

NMSupplicantInterface *
nm_supplicant_interface_new (NMSupplicantManager *smgr,
                             const char *ifname,
                             gboolean is_wireless,
                             gboolean fast_supported,
                             ApSupport ap_support,
                             gboolean start_now)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	guint id;

	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (smgr), NULL);
	g_return_val_if_fail (ifname != NULL, NULL);

	self = g_object_new (NM_TYPE_SUPPLICANT_INTERFACE, NULL);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	priv->smgr = g_object_ref (smgr);
	id = g_signal_connect (priv->smgr,
	                       "notify::" NM_SUPPLICANT_MANAGER_AVAILABLE,
	                       G_CALLBACK (smgr_avail_cb),
	                       self);
	priv->smgr_avail_id = id;

	priv->dev = g_strdup (ifname);
	priv->is_wireless = is_wireless;
	priv->fast_supported = fast_supported;
	priv->ap_support = ap_support;

	if (start_now)
		interface_add (self, priv->is_wireless);

	return self;
}

static void
nm_supplicant_interface_init (NMSupplicantInterface * self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GDBusConnection *bus;

	priv->state = NM_SUPPLICANT_INTERFACE_STATE_INIT;
	priv->assoc_cancellable = g_cancellable_new ();
	priv->other_cancellable = g_cancellable_new ();

	bus = nm_dbus_manager_get_connection (nm_dbus_manager_get ());
	priv->wpas_proxy = g_dbus_proxy_new_sync (bus,
	                                          G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                                              G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
	                                          NULL,
	                                          WPAS_DBUS_SERVICE,
	                                          WPAS_DBUS_PATH,
	                                          WPAS_DBUS_INTERFACE,
	                                          NULL, NULL);

	priv->bss_proxies = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_SCANNING:
		g_value_set_boolean (value, NM_SUPPLICANT_INTERFACE_GET_PRIVATE (object)->scanning);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_supplicant_interface_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	if (priv->assoc_cancellable) {
		g_cancellable_cancel (priv->assoc_cancellable);
		g_clear_object (&priv->assoc_cancellable);
	}
	if (priv->other_cancellable) {
		g_cancellable_cancel (priv->other_cancellable);
		g_clear_object (&priv->other_cancellable);
	}

	if (priv->props_proxy)
		g_object_unref (priv->props_proxy);

	if (priv->iface_proxy)
		g_object_unref (priv->iface_proxy);

	g_free (priv->net_path);

	if (priv->introspect_proxy)
		g_object_unref (priv->introspect_proxy);

	if (priv->wpas_proxy)
		g_object_unref (priv->wpas_proxy);

	g_hash_table_destroy (priv->bss_proxies);

	if (priv->smgr) {
		if (priv->smgr_avail_id)
			g_signal_handler_disconnect (priv->smgr, priv->smgr_avail_id);
		g_object_unref (priv->smgr);
	}

	g_free (priv->dev);

	if (priv->cfg)
		g_object_unref (priv->cfg);

	g_free (priv->object_path);

	/* Chain up to the parent class */
	G_OBJECT_CLASS (nm_supplicant_interface_parent_class)->dispose (object);
}

static void
nm_supplicant_interface_class_init (NMSupplicantInterfaceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMSupplicantInterfacePrivate));

	object_class->dispose = dispose;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_SCANNING,
		 g_param_spec_boolean ("scanning", "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/* Signals */
	signals[STATE] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_STATE,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, state),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 3, G_TYPE_UINT, G_TYPE_UINT, G_TYPE_INT);

	signals[REMOVED] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	signals[NEW_BSS] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_NEW_BSS,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, new_bss),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_VARIANT);

	signals[BSS_UPDATED] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_BSS_UPDATED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, bss_updated),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_STRING);

	signals[BSS_REMOVED] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_BSS_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, bss_removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_STRING);

	signals[SCAN_DONE] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_SCAN_DONE,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, scan_done),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_BOOLEAN);

	signals[CONNECTION_ERROR] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_CONNECTION_ERROR,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, connection_error),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRING);

	signals[CREDENTIALS_REQUEST] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_CREDENTIALS_REQUEST,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, credentials_request),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRING);
}

