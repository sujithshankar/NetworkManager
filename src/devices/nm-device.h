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

#ifndef __NETWORKMANAGER_DEVICE_H__
#define __NETWORKMANAGER_DEVICE_H__

#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include <netinet/in.h>

#include "nm-dbus-interface.h"
#include "nm-types.h"
#include "nm-connection.h"
#include "nm-rfkill-manager.h"
#include "NetworkManagerUtils.h"

/* Properties */
#define NM_DEVICE_UDI              "udi"
#define NM_DEVICE_IFACE            "interface"
#define NM_DEVICE_IP_IFACE         "ip-interface"
#define NM_DEVICE_DRIVER           "driver"
#define NM_DEVICE_DRIVER_VERSION   "driver-version"
#define NM_DEVICE_FIRMWARE_VERSION "firmware-version"
#define NM_DEVICE_CAPABILITIES     "capabilities"
#define NM_DEVICE_CARRIER          "carrier"
#define NM_DEVICE_IP4_ADDRESS      "ip4-address"
#define NM_DEVICE_IP4_CONFIG       "ip4-config"
#define NM_DEVICE_DHCP4_CONFIG     "dhcp4-config"
#define NM_DEVICE_IP6_CONFIG       "ip6-config"
#define NM_DEVICE_DHCP6_CONFIG     "dhcp6-config"
#define NM_DEVICE_STATE            "state"
#define NM_DEVICE_STATE_REASON     "state-reason"
#define NM_DEVICE_ACTIVE_CONNECTION "active-connection"
#define NM_DEVICE_DEVICE_TYPE      "device-type" /* ugh */
#define NM_DEVICE_MANAGED          "managed"
#define NM_DEVICE_AUTOCONNECT      "autoconnect"
#define NM_DEVICE_FIRMWARE_MISSING "firmware-missing"
#define NM_DEVICE_AVAILABLE_CONNECTIONS "available-connections"
#define NM_DEVICE_PHYSICAL_PORT_ID "physical-port-id"
#define NM_DEVICE_MTU              "mtu"
#define NM_DEVICE_HW_ADDRESS       "hw-address"
#define NM_DEVICE_REAL             "real"

#define NM_DEVICE_TYPE_DESC        "type-desc"      /* Internal only */
#define NM_DEVICE_RFKILL_TYPE      "rfkill-type"    /* Internal only */
#define NM_DEVICE_IFINDEX          "ifindex"        /* Internal only */
#define NM_DEVICE_IS_MASTER        "is-master"      /* Internal only */
#define NM_DEVICE_MASTER           "master"         /* Internal only */
#define NM_DEVICE_HAS_PENDING_ACTION "has-pending-action" /* Internal only */

/* Internal signals */
#define NM_DEVICE_AUTH_REQUEST          "auth-request"
#define NM_DEVICE_IP4_CONFIG_CHANGED    "ip4-config-changed"
#define NM_DEVICE_IP6_CONFIG_CHANGED    "ip6-config-changed"
#define NM_DEVICE_REMOVED               "removed"
#define NM_DEVICE_RECHECK_AUTO_ACTIVATE "recheck-auto-activate"
#define NM_DEVICE_RECHECK_ASSUME        "recheck-assume"


G_BEGIN_DECLS

#define NM_TYPE_DEVICE			(nm_device_get_type ())
#define NM_DEVICE(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE, NMDevice))
#define NM_DEVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE, NMDeviceClass))
#define NM_IS_DEVICE(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE))
#define NM_IS_DEVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE))
#define NM_DEVICE_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE, NMDeviceClass))

typedef enum NMActStageReturn NMActStageReturn;

struct _NMDevice {
	GObject parent;
};

typedef struct {
	GObjectClass parent;

	const char *connection_type;

	void (*state_changed) (NMDevice *device,
	                       NMDeviceState new_state,
	                       NMDeviceState old_state,
	                       NMDeviceStateReason reason);

	void            (* link_changed) (NMDevice *self, NMPlatformLink *info);

	/**
	 * realize():
	 * @self: the #NMDevice
	 * @plink: the #NMPlatformLink if backed by a kernel netdevice
	 * @error: location to store error, or %NULL
	 *
	 * Realize the device from existing backing resources.  No resources
	 * should be created as a side-effect of this function.  This function
	 * should only fail if critical device properties/resources (eg, VLAN ID)
	 * fail to be read or initialized, that would cause the device to be
	 * unusable.  For example, for any properties required to realize the device
	 * during create_and_realize(), if reading those properties in realize()
	 * should fail, this function should probably return %FALSE and an error.
	 *
	 * Returns: %TRUE on success, %FALSE if some error ocurred when realizing
	 * the device from backing resources
	 */
	gboolean        (*realize) (NMDevice *self,
	                            NMPlatformLink *plink,
	                            GError **error);

	/**
	 * create_and_realize():
	 * @self: the #NMDevice
	 * @connection: the #NMConnection being activated
	 * @parent: the parent #NMDevice, if any
	 * @out_plink: on success, a backing kernel network device if one exists
	 * @error: location to store error, or %NULL
	 *
	 * Create any backing resources (kernel devices, etc) required for this
	 * device to activate @connection.  If the device is backed by a kernel
	 * network device, that device should be returned in @out_plink after
	 * being created.
	 *
	 * Returns: %TRUE on success, %FALSE on error
	 */
	gboolean        (*create_and_realize) (NMDevice *self,
	                                       NMConnection *connection,
	                                       NMDevice *parent,
	                                       NMPlatformLink *out_plink,
	                                       GError **error);

	/**
	 * setup():
	 * @self: the #NMDevice
	 * @plink: the #NMPlatformLink if backed by a kernel netdevice
	 *
	 * Update the device from backing resource properties (like hardware
	 * addresses, carrier states, driver/firmware info, etc).
	 */
	void        (*setup) (NMDevice *self, NMPlatformLink *plink);

	/**
	 * unrealize():
	 * @self: the #NMDevice
	 * @link_deleted: if %TRUE, the backing kernel resources are already deleted
	 * @error: location to store error, or %NULL
	 *
	 * Releases any backing resources (kernel devices, etc) created for this
	 * device and clears properties that depend on them.  Does not destroy
	 * the device object itself.
	 *
	 * Returns: %TRUE on success, %FALSE on error
	 */
	gboolean        (*unrealize)  (NMDevice *self, gboolean link_deleted, GError **error);

	/* Hardware state (IFF_UP) */
	gboolean        (*is_up)      (NMDevice *self);
	gboolean        (*bring_up)   (NMDevice *self, gboolean *no_firmware);
	gboolean        (*take_down)  (NMDevice *self);

	/* Carrier state (IFF_LOWER_UP) */
	void            (*carrier_changed) (NMDevice *, gboolean carrier);

	gboolean    (* get_ip_iface_identifier) (NMDevice *self, NMUtilsIPv6IfaceId *out_iid);

	guint32		(* get_generic_capabilities)	(NMDevice *self);

	gboolean	(* is_available) (NMDevice *self);

	gboolean    (* get_enabled) (NMDevice *self);

	void        (* set_enabled) (NMDevice *self, gboolean enabled);

	gboolean    (* can_auto_connect) (NMDevice *self,
	                                  NMConnection *connection,
	                                  char **specific_object);

	/* Checks whether the connection is compatible with the device using
	 * only the devices type and characteristics.  Does not use any live
	 * network information like WiFi/WiMAX scan lists etc.
	 */
	gboolean    (* check_connection_compatible) (NMDevice *self, NMConnection *connection);

	/* Checks whether the connection is likely available to be activated,
	 * including any live network information like scan lists.  The connection
	 * is checked against the object defined by @specific_object, if given.
	 * Returns TRUE if the connection is available; FALSE if not.
	 */
	gboolean    (* check_connection_available) (NMDevice *self,
	                                            NMConnection *connection,
	                                            const char *specific_object);

	/* Same as check_connection_available() but called if the connection
	 * is not present in the activating-connections array during activation,
	 * to give the device a chance to allow/deny the activation.  This is a
	 * hack only meant for hidden WiFi networks.
	 */
	gboolean    (* check_connection_available_wifi_hidden) (NMDevice *self,
	                                                        NMConnection *connection);

	gboolean    (* complete_connection)         (NMDevice *self,
	                                             NMConnection *connection,
	                                             const char *specific_object,
	                                             const GSList *existing_connections,
	                                             GError **error);

	NMActStageReturn	(* act_stage1_prepare)	(NMDevice *self,
	                                             NMDeviceStateReason *reason);
	NMActStageReturn	(* act_stage2_config)	(NMDevice *self,
	                                             NMDeviceStateReason *reason);
	NMActStageReturn	(* act_stage3_ip4_config_start) (NMDevice *self,
														 NMIP4Config **out_config,
														 NMDeviceStateReason *reason);
	NMActStageReturn	(* act_stage3_ip6_config_start) (NMDevice *self,
														 NMIP6Config **out_config,
														 NMDeviceStateReason *reason);
	NMActStageReturn	(* act_stage4_ip4_config_timeout)	(NMDevice *self,
	                                                         NMDeviceStateReason *reason);
	NMActStageReturn	(* act_stage4_ip6_config_timeout)	(NMDevice *self,
	                                                         NMDeviceStateReason *reason);

	/* Called right before IP config is set; use for setting MTU etc */
	void                (* ip4_config_pre_commit) (NMDevice *self, NMIP4Config *config);
	void                (* ip6_config_pre_commit) (NMDevice *self, NMIP6Config *config);

	void			(* deactivate)			(NMDevice *self);

	gboolean        (* spec_match_list)     (NMDevice *self, const GSList *specs);

	/* Update the connection with currently configured L2 settings */
	void            (* update_connection) (NMDevice *device, NMConnection *connection);

	gboolean (*master_update_slave_connection) (NMDevice *self,
	                                            NMDevice *slave,
	                                            NMConnection *connection,
	                                            GError **error);

	gboolean        (* enslave_slave) (NMDevice *self,
	                                   NMDevice *slave,
	                                   NMConnection *connection,
	                                   gboolean configure);

	gboolean        (* release_slave) (NMDevice *self,
	                                   NMDevice *slave,
	                                   gboolean configure);

	gboolean        (* have_any_ready_slaves) (NMDevice *self,
	                                           const GSList *slaves);

	gboolean        (* component_added) (NMDevice *self, GObject *component);

	gboolean        (* owns_iface) (NMDevice *self, const char *iface);

	NMConnection *  (* new_default_connection) (NMDevice *self);
} NMDeviceClass;

typedef void (*NMDeviceAuthRequestFunc) (NMDevice *device,
                                         DBusGMethodInvocation *context,
                                         GError *error,
                                         gpointer user_data);

GType nm_device_get_type (void);

const char *    nm_device_get_path (NMDevice *dev);
void            nm_device_dbus_export   (NMDevice *device);

void            nm_device_finish_init   (NMDevice *device);

const char *	nm_device_get_udi		(NMDevice *dev);
const char *	nm_device_get_iface		(NMDevice *dev);
int             nm_device_get_ifindex	(NMDevice *dev);
gboolean        nm_device_is_software   (NMDevice *dev);
gboolean        nm_device_is_real       (NMDevice *dev);
const char *	nm_device_get_ip_iface	(NMDevice *dev);
int             nm_device_get_ip_ifindex(NMDevice *dev);
const char *	nm_device_get_driver	(NMDevice *dev);
const char *	nm_device_get_driver_version	(NMDevice *dev);
const char *	nm_device_get_type_desc (NMDevice *dev);
NMDeviceType	nm_device_get_device_type	(NMDevice *dev);

int			nm_device_get_priority (NMDevice *dev);
guint32     nm_device_get_ip4_route_metric (NMDevice *dev);
guint32     nm_device_get_ip6_route_metric (NMDevice *dev);

const char *    nm_device_get_hw_address           (NMDevice *dev);
const char *    nm_device_get_permanent_hw_address (NMDevice *dev);
const char *    nm_device_get_initial_hw_address   (NMDevice *dev);

NMDhcp4Config * nm_device_get_dhcp4_config (NMDevice *dev);
NMDhcp6Config * nm_device_get_dhcp6_config (NMDevice *dev);

NMIP4Config *	nm_device_get_ip4_config	(NMDevice *dev);
void            nm_device_set_vpn4_config   (NMDevice *dev, NMIP4Config *config);

NMIP6Config *	nm_device_get_ip6_config	(NMDevice *dev);
void            nm_device_set_vpn6_config   (NMDevice *dev, NMIP6Config *config);

void            nm_device_capture_initial_config (NMDevice *dev);

/* Master */
GSList *        nm_device_master_get_slaves (NMDevice *dev);

/* Slave */
NMDevice *      nm_device_get_master        (NMDevice *dev);

NMActRequest *	nm_device_get_act_request	(NMDevice *dev);
NMConnection *  nm_device_get_connection	(NMDevice *dev);

void            nm_device_removed        (NMDevice *dev);

gboolean        nm_device_is_available   (NMDevice *dev);
gboolean        nm_device_has_carrier    (NMDevice *dev);

NMConnection * nm_device_generate_connection (NMDevice *self, NMDevice *master);

gboolean nm_device_master_update_slave_connection (NMDevice *master,
                                                   NMDevice *slave,
                                                   NMConnection *connection,
                                                   GError **error);

gboolean nm_device_can_auto_connect (NMDevice *self,
                                     NMConnection *connection,
                                     char **specific_object);

gboolean nm_device_complete_connection (NMDevice *device,
                                        NMConnection *connection,
                                        const char *specific_object,
                                        const GSList *existing_connection,
                                        GError **error);

gboolean nm_device_check_connection_compatible (NMDevice *device, NMConnection *connection);

gboolean nm_device_uses_assumed_connection (NMDevice *device);

gboolean nm_device_can_assume_active_connection (NMDevice *device);

gboolean nm_device_spec_match_list (NMDevice *device, const GSList *specs);

gboolean		nm_device_is_activating		(NMDevice *dev);
gboolean		nm_device_autoconnect_allowed	(NMDevice *self);

NMDeviceState nm_device_get_state (NMDevice *device);

gboolean nm_device_get_enabled (NMDevice *device);

void nm_device_set_enabled (NMDevice *device, gboolean enabled);

RfKillType nm_device_get_rfkill_type (NMDevice *device);

/**
 * NMUnmanagedFlags:
 * @NM_UNMANAGED_NONE: placeholder value
 * @NM_UNMANAGED_DEFAULT: %TRUE when unmanaged by default (ie, Generic devices)
 * @NM_UNMANAGED_INTERNAL: %TRUE when unmanaged by internal decision (ie,
 *   because NM is sleeping or not managed for some other reason)
 * @NM_UNMANAGED_USER: %TRUE when unmanaged by user decision (via unmanaged-specs)
 * @NM_UNMANAGED_PARENT: %TRUE when unmanaged due to parent device being unmanaged
 * @NM_UNMANAGED_EXTERNAL_DOWN: %TRUE when unmanaged because !IFF_UP and not created by NM
 */
typedef enum {
	NM_UNMANAGED_NONE          = 0x00,
	NM_UNMANAGED_DEFAULT       = 0x01,
	NM_UNMANAGED_INTERNAL      = 0x02,
	NM_UNMANAGED_USER          = 0x04,
	NM_UNMANAGED_PARENT        = 0x08,
	NM_UNMANAGED_EXTERNAL_DOWN = 0x10,

	/* Boundary value */
	__NM_UNMANAGED_LAST,
	NM_UNMANAGED_LAST     = __NM_UNMANAGED_LAST - 1,
} NMUnmanagedFlags;

gboolean nm_device_get_managed (NMDevice *device);
gboolean nm_device_get_unmanaged_flag (NMDevice *device, NMUnmanagedFlags flag);
void nm_device_set_unmanaged (NMDevice *device,
                              NMUnmanagedFlags flag,
                              gboolean unmanaged,
                              NMDeviceStateReason reason);
void nm_device_set_unmanaged_quitting (NMDevice *device);
void nm_device_set_initial_unmanaged_flag (NMDevice *device,
                                           NMUnmanagedFlags flag,
                                           gboolean unmanaged);

gboolean nm_device_get_is_nm_owned (NMDevice *device);
void     nm_device_set_nm_owned    (NMDevice *device);

gboolean nm_device_realize            (NMDevice *device,
                                       NMPlatformLink *plink,
                                       GError **error);
gboolean nm_device_create_and_realize (NMDevice *self,
                                       NMConnection *connection,
                                       NMDevice *parent,
                                       GError **error);
gboolean nm_device_unrealize          (NMDevice *device,
                                       gboolean link_deleted,
                                       GError **error);

gboolean nm_device_get_autoconnect (NMDevice *device);

void nm_device_handle_autoip4_event (NMDevice *self,
                                     const char *event,
                                     const char *address);

void nm_device_state_changed (NMDevice *device,
                              NMDeviceState state,
                              NMDeviceStateReason reason);

void nm_device_queue_state   (NMDevice *self,
                              NMDeviceState state,
                              NMDeviceStateReason reason);

gboolean nm_device_get_firmware_missing (NMDevice *self);

void nm_device_queue_activation (NMDevice *device, NMActRequest *req);

gboolean nm_device_supports_vlans (NMDevice *device);

gboolean nm_device_add_pending_action    (NMDevice *device, const char *action, gboolean assert_not_yet_pending);
gboolean nm_device_remove_pending_action (NMDevice *device, const char *action, gboolean assert_is_pending);
gboolean nm_device_has_pending_action    (NMDevice *device);

GPtrArray *nm_device_get_available_connections (NMDevice *device,
                                                const char *specific_object);

gboolean   nm_device_connection_is_available (NMDevice *device,
                                              NMConnection *connection,
                                              gboolean allow_device_override);

gboolean nm_device_notify_component_added (NMDevice *device, GObject *component);

gboolean nm_device_owns_iface (NMDevice *device, const char *iface);

NMConnection *nm_device_new_default_connection (NMDevice *self);

const NMPlatformIP4Route *nm_device_get_ip4_default_route (NMDevice *self, gboolean *out_is_assumed);
const NMPlatformIP6Route *nm_device_get_ip6_default_route (NMDevice *self, gboolean *out_is_assumed);

void nm_device_spawn_iface_helper (NMDevice *self);

G_END_DECLS

/* For testing only */
extern const char* nm_device_autoipd_helper_path;

#endif	/* NM_DEVICE_H */
