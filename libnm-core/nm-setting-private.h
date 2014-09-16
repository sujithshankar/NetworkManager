/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2011 Red Hat, Inc.
 */

#ifndef __NM_SETTING_PRIVATE_H__
#define __NM_SETTING_PRIVATE_H__

#include "nm-setting.h"
#include "nm-connection.h"
#include "nm-core-enum-types.h"
#include "nm-glib-compat.h"

#include "nm-core-internal.h"

/**
 * NMSettingVerifyResult:
 * @NM_SETTING_VERIFY_SUCCESS: the setting verifies successfully
 * @NM_SETTING_VERIFY_ERROR: the setting has a serious misconfiguration
 * @NM_SETTING_VERIFY_NORMALIZABLE: the setting is valid but has properties
 * that should be normalized
 * @NM_SETTING_VERIFY_NORMALIZABLE_ERROR: the setting is invalid but the
 * errors can be fixed by nm_connection_normalize().
 */
typedef enum {
	NM_SETTING_VERIFY_SUCCESS       = TRUE,
	NM_SETTING_VERIFY_ERROR         = FALSE,
	NM_SETTING_VERIFY_NORMALIZABLE  = 2,
	NM_SETTING_VERIFY_NORMALIZABLE_ERROR = 3,
} NMSettingVerifyResult;

void _nm_register_setting (const char *name,
                           const GType type,
                           const guint32 priority,
                           const GQuark error_quark);

#define _nm_register_setting(name, priority) \
	G_STMT_START { \
		_nm_register_setting (NM_SETTING_ ## name ## _SETTING_NAME "", g_define_type_id, priority, NM_SETTING_ ## name ## _ERROR); \
		g_type_ensure (NM_TYPE_SETTING_ ## name ## _ERROR); \
	} G_STMT_END

gboolean _nm_setting_is_base_type (NMSetting *setting);
gboolean _nm_setting_type_is_base_type (GType type);
gint _nm_setting_compare_priority (gconstpointer a, gconstpointer b);

typedef enum NMSettingUpdateSecretResult {
	NM_SETTING_UPDATE_SECRET_ERROR              = FALSE,
	NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED   = TRUE,
	NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED  = 2,
} NMSettingUpdateSecretResult;

NMSettingUpdateSecretResult _nm_setting_update_secrets (NMSetting *setting,
                                                        GHashTable *secrets,
                                                        GError **error);
gboolean _nm_setting_clear_secrets (NMSetting *setting);
gboolean _nm_setting_clear_secrets_with_flags (NMSetting *setting,
                                               NMSettingClearSecretsWithFlagsFn func,
                                               gpointer user_data);


/* The property of the #NMSetting should be considered during comparisons that
 * use the %NM_SETTING_COMPARE_FLAG_INFERRABLE flag. Properties that don't have
 * this flag, are ignored when doing an infrerrable comparison.  This flag should
 * be set on all properties that are read from the kernel or the system when a
 * connection is generated.  eg, IP addresses/routes can be read from the
 * kernel, but the 'autoconnect' property cannot, so
 * %NM_SETTING_IP4_CONFIG_ADDRESSES gets the INFERRABLE flag, but
 * %NM_SETTING_CONNECTION_AUTOCONNECT would not.
 *
 * This flag should not be used with properties where the default cannot be
 * read separately from the current value, like MTU or wired duplex mode.
 */
#define NM_SETTING_PARAM_INFERRABLE (1 << (4 + G_PARAM_USER_SHIFT))

/* Ensure the setting's GType is registered at library load time */
#define NM_SETTING_REGISTER_TYPE(x) \
static void __attribute__((constructor)) register_setting (void) \
{ g_type_init (); g_type_ensure (x); }

NMSetting *nm_setting_find_in_list (GSList *settings_list, const char *setting_name);

NMSetting * _nm_setting_find_in_list_required (GSList *all_settings,
                                               const char *setting_name,
                                               GError **error,
                                               const char *error_prefix_setting_name,
                                               const char *error_prefix_property_name);

NMSettingVerifyResult _nm_setting_verify_required_virtual_interface_name (GSList *all_settings,
                                                                          GError **error);

gboolean _nm_setting_get_deprecated_virtual_interface_name (NMSetting *setting,
                                                            NMConnection *connection,
                                                            const char *property,
                                                            GValue *value);
gboolean _nm_setting_set_deprecated_virtual_interface_name (NMSetting *setting,
                                                            GHashTable *connection_hash,
                                                            const char *property,
                                                            const GValue *value,
                                                            GError **error);

NMSettingVerifyResult _nm_setting_verify (NMSetting *setting,
                                          GSList    *all_settings,
                                          GError    **error);

NMSetting *_nm_setting_find_in_list_base_type (GSList *all_settings);
gboolean _nm_setting_slave_type_is_valid (const char *slave_type, const char **out_port_type);
const char * _nm_setting_slave_type_detect_from_settings (GSList *all_settings, NMSetting **out_s_port);

GHashTable *_nm_setting_to_dbus       (NMSetting *setting,
                                       NMConnection *connection,
                                       NMConnectionSerializationFlags flags);

NMSetting  *_nm_setting_new_from_dbus (GType setting_type,
                                       GHashTable *setting_hash,
                                       GHashTable *connection_hash,
                                       GError **error);

typedef gboolean (*NMSettingPropertyGetFunc)    (NMSetting     *setting,
                                                 NMConnection  *connection,
                                                 const char    *property,
                                                 GValue        *value);
typedef gboolean (*NMSettingPropertySetFunc)    (NMSetting     *setting,
                                                 GHashTable    *connection_hash,
                                                 const char    *property,
                                                 const GValue  *value,
                                                 GError       **error);
typedef gboolean (*NMSettingPropertyNotSetFunc) (NMSetting     *setting,
                                                 GHashTable    *connection_hash,
                                                 const char    *property,
                                                 GError       **error);

void _nm_setting_class_add_dbus_only_property (NMSettingClass *setting_class,
                                               const char *property_name,
                                               GType dbus_type,
                                               NMSettingPropertyGetFunc get_func,
                                               NMSettingPropertySetFunc set_func);

void _nm_setting_class_override_property (NMSettingClass *setting_class,
                                          const char *property_name,
                                          GType dbus_type,
                                          NMSettingPropertyGetFunc get_func,
                                          NMSettingPropertySetFunc set_func,
                                          NMSettingPropertyNotSetFunc not_set_func);

typedef void (*NMSettingPropertyTransformFunc) (const GValue *from,
                                                GValue       *to);

void _nm_setting_class_transform_property (NMSettingClass *setting_class,
                                           const char *property_name,
                                           GType dbus_type,
                                           NMSettingPropertyTransformFunc to_dbus,
                                           NMSettingPropertyTransformFunc from_dbus);

#endif  /* NM_SETTING_PRIVATE_H */