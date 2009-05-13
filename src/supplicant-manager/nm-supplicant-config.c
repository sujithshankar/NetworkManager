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
 * Copyright (C) 2006 - 2008 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include <netinet/ether.h>
#include <dbus/dbus-glib.h>

#include "nm-supplicant-config.h"
#include "nm-supplicant-settings-verify.h"
#include "nm-utils.h"
#include "nm-setting.h"
#include "NetworkManagerUtils.h"

#include "gnome-keyring-md5.h"

static char *hexstr2bin (const char *hex, size_t len);

#define NM_SUPPLICANT_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                             NM_TYPE_SUPPLICANT_CONFIG, \
                                             NMSupplicantConfigPrivate))

G_DEFINE_TYPE (NMSupplicantConfig, nm_supplicant_config, G_TYPE_OBJECT)

typedef struct {
	char *value;
	guint32 len;	
	OptType type;
} ConfigOption;

typedef struct
{
	GHashTable *config;
	GHashTable *blobs;
	guint32    ap_scan;
	gboolean   dispose_has_run;
} NMSupplicantConfigPrivate;

NMSupplicantConfig *
nm_supplicant_config_new (void)
{
	return g_object_new (NM_TYPE_SUPPLICANT_CONFIG, NULL);
}

static void
config_option_free (ConfigOption *opt)
{
	g_free (opt->value);
	g_slice_free (ConfigOption, opt);
}

static void
blob_free (GByteArray *array)
{
	g_byte_array_free (array, TRUE);
}

static void
nm_supplicant_config_init (NMSupplicantConfig * self)
{
	NMSupplicantConfigPrivate *priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	priv->config = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                      (GDestroyNotify) g_free,
	                                      (GDestroyNotify) config_option_free);

	priv->blobs = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                     (GDestroyNotify) g_free,
	                                     (GDestroyNotify) blob_free);

	priv->ap_scan = 1;
	priv->dispose_has_run = FALSE;
}

static gboolean
nm_supplicant_config_add_option_with_type (NMSupplicantConfig *self,
                                           const char *key,
                                           const char *value,
                                           gint32 len,
                                           OptType opt_type,
                                           gboolean secret)
{
	NMSupplicantConfigPrivate *priv;
	ConfigOption *old_opt;
	ConfigOption *opt;
	OptType type;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	if (len < 0)
		len = strlen (value);

	if (opt_type != TYPE_INVALID)
		type = opt_type;
	else {
		type = nm_supplicant_settings_verify_setting (key, value, len);
		if (type == TYPE_INVALID) {
			char buf[255];
			memset (&buf[0], 0, sizeof (buf));
			memcpy (&buf[0], value, len > 254 ? 254 : len);
			nm_debug ("Key '%s' and/or value '%s' invalid.", key, buf);
			return FALSE;
		}
	}

	old_opt = (ConfigOption *) g_hash_table_lookup (priv->config, key);
	if (old_opt) {
		nm_debug ("Key '%s' already in table.", key);
		return FALSE;
	}

	opt = g_slice_new0 (ConfigOption);
	if (opt == NULL) {
		nm_debug ("Couldn't allocate memory for new config option.");
		return FALSE;
	}

	opt->value = g_malloc0 ((sizeof (char) * len) + 1);
	if (opt->value == NULL) {
		nm_debug ("Couldn't allocate memory for new config option value.");
		g_slice_free (ConfigOption, opt);
		return FALSE;
	}
	memcpy (opt->value, value, len);

	opt->len = len;
	opt->type = type;	

{
char buf[255];
memset (&buf[0], 0, sizeof (buf));
memcpy (&buf[0], opt->value, opt->len > 254 ? 254 : opt->len);
nm_info ("Config: added '%s' value '%s'", key, secret ? "<omitted>" : &buf[0]);
}
	g_hash_table_insert (priv->config, g_strdup (key), opt);

	return TRUE;
}

static gboolean
nm_supplicant_config_add_option (NMSupplicantConfig *self,
                                 const char *key,
                                 const char *value,
                                 gint32 len,
                                 gboolean secret)
{
	return nm_supplicant_config_add_option_with_type (self, key, value, len, TYPE_INVALID, secret);
}

static gboolean
nm_supplicant_config_add_blob (NMSupplicantConfig *self,
                               const char *key,
                               const GByteArray *value,
                               const char *blobid)
{
	NMSupplicantConfigPrivate *priv;
	ConfigOption *old_opt;
	ConfigOption *opt;
	OptType type;
	GByteArray *blob;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);
	g_return_val_if_fail (value->len > 0, FALSE);
	g_return_val_if_fail (blobid != NULL, FALSE);

	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	type = nm_supplicant_settings_verify_setting (key, (const char *) value->data, value->len);
	if (type == TYPE_INVALID) {
		nm_debug ("Key '%s' and/or it's contained value is invalid.", key);
		return FALSE;
	}

	old_opt = (ConfigOption *) g_hash_table_lookup (priv->config, key);
	if (old_opt) {
		nm_debug ("Key '%s' already in table.", key);
		return FALSE;
	}

	blob = g_byte_array_sized_new (value->len);
	if (!blob) {
		nm_debug ("Couldn't allocate memory for new config blob.");
		return FALSE;
	}
	g_byte_array_append (blob, value->data, value->len);

	opt = g_slice_new0 (ConfigOption);
	if (opt == NULL) {
		nm_debug ("Couldn't allocate memory for new config option.");
		g_byte_array_free (blob, TRUE);
		return FALSE;
	}

	opt->value = g_strdup_printf ("blob://%s", blobid);
	if (opt->value == NULL) {
		nm_debug ("Couldn't allocate memory for new config option value.");
		g_byte_array_free (blob, TRUE);
		g_slice_free (ConfigOption, opt);
		return FALSE;
	}

	opt->len = strlen (opt->value);
	opt->type = type;	

nm_info ("Config: added '%s' value '%s'", key, opt->value);

	g_hash_table_insert (priv->config, g_strdup (key), opt);
	g_hash_table_insert (priv->blobs, g_strdup (blobid), blob);

	return TRUE;
}

static void
nm_supplicant_config_finalize (GObject *object)
{
	/* Complete object destruction */
	g_hash_table_destroy (NM_SUPPLICANT_CONFIG_GET_PRIVATE (object)->config);
	g_hash_table_destroy (NM_SUPPLICANT_CONFIG_GET_PRIVATE (object)->blobs);

	/* Chain up to the parent class */
	G_OBJECT_CLASS (nm_supplicant_config_parent_class)->finalize (object);
}


static void
nm_supplicant_config_class_init (NMSupplicantConfigClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = nm_supplicant_config_finalize;

	g_type_class_add_private (object_class, sizeof (NMSupplicantConfigPrivate));
}

guint32
nm_supplicant_config_get_ap_scan (NMSupplicantConfig * self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), 1);

	return NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->ap_scan;
}

void
nm_supplicant_config_set_ap_scan (NMSupplicantConfig * self,
                                  guint32 ap_scan)
{
	g_return_if_fail (NM_IS_SUPPLICANT_CONFIG (self));
	g_return_if_fail (ap_scan >= 0 && ap_scan <= 2);

	NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->ap_scan = ap_scan;
}

static void
get_hash_cb (gpointer key, gpointer value, gpointer user_data)
{
	ConfigOption *opt = (ConfigOption *) value;
	GValue *variant;
	GByteArray *array;

	variant = g_slice_new0 (GValue);

	switch (opt->type) {
	case TYPE_INT:
		g_value_init (variant, G_TYPE_INT);
		g_value_set_int (variant, atoi (opt->value));
		break;
	case TYPE_BYTES:
		array = g_byte_array_sized_new (opt->len);
		g_byte_array_append (array, (const guint8 *) opt->value, opt->len);
		g_value_init (variant, DBUS_TYPE_G_UCHAR_ARRAY);
		g_value_set_boxed (variant, array);
		g_byte_array_free (array, TRUE);
		break;
	case TYPE_KEYWORD:
	case TYPE_STRING:
		g_value_init (variant, G_TYPE_STRING);
		g_value_set_string (variant, opt->value);
		break;
	default:
		g_slice_free (GValue, variant);
		return;
	}

	g_hash_table_insert ((GHashTable *) user_data, g_strdup (key), variant);
}

static void
destroy_hash_value (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

GHashTable *
nm_supplicant_config_get_hash (NMSupplicantConfig * self)
{
	NMSupplicantConfigPrivate *priv;
	GHashTable *hash;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), NULL);

	hash = g_hash_table_new_full (g_str_hash, g_str_equal,
	                              (GDestroyNotify) g_free,
	                              destroy_hash_value);

	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);
	g_hash_table_foreach (priv->config, get_hash_cb, hash);
	return hash;
}

GHashTable *
nm_supplicant_config_get_blobs (NMSupplicantConfig * self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), NULL);

	return NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->blobs;
}

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((guint8*)(x))[0],((guint8*)(x))[1],((guint8*)(x))[2],((guint8*)(x))[3],((guint8*)(x))[4],((guint8*)(x))[5]

gboolean
nm_supplicant_config_add_setting_wireless (NMSupplicantConfig * self,
                                           NMSettingWireless * setting,
                                           gboolean is_broadcast,
                                           guint32 adhoc_freq,
                                           gboolean has_scan_capa_ssid)
{
	NMSupplicantConfigPrivate *priv;
	gboolean is_adhoc;
	const char *mode;
	const GByteArray *id;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (setting != NULL, FALSE);

	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	mode = nm_setting_wireless_get_mode (setting);
	is_adhoc = (mode && !strcmp (mode, "adhoc")) ? TRUE : FALSE;
	if (is_adhoc)
		priv->ap_scan = 2;
	else if (is_broadcast == FALSE) {
		/* drivers that support scanning specific SSIDs should use
		 * ap_scan=1, while those that do not should use ap_scan=2.
		 */
		priv->ap_scan = has_scan_capa_ssid ? 1 : 2;
	}

	id = nm_setting_wireless_get_ssid (setting);
	if (!nm_supplicant_config_add_option (self, "ssid", (char *) id->data, id->len, FALSE)) {
		nm_warning ("Error adding SSID to supplicant config.");
		return FALSE;
	}

	if (is_adhoc) {
		if (!nm_supplicant_config_add_option (self, "mode", "1", -1, FALSE)) {
			nm_warning ("Error adding mode to supplicant config.");
			return FALSE;
		}

		if (adhoc_freq) {
			char *str_freq;

			str_freq = g_strdup_printf ("%u", adhoc_freq);
			if (!nm_supplicant_config_add_option (self, "frequency", str_freq, -1, FALSE)) {
				g_free (str_freq);
				nm_warning ("Error adding Ad-Hoc frequency to supplicant config.");
				return FALSE;
			}
			g_free (str_freq);
		}
	}

	/* Except for Ad-Hoc networks, request that the driver probe for the
	 * specific SSID we want to associate with.
	 */
	if (!is_adhoc) {
		if (!nm_supplicant_config_add_option (self, "scan_ssid", "1", -1, FALSE))
			return FALSE;
	}

	id = nm_setting_wireless_get_bssid (setting);
	if (id && id->len) {
		char *str_bssid;

		str_bssid = g_strdup_printf (MAC_FMT, MAC_ARG (id->data));
		if (!nm_supplicant_config_add_option (self, "bssid",
		                                      str_bssid, strlen (str_bssid),
		                                      FALSE)) {
			g_free (str_bssid);
			nm_warning ("Error adding BSSID to supplicant config.");
			return FALSE;
		}
		g_free (str_bssid);
	}

	// FIXME: band & channel config items
	
	return TRUE;
}

static gboolean
add_string_val (NMSupplicantConfig *self,
                const char *field,
                const char *name,
                gboolean ucase,
                gboolean secret)
{
	gboolean success;
	char *value;

	if (!field)
		return TRUE;

	value = ucase ? g_ascii_strup (field, -1) : g_strdup (field);
	success = nm_supplicant_config_add_option (self, name, value, strlen (field), secret);
	if (!success)
		nm_warning ("Error adding %s to supplicant config.", name);
	g_free (value);
	return success;
}

#define ADD_STRING_LIST_VAL(setting, setting_name, field, field_plural, name, ucase, secret) \
	if (nm_setting_##setting_name##_get_num_##field_plural (setting)) { \
		guint32 k; \
		GString *str = g_string_new (NULL); \
		for (k = 0; k < nm_setting_##setting_name##_get_num_##field_plural (setting); k++) { \
			const char *item = nm_setting_##setting_name##_get_##field (setting, k); \
			if (!str->len) { \
				g_string_append (str, item); \
			} else { \
				g_string_append_c (str, ' '); \
				g_string_append (str, item); \
			} \
		} \
		if (ucase) \
			g_string_ascii_up (str); \
		if (str->len) \
			success = nm_supplicant_config_add_option (self, name, str->str, -1, secret); \
		else \
			success = TRUE; \
		g_string_free (str, TRUE); \
		if (!success) { \
			nm_warning ("Error adding %s to supplicant config.", name); \
			return FALSE; \
		} \
	}

static char *
get_blob_id (const char *name, const char *seed_uid)
{
	char *uid = g_strdup_printf ("%s-%s", seed_uid, name);
	char *p = uid;
	while (*p) {
		if (*p == '/') *p = '-';
		p++;
	}
	return uid;
}

#define ADD_BLOB_VAL(field, name, con_uid) \
	if (field && field->len) { \
		char *uid = get_blob_id (name, con_uid); \
		success = nm_supplicant_config_add_blob (self, name, field, uid); \
		g_free (uid); \
		if (!success) { \
			nm_warning ("Error adding %s to supplicant config.", name); \
			return FALSE; \
		} \
	}


static unsigned char *
wep128_passphrase_hash (const char *input, size_t input_len, size_t *out_len)
{
	char md5_data[65];
	unsigned char *digest;
	int i;

	*out_len = 16;
	digest = g_malloc0 (*out_len);

	/* Get at least 64 bytes */
	for (i = 0; i < 64; i++)
		md5_data[i] = input[i % input_len];

	/* Null terminate md5 seed data and hash it */
	md5_data[64] = 0;
	gnome_keyring_md5_string (md5_data, digest);
	return digest;
}

static gboolean
add_wep_key (NMSupplicantConfig *self,
             const char *key,
             const char *name,
             NMWepKeyType wep_type)
{
	char *value;
	gboolean success;
	size_t key_len = key ? strlen (key) : 0;

	if (!key || !key_len)
		return TRUE;

	if (   (wep_type == NM_WEP_KEY_TYPE_UNKNOWN)
	    || (wep_type == NM_WEP_KEY_TYPE_KEY)) {
		if ((key_len == 10) || (key_len == 26)) {
			value = hexstr2bin (key, strlen (key));
			success = nm_supplicant_config_add_option (self, name, value, key_len / 2, TRUE);
			g_free (value);
			if (!success) {
				nm_warning ("Error adding %s to supplicant config.", name);
				return FALSE;
			}
		} else if ((key_len == 5) || (key_len == 13)) {
			if (!nm_supplicant_config_add_option (self, name, key, key_len, TRUE)) {
				nm_warning ("Error adding %s to supplicant config.", name);
				return FALSE;
			}
		} else {
			nm_warning ("Invalid WEP key '%s'", name);
			return FALSE;
		}
	} else if (wep_type == NM_WEP_KEY_TYPE_PASSPHRASE) {
		char *digest;
		size_t digest_len;

		digest = (char *) wep128_passphrase_hash (key, key_len, &digest_len);
		success = nm_supplicant_config_add_option (self, name, digest, 13, TRUE);
		g_free (digest);
		if (!success) {
			nm_warning ("Error adding %s to supplicant config.", name);
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
nm_supplicant_config_add_setting_wireless_security (NMSupplicantConfig *self,
                                                    NMSettingWirelessSecurity *setting,
                                                    NMSetting8021x *setting_8021x,
                                                    const char *connection_uid)
{
	NMSupplicantConfigPrivate *priv;
	char *value;
	gboolean success;
	const char *key_mgmt, *auth_alg;
	const char *psk;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (setting != NULL, FALSE);
	g_return_val_if_fail (connection_uid != NULL, FALSE);

	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (setting);
	if (!add_string_val (self, key_mgmt, "key_mgmt", TRUE, FALSE))
		return FALSE;

	auth_alg = nm_setting_wireless_security_get_auth_alg (setting);
	if (!add_string_val (self, auth_alg, "auth_alg", TRUE, FALSE))
		return FALSE;

	psk = nm_setting_wireless_security_get_psk (setting);
	if (psk) {
		size_t psk_len = strlen (psk);

		if (psk_len == 64) {
			/* Hex PSK */
			value = hexstr2bin (psk, psk_len);
			success = nm_supplicant_config_add_option (self, "psk", value, psk_len / 2, TRUE);
			g_free (value);
			if (!success) {
				nm_warning ("Error adding 'psk' to supplicant config.");
				return FALSE;
			}
		} else if (psk_len >= 8 && psk_len < 63) {
			/* Use TYPE_STRING here so that it gets pushed to the
			 * supplicant as a string, and therefore gets quoted,
			 * and therefore the supplicant will interpret it as a
			 * passphrase and not a hex key.
			 */
			if (!nm_supplicant_config_add_option_with_type (self, "psk", psk, -1, TYPE_STRING, TRUE)) {
				nm_warning ("Error adding 'psk' to supplicant config.");
				return FALSE;
			}
		} else {
			/* Invalid PSK */
			nm_warning ("Invalid PSK length %u: not between 8 and 63 characters inclusive.", (guint32) psk_len);
			return FALSE;
		}
	}

	/* Only WPA-specific things when using WPA */
	if (   !strcmp (key_mgmt, "wpa-none")
	    || !strcmp (key_mgmt, "wpa-psk")
	    || !strcmp (key_mgmt, "wpa-eap")) {
		ADD_STRING_LIST_VAL (setting, wireless_security, proto, protos, "proto", TRUE, FALSE);
		ADD_STRING_LIST_VAL (setting, wireless_security, pairwise, pairwise, "pairwise", TRUE, FALSE);
		ADD_STRING_LIST_VAL (setting, wireless_security, group, groups, "group", TRUE, FALSE);
	}

	/* WEP keys if required */
	if (!strcmp (key_mgmt, "none")) {
		NMWepKeyType wep_type = nm_setting_wireless_security_get_wep_key_type (setting);
		const char *wep0 = nm_setting_wireless_security_get_wep_key (setting, 0);
		const char *wep1 = nm_setting_wireless_security_get_wep_key (setting, 1);
		const char *wep2 = nm_setting_wireless_security_get_wep_key (setting, 2);
		const char *wep3 = nm_setting_wireless_security_get_wep_key (setting, 3);

		if (!add_wep_key (self, wep0, "wep_key0", wep_type))
			return FALSE;
		if (!add_wep_key (self, wep1, "wep_key1", wep_type))
			return FALSE;
		if (!add_wep_key (self, wep2, "wep_key2", wep_type))
			return FALSE;
		if (!add_wep_key (self, wep3, "wep_key3", wep_type))
			return FALSE;

		if (wep0 || wep1 || wep2 || wep3) {
			value = g_strdup_printf ("%d", nm_setting_wireless_security_get_wep_tx_keyidx (setting));
			success = nm_supplicant_config_add_option (self, "wep_tx_keyidx", value, -1, FALSE);
			g_free (value);
			if (!success) {
				nm_warning ("Error adding wep_tx_keyidx to supplicant config.");
				return FALSE;
			}
		}
	}

	if (auth_alg && !strcmp (auth_alg, "leap")) {
		/* LEAP */
		if (!strcmp (key_mgmt, "ieee8021x")) {
			const char *tmp;

			tmp = nm_setting_wireless_security_get_leap_username (setting);
			if (!add_string_val (self, tmp, "identity", FALSE, FALSE))
				return FALSE;

			tmp = nm_setting_wireless_security_get_leap_password (setting);
			if (!add_string_val (self, tmp, "password", FALSE, TRUE))
				return FALSE;

			if (!add_string_val (self, "leap", "eap", TRUE, FALSE))
				return FALSE;
		} else {
			return FALSE;
		}
	} else {
		/* 802.1x for Dynamic WEP and WPA-Enterprise */
		if (!strcmp (key_mgmt, "ieee8021x") || !strcmp (key_mgmt, "wpa-eap")) {
		    if (!setting_8021x)
		    	return FALSE;
			if (!nm_supplicant_config_add_setting_8021x (self, setting_8021x, connection_uid, FALSE))
				return FALSE;
		}
	}

	return TRUE;
}

gboolean
nm_supplicant_config_add_setting_8021x (NMSupplicantConfig *self,
                                        NMSetting8021x *setting,
                                        const char *connection_uid,
                                        gboolean wired)
{
	NMSupplicantConfigPrivate *priv;
	char *tmp;
	const char *peapver, *value;
	gboolean success;
	GString *phase1, *phase2;
	const GByteArray *array;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (setting != NULL, FALSE);
	g_return_val_if_fail (connection_uid != NULL, FALSE);

	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	value = nm_setting_802_1x_get_password (setting);
	if (!add_string_val (self, value, "password", FALSE, TRUE))
		return FALSE;
	value = nm_setting_802_1x_get_pin (setting);
	if (!add_string_val (self, value, "pin", FALSE, TRUE))
		return FALSE;

	if (wired) {
		if (!add_string_val (self, "IEEE8021X", "key_mgmt", FALSE, FALSE))
			return FALSE;
		/* Wired 802.1x must always use eapol_flags=0 */
		if (!add_string_val (self, "0", "eapol_flags", FALSE, FALSE))
			return FALSE;
	}

	ADD_STRING_LIST_VAL (setting, 802_1x, eap_method, eap_methods, "eap", TRUE, FALSE);

	/* Drop the fragment size a bit for better compatibility */
	if (!nm_supplicant_config_add_option (self, "fragment_size", "1300", -1, FALSE))
		return FALSE;

	phase1 = g_string_new (NULL);
	peapver = nm_setting_802_1x_get_phase1_peapver (setting);
	if (peapver) {
		if (!strcmp (peapver, "0"))
			g_string_append (phase1, "peapver=0");
		else if (!strcmp (peapver, "1"))
			g_string_append (phase1, "peapver=1");
	}

	if (nm_setting_802_1x_get_phase1_peaplabel (setting)) {
		if (phase1->len)
			g_string_append_c (phase1, ' ');
		g_string_append_printf (phase1, "peaplabel=%s", nm_setting_802_1x_get_phase1_peaplabel (setting));
	}

	if (phase1->len) {
		if (!add_string_val (self, phase1->str, "phase1", FALSE, FALSE)) {
			g_string_free (phase1, TRUE);
			return FALSE;
		}
	}
	g_string_free (phase1, TRUE);

	phase2 = g_string_new (NULL);
	if (nm_setting_802_1x_get_phase2_auth (setting)) {
		tmp = g_ascii_strup (nm_setting_802_1x_get_phase2_auth (setting), -1);
		g_string_append_printf (phase2, "auth=%s", tmp);
		g_free (tmp);
	}

	if (nm_setting_802_1x_get_phase2_autheap (setting)) {
		if (phase2->len)
			g_string_append_c (phase2, ' ');
		tmp = g_ascii_strup (nm_setting_802_1x_get_phase2_autheap (setting), -1);
		g_string_append_printf (phase2, "autheap=%s", tmp);
		g_free (tmp);
	}

	if (phase2->len) {
		if (!add_string_val (self, phase2->str, "phase2", FALSE, FALSE)) {
			g_string_free (phase2, TRUE);
			return FALSE;
		}
	}
	g_string_free (phase2, TRUE);

	if (nm_setting_802_1x_get_system_ca_certs (setting)) {
		if (!add_string_val (self, SYSTEM_CA_PATH, "ca_path", FALSE, FALSE))
			return FALSE;
	} else {
		ADD_BLOB_VAL (nm_setting_802_1x_get_ca_cert (setting), "ca_cert", connection_uid);
	}

	array = nm_setting_802_1x_get_private_key (setting);
	if (array) {
		ADD_BLOB_VAL (array, "private_key", connection_uid);

		switch (nm_setting_802_1x_get_private_key_type (setting)) {
		case NM_SETTING_802_1X_CK_TYPE_PKCS12:
			/* Only add the private key password for PKCS#12 keys */
			value = nm_setting_802_1x_get_private_key_password (setting);
			if (!add_string_val (self, value, "private_key_passwd", FALSE, TRUE))
				return FALSE;
			break;
		default:
			/* Only add the client cert if the private key is not PKCS#12 */
			ADD_BLOB_VAL (nm_setting_802_1x_get_client_cert (setting), "client_cert", connection_uid);
			break;
		}
	}

	if (nm_setting_802_1x_get_system_ca_certs (setting)) {
		if (!add_string_val (self, SYSTEM_CA_PATH, "ca_path2", FALSE, FALSE))
			return FALSE;
	} else {
		ADD_BLOB_VAL (nm_setting_802_1x_get_phase2_ca_cert (setting), "ca_cert2", connection_uid);
	}

	array = nm_setting_802_1x_get_phase2_private_key (setting);
	if (array) {
		ADD_BLOB_VAL (array, "private_key2", connection_uid);

		switch (nm_setting_802_1x_get_phase2_private_key_type (setting)) {
		case NM_SETTING_802_1X_CK_TYPE_PKCS12:
			/* Only add the private key password for PKCS#12 keys */
			value = nm_setting_802_1x_get_phase2_private_key_password (setting);
			if (!add_string_val (self, value, "private_key2_passwd", FALSE, TRUE))
				return FALSE;
			break;
		default:
			/* Only add the client cert if the private key is not PKCS#12 */
			ADD_BLOB_VAL (nm_setting_802_1x_get_phase2_client_cert (setting), "client_cert2", connection_uid);
			break;
		}
	}

	value = nm_setting_802_1x_get_identity (setting);
	if (!add_string_val (self, value, "identity", FALSE, FALSE))
		return FALSE;
	value = nm_setting_802_1x_get_anonymous_identity (setting);
	if (!add_string_val (self, value, "anonymous_identity", FALSE, FALSE))
		return FALSE;

	return TRUE;
}

gboolean
nm_supplicant_config_add_no_security (NMSupplicantConfig *self)
{
	return nm_supplicant_config_add_option (self, "key_mgmt", "NONE", -1, FALSE);
}

/* From hostap, Copyright (c) 2002-2005, Jouni Malinen <jkmaline@cc.hut.fi> */

static int hex2num (char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int hex2byte (const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

static char *
hexstr2bin (const char *hex, size_t len)
{
	size_t       i;
	int          a;
	const char * ipos = hex;
	char *       buf = NULL;
	char *       opos;

	/* Length must be a multiple of 2 */
	if ((len % 2) != 0)
		return NULL;

	opos = buf = g_malloc0 ((len / 2) + 1);
	for (i = 0; i < len; i += 2) {
		a = hex2byte (ipos);
		if (a < 0) {
			g_free (buf);
			return NULL;
		}
		*opos++ = a;
		ipos += 2;
	}
	return buf;
}

/* End from hostap */

