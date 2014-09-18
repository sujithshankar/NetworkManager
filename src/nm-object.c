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
 * Copyright 2014 Red Hat, Inc.
 */

#include "config.h"

#include <stdarg.h>

#include "nm-object.h"
#include "nm-dbus-manager.h"
#include "nm-properties-changed-signal.h"

typedef struct {
	GType dbus_skeleton_type;
	char *method_name;
	GCallback impl;
} NMObjectDBusMethodImpl;

typedef struct {
	GSList *skeleton_types;
	GArray *methods;
	GHashTable *signals;
} NMObjectClassPrivate;

#define NM_OBJECT_CLASS_GET_PRIVATE(k) (G_TYPE_CLASS_GET_PRIVATE ((k), NM_TYPE_OBJECT, NMObjectClassPrivate))

G_DEFINE_TYPE_WITH_CODE (NMObject, nm_object, G_TYPE_OBJECT,
                         g_type_add_class_private (g_define_type_id, sizeof (NMObjectClassPrivate));
                         )

typedef struct {
	GSList *interfaces;
	char *path;
} NMObjectPrivate;

#define NM_OBJECT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OBJECT, NMObjectPrivate))

static char *
skeletonify_method_name (const char *dbus_method_name)
{
	GString *out;
	const char *p;

	out = g_string_new ("handle");
	for (p = dbus_method_name; *p; p++) {
		if (g_ascii_isupper (*p)) {
			g_string_append_c (out, '-');
			g_string_append_c (out, g_ascii_tolower (*p));
		} else
			g_string_append_c (out, *p);
	}

	return g_string_free (out, FALSE);
}

static char *
dbusify_signal_name (const char *gobject_signal_name)
{
	GString *out;
	const char *p;
	gboolean capitalize = TRUE;

	out = g_string_new ("");
	for (p = gobject_signal_name; *p; p++) {
		if (capitalize) {
			g_string_append_c (out, g_ascii_toupper (*p));
			capitalize = FALSE;
		} else if (*p == '-')
			capitalize = TRUE;
		else
			g_string_append_c (out, *p);
	}

	return g_string_free (out, FALSE);
}

/**
 * nm_object_class_add_interface:
 * @object_class: an #NMObjectClass
 * @dbus_skeleton_type: the type of the #GDBusObjectSkeleton to add
 * @...: signal name / handler pairs, %NULL-terminated
 *
 * Adds @dbus_skeleton_type to the list of D-Bus interfaces implemented by
 * @object_class. Instances of @object_class will automatically have a skeleton
 * of that type created, which will be exported when you call
 * nm_object_export().
 *
 * The skeleton's properties will be initialized from the #NMObject's (which
 * must have corresponding properties of the same type), and bidirectional
 * bindings will be set up between them.
 *
 * The arguments after @dbus_skeleton_type are pairs of D-Bus method names (in
 * CamelCase), and the corresponding handlers for them (which must have the same
 * prototype as the corresponding signal on @dbus_skeleton_type, but with the
 * first argument being an object of @object_class's type, not of
 * @dbus_skeleton_type).
 *
 * FIXME: autoconnect methods somehow?
 *
 * FIXME: do something clever with D-Bus signals. For now, you have to manually
 * emit them via nm_object_emit_dbus_signal().
 */
void
nm_object_class_add_interface (NMObjectClass *object_class,
                               GType          dbus_skeleton_type,
                               ...)
{
	NMObjectClassPrivate *cpriv = NM_OBJECT_CLASS_GET_PRIVATE (object_class);
	NMObjectDBusMethodImpl method;
	va_list ap;
	const char *method_name;
	GCallback impl;
	guint *signals, n_signals;
	GSignalQuery query;
	int i;

	g_return_if_fail (NM_IS_OBJECT_CLASS (object_class));
	g_return_if_fail (g_type_is_a (dbus_skeleton_type, G_DBUS_TYPE_OBJECT_SKELETON));

	cpriv->skeleton_types = g_slist_prepend (cpriv->skeleton_types,
	                                         GSIZE_TO_POINTER (dbus_skeleton_type));

	/* Methods */
	va_start (ap, dbus_skeleton_type);
	while ((method_name = va_arg (ap, const char *)) && (impl = va_arg (ap, GCallback))) {
		method.dbus_skeleton_type = dbus_skeleton_type;
		method.method_name = skeletonify_method_name (method_name);
		method.impl = impl;

		g_array_append_val (cpriv->methods, method);
	}
	va_end (ap);

	/* Signals */
	signals = g_signal_list_ids (dbus_skeleton_type, &n_signals);
	for (i = 0; i < n_signals; i++) {
		g_signal_query (signals[i], &query);
		g_hash_table_insert (cpriv->signals,
		                     dbusify_signal_name (query.signal_name),
		                     g_memdup (&query, sizeof (query)));
	}

	nm_properties_changed_signal_setup (G_TYPE_FROM_CLASS (object_class), dbus_skeleton_type)
}

/**
 * nm_object_export:
 * @self: an #NMObject
 * @path: the path to export @self on
 *
 * Exports @self on @path on all active and future D-Bus connections.
 */
void
nm_object_export (NMObject   *self,
                  const char *path)
{
	NMObjectPrivate *priv;
	NMDBusManager *dbus_mgr;
	GSList *iter;

	g_return_if_fail (NM_IS_OBJECT (self));
	priv = NM_OBJECT_GET_PRIVATE (self);

	g_return_if_fail (priv->interfaces != NULL);
	g_return_if_fail (priv->path == NULL);

	priv->path = g_strdup (path);

	dbus_mgr = nm_dbus_manager_get ();
	for (iter = priv->interfaces; iter; iter = iter->next)
		nm_dbus_manager_register_object (dbus_mgr, path, self);
}

/**
 * nm_object_get_path:
 * @self: an #NMObject
 *
 * Gets @self's D-Bus path.
 *
 * Returns: @self's D-Bus path, or %NULL if @self is not exported.
 */
const char *
nm_object_get_dbus_path (NMObject *self)
{
	g_return_if_fail (NM_IS_OBJECT (self));

	return NM_OBJECT_GET_PRIVATE (self)->path;
}

/**
 * nm_object_unexport:
 * @self: an #NMObject
 *
 * Unexports @self on all active D-Bus connections (and prevents it from being
 * auto-exported on future connections).
 */
void
nm_object_unexport (NMObject *self)
{
	NMObjectPrivate *priv;
	NMDBusManager *dbus_mgr;
	GSList *iter;

	g_return_if_fail (NM_IS_OBJECT (self));
	priv = NM_OBJECT_GET_PRIVATE (self);

	g_return_if_fail (priv->interfaces != NULL);
	g_return_if_fail (priv->path != NULL);

	g_clear_pointer (&priv->path, g_free);

	dbus_mgr = nm_dbus_manager_get ();
	for (iter = priv->interfaces; iter; iter = iter->next)
		nm_dbus_manager_unregister_object (dbus_mgr, self);
}

/**
 * nm_object_emit_dbus_signal:
 * @self: an #NMObject
 * @signal_name: the D-Bus signal to emit (in CamelCase)
 * @...: signal arguments
 *
 * Emits the D-Bus signal @signal_name on the appropriate D-Bus interface on
 * @self.
 */
void
nm_object_emit_dbus_signal (NMObject   *self,
                            const char *signal_name,
                            ...)
{
	NMObjectClassPrivate *cpriv;
	NMObjectPrivate *priv;
	GSignalQuery *signal_info;
	GDBusObjectSkeleton *interface = NULL;
	GSList *iter;
	va_list ap;

	g_return_if_fail (NM_IS_OBJECT (self));

	priv = NM_OBJECT_GET_PRIVATE (self);
	cpriv = NM_OBJECT_CLASS_GET_PRIVATE (NM_OBJECT_GET_CLASS (self));

	signal_info = g_hash_table_lookup (cpriv->signals, signal_name);
	g_return_if_fail (signal_info != NULL);

	for (iter = priv->interfaces; iter; iter = iter->next) {
		if (G_OBJECT_TYPE (iter->data) == signal_info->itype) {
			interface = iter->data;
			break;
		}
	}
	g_return_if_fail (interface != NULL);

	va_start (ap, signal_name);
	g_signal_emit_valist (interface, signal_info->signal_id, 0, ap);
	va_end (ap);
}

static void
nm_object_init (NMObject *self)
{
}

static void
nm_object_constructed (GObject *object)
{
	NMObject *self = NM_OBJECT (object);
	NMObjectClassPrivate *cpriv = NM_OBJECT_CLASS_GET_PRIVATE (NM_OBJECT_GET_CLASS (self));
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	GSList *iter;
	GDBusObjectSkeleton *interface;
	GParamSpec **properties;
	guint n_properties;
	int i;

	for (iter = cpriv->skeleton_types; iter; iter = iter->next) {
		GType dbus_skeleton_type = GPOINTER_TO_SIZE (iter->data);

		interface = g_object_new (dbus_skeleton_type, NULL);
		priv->interfaces = g_slist_prepend (priv->interfaces, interface);

		/* Bind properties */
		properties = g_object_class_list_properties (G_OBJECT_GET_CLASS (interface), &n_properties);
		for (i = 0; i < n_properties; i++) {
			g_object_bind_property (self, properties[i]->name,
			                        interface, properties[i]->name,
			                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
		}

		/* Bind methods */
		for (i = 0; i < cpriv->methods->len; i++) {
			NMObjectDBusMethodImpl *method = &g_array_index (cpriv->methods, NMObjectDBusMethodImpl, i);

			if (method->dbus_skeleton_type == dbus_skeleton_type)
				g_signal_connect_swapped (interface, method->method_name, method->impl, self);
		}
	}
}

static void
nm_object_dispose (GObject *object)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);

	if (priv->path)
		nm_object_unexport (NM_OBJECT (object));

	g_slist_free_full (priv->interfaces, g_object_unref);
	priv->interfaces = NULL;

	G_OBJECT_CLASS (nm_object_parent_class)->dispose (object);
}

static void
nm_object_class_init (NMObjectClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClassPrivate *cpriv = NM_OBJECT_CLASS_GET_PRIVATE (klass);

	cpriv->methods = g_array_new (FALSE, FALSE, sizeof (NMObjectDBusMethodImpl));
	cpriv->signals = g_hash_table_new (g_str_hash, g_str_equal);

	g_type_class_add_private (object_class, sizeof (NMObjectPrivate));

	object_class->constructed = nm_object_constructed;
	object_class->dispose     = nm_object_dispose;
}
