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

#ifndef NM_OBJECT_H
#define NM_OBJECT_H

#include <gio/gio.h>

#include "nm-dbus-utils.h"

G_BEGIN_DECLS

#define NM_TYPE_OBJECT            (nm_object_get_type ())
#define NM_OBJECT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_OBJECT, NMObject))
#define NM_OBJECT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_OBJECT, NMObjectClass))
#define NM_IS_OBJECT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_OBJECT))
#define NM_IS_OBJECT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_OBJECT))
#define NM_OBJECT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_OBJECT, NMObjectClass))

typedef struct {
	GObject parent;
} NMObject;

typedef struct {
	GObjectClass parent;

} NMObjectClass;

GType nm_object_get_type (void);

void        nm_object_class_add_interface (NMObjectClass *object_class,
                                           GType          dbus_skeleton_type,
                                           ...) G_GNUC_NULL_TERMINATED;

void        nm_object_export              (NMObject      *self,
                                           const char    *path);
const char *nm_object_get_path            (NMObject      *self);
void        nm_object_unexport            (NMObject      *self);

void        nm_object_emit_dbus_signal    (NMObject      *self,
                                           const char    *signal_name,
                                           ...);

G_END_DECLS

#endif	/* NM_OBJECT_H */
