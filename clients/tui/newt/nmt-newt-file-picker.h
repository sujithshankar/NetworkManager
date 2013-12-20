/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef NMT_NEWT_FILE_PICKER_H
#define NMT_NEWT_FILE_PICKER_H

#include <gio/gio.h>

#include "nmt-newt-form.h"

G_BEGIN_DECLS

#define NMT_TYPE_NEWT_FILE_PICKER               (nmt_newt_file_picker_get_type ())
#define NMT_NEWT_FILE_PICKER(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_FILE_PICKER, NmtNewtFilePicker))
#define NMT_NEWT_FILE_PICKER_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_FILE_PICKER, NmtNewtFilePickerClass))
#define NMT_IS_NEWT_FILE_PICKER(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_FILE_PICKER))
#define NMT_IS_NEWT_FILE_PICKER_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_FILE_PICKER))
#define NMT_NEWT_FILE_PICKER_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NMT_TYPE_NEWT_FILE_PICKER, NmtNewtFilePickerInterface))

typedef gboolean (*NmtNewtFilePickerFilter) (NmtNewtFilePicker *picker,
                                             const char        *path,
                                             GFileInfo         *info,
                                             gpointer           user_data);

typedef struct {
	GTypeInterface parent;

	void         (*set_filter)    (NmtNewtFilePicker       *picker,
	                               NmtNewtFilePickerFilter  filter,
	                               gpointer                 filter_data,
	                               GDestroyNotify           filter_destroy);
	
	const char * (*get_cwd)       (NmtNewtFilePicker       *picker);
	const char * (*get_selection) (NmtNewtFilePicker       *picker);

} NmtNewtFilePickerInterface;

GType nmt_newt_file_picker_get_type (void);

NmtNewtForm *nmt_newt_file_picker_new           (const char              *initial_directory);

void         nmt_newt_file_picker_set_filter    (NmtNewtFilePicker       *picker,
                                                 NmtNewtFilePickerFilter  filter,
                                                 gpointer                 filter_data,
                                                 GDestroyNotify           filter_destroy);

void         nmt_newt_file_picker_set_cwd       (NmtNewtFilePicker       *picker,
                                                 const char              *cwd);
const char  *nmt_newt_file_picker_get_cwd       (NmtNewtFilePicker       *picker);

void         nmt_newt_file_picker_set_selection (NmtNewtFilePicker       *picker,
                                                 const char              *selection);
const char  *nmt_newt_file_picker_get_selection (NmtNewtFilePicker       *picker);

G_END_DECLS

#endif /* NMT_NEWT_FILE_PICKER_H */
