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

#ifndef NMT_NEWT_FILE_DIALOG_H
#define NMT_NEWT_FILE_DIALOG_H

#include <gio/gio.h>

#include "nmt-newt-form.h"

G_BEGIN_DECLS

#define NMT_TYPE_NEWT_FILE_DIALOG            (nmt_newt_file_dialog_get_type ())
#define NMT_NEWT_FILE_DIALOG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_FILE_DIALOG, NmtNewtFileDialog))
#define NMT_NEWT_FILE_DIALOG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_FILE_DIALOG, NmtNewtFileDialogClass))
#define NMT_IS_NEWT_FILE_DIALOG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_FILE_DIALOG))
#define NMT_IS_NEWT_FILE_DIALOG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_FILE_DIALOG))
#define NMT_NEWT_FILE_DIALOG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_FILE_DIALOG, NmtNewtFileDialogClass))

struct _NmtNewtFileDialog {
	NmtNewtForm parent;

};

typedef struct {
	NmtNewtFormClass parent;

} NmtNewtFileDialogClass;

GType nmt_newt_file_dialog_get_type (void);

NmtNewtForm *nmt_newt_file_dialog_new (void);

G_END_DECLS

#endif /* NMT_NEWT_FILE_DIALOG_H */
