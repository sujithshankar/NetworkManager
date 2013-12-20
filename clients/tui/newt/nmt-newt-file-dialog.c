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

/**
 * SECTION:nmt-newt-file-dialog
 * @short_description: File selection dialog
 *
 * #NmtNewtFileDialog implements a form for selecting an existing file from
 * disk.  At this time it does not support creating new files, or selecting
 * directories.
 *
 * A #NmtNewtFileDialog can be reused, and remembers its state between uses.
 */

#include "config.h"

#include <glib.h>
#include <glib/gi18n-lib.h>

#include "nm-glib-compat.h"

#include "nmt-newt-file-dialog.h"
#include "nmt-newt-file-picker.h"
#include "nmt-newt-button.h"
#include "nmt-newt-grid.h"
#include "nmt-newt-label.h"
#include "nmt-newt-listbox.h"
#include "nmt-newt-utils.h"

static void nmt_newt_file_dialog_file_picker_interface_init (NmtNewtFilePickerInterface *iface, gpointer iface_data);

G_DEFINE_TYPE_WITH_CODE (NmtNewtFileDialog, nmt_newt_file_dialog, NMT_TYPE_NEWT_FORM,
                         G_IMPLEMENT_INTERFACE (NMT_TYPE_NEWT_FILE_PICKER,
                                                nmt_newt_file_dialog_file_picker_interface_init);
                         )

#define NMT_NEWT_FILE_DIALOG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_FILE_DIALOG, NmtNewtFileDialogPrivate))

static void path_selected (NmtNewtWidget *widget, gpointer user_data);

typedef struct {
	NmtNewtListbox *list;

	char *cwd;
	char *display_cwd;
	char *selection;
	char *display_selection;

	NmtNewtFilePickerFilter filter;
	gpointer filter_data;
	GDestroyNotify filter_destroy;

} NmtNewtFileDialogPrivate;

enum {
	PROP_0,
	PROP_CWD,
	PROP_DISPLAY_CWD,
	PROP_SELECTION,
	PROP_DISPLAY_SELECTION,

	LAST_PROP
};

/**
 * nmt_newt_file_dialog_new:
 *
 * Creates a new #NmtNewtFileDialog.
 *
 * Returns: a new #NmtNewtFileDialog
 */
NmtNewtForm *
nmt_newt_file_dialog_new (void)
{
	return g_object_new (NMT_TYPE_NEWT_FILE_DIALOG,
	                     // FIXME "escape-exits", TRUE,
	                     NULL);
}

static void
nmt_newt_file_dialog_init (NmtNewtFileDialog *dialog)
{
	NmtNewtFileDialogPrivate *priv = NMT_NEWT_FILE_DIALOG_GET_PRIVATE (dialog);
	int screen_height, screen_width, height;
	NmtNewtWidget *list;

	newtGetScreenSize (&screen_width, &screen_height);
	height = MAX (10, screen_height - 10);
	list = nmt_newt_listbox_new (height, NMT_NEWT_LISTBOX_SCROLL | NMT_NEWT_LISTBOX_BORDER);
	g_signal_connect (list, "activated", G_CALLBACK (path_selected), dialog);
	priv->list = NMT_NEWT_LISTBOX (list);
}

static gboolean
sort_fileinfos (gconstpointer a, gconstpointer b)
{
	GFileInfo *info_a = *(GFileInfo **) a;
	GFileInfo *info_b = *(GFileInfo **) b;
	GFileType type_a = g_file_info_get_file_type (info_a);
	GFileType type_b = g_file_info_get_file_type (info_b);
	const char *name_a = g_file_info_get_display_name (info_a);
	const char *name_b = g_file_info_get_display_name (info_b);

	/* Sort directories before files */
	if (type_a == G_FILE_TYPE_DIRECTORY && type_b != G_FILE_TYPE_DIRECTORY)
		return -1;
	else if (type_b == G_FILE_TYPE_DIRECTORY && type_a != G_FILE_TYPE_DIRECTORY)
		return 1;

	/* Sort dotfiles before non-dotfiles */
	if (*name_a == '.' && *name_b != '.')
		return -1;
	else if (*name_b == '.' && *name_a != '.')
		return 1;

	/* Otherwise, use locale collation rules */
	return g_utf8_collate (name_a, name_b);
}

static void
update_selection (NmtNewtFileDialog *dialog)
{
	NmtNewtFileDialogPrivate *priv = NMT_NEWT_FILE_DIALOG_GET_PRIVATE (dialog);
	char *dirname, *basename;
	int i, num;
	GFileInfo *info;

	if (!priv->selection) {
		nmt_newt_listbox_set_active (priv->list, 0);
		return;
	}

	dirname = g_path_get_dirname (priv->selection);
	if (strcmp (dirname, priv->cwd) != 0) {
		g_free (dirname);
		nmt_newt_listbox_set_active (priv->list, 0);
		return;
	}
	g_free (dirname);

	basename = g_path_get_basename (priv->selection);
	num = nmt_newt_listbox_get_num_rows (priv->list);
	for (i = 0; i < num; i++) {
		info = nmt_newt_listbox_get_key (priv->list, i);
		if (info && !strcmp (basename, g_file_info_get_name (info))) {
			g_free (basename);
			nmt_newt_listbox_set_active (priv->list, i);
			return;
		}
	}

	g_free (basename);
	nmt_newt_listbox_set_active (priv->list, 0);
}

static void
rebuild_dialog (NmtNewtFileDialog *dialog)
{
	NmtNewtFileDialogPrivate *priv = NMT_NEWT_FILE_DIALOG_GET_PRIVATE (dialog);
	GPtrArray *fileinfos;
	GFile *dir;
	GFileEnumerator *iter;
	GFileInfo *info;
	GFileType type;
	GError *error = NULL;
	const char *display_name;
	int i;

	nmt_newt_listbox_clear (priv->list);

	fileinfos = g_ptr_array_new ();

	dir = g_file_new_for_path (priv->cwd);
	iter = g_file_enumerate_children (dir,
	                                  G_FILE_ATTRIBUTE_STANDARD_NAME ","
	                                  G_FILE_ATTRIBUTE_STANDARD_DISPLAY_NAME ","
	                                  G_FILE_ATTRIBUTE_STANDARD_TYPE,
	                                  G_FILE_QUERY_INFO_NONE,
	                                  NULL, &error);
	/* FIXME */
	g_assert_no_error (error);

	while ((info = g_file_enumerator_next_file (iter, NULL, NULL))) {
		type = g_file_info_get_file_type (info);

		if (type == G_FILE_TYPE_REGULAR || type == G_FILE_TYPE_SYMBOLIC_LINK) {
			if (priv->filter) {
				char *full_path;
				gboolean keep;

				full_path = g_build_filename (priv->cwd, g_file_info_get_name (info), NULL);
				keep = priv->filter (NMT_NEWT_FILE_PICKER (dialog), full_path,
				                     info, priv->filter_data);
				g_free (full_path);
				if (!keep) {
					g_object_unref (info);
					continue;
				}
			}
			g_ptr_array_add (fileinfos, info);
		} else if (g_file_info_get_file_type (info) == G_FILE_TYPE_DIRECTORY) {
			g_ptr_array_add (fileinfos, info);
		} else
			g_object_unref (info);
	}
	g_object_unref (iter);

	g_ptr_array_sort (fileinfos, sort_fileinfos);

	/* ".." goes first */
	if (g_file_get_parent (dir))
		nmt_newt_listbox_append (priv->list, "../", NULL);

	for (i = 0; i < fileinfos->len; i++) {
		info = fileinfos->pdata[i];
		display_name = g_file_info_get_display_name (info);

		if (g_file_info_get_file_type (info) == G_FILE_TYPE_DIRECTORY) {
			char *dname;

			dname = g_strdup_printf ("%s/", display_name);
			g_object_set_data_full (G_OBJECT (info), "NmtNewtFileDialog-display-name",
			                        dname, g_free);
			display_name = dname;
		}

		nmt_newt_listbox_append (priv->list, display_name, info);
	}

	update_selection (dialog);

	g_object_unref (dir);
	g_ptr_array_unref (fileinfos);
}

static void
path_selected (NmtNewtWidget *widget,
               gpointer       user_data)
{
	NmtNewtFileDialog *dialog = user_data;
	NmtNewtFileDialogPrivate *priv = NMT_NEWT_FILE_DIALOG_GET_PRIVATE (dialog);
	GFileInfo *info;
	const char *name;
	char *selected_path;

	info = nmt_newt_listbox_get_active_key (priv->list);
	if (info) {
		name = g_file_info_get_name (info);
		selected_path = g_build_filename (priv->cwd, name, NULL);
	} else /* ".." */
		selected_path = g_path_get_dirname (priv->cwd);

	if (!info || g_file_info_get_file_type (info) == G_FILE_TYPE_DIRECTORY) {
		nmt_newt_file_picker_set_cwd (NMT_NEWT_FILE_PICKER (dialog), selected_path);
	} else {
		nmt_newt_file_picker_set_selection (NMT_NEWT_FILE_PICKER (dialog), selected_path);
		nmt_newt_form_quit (NMT_NEWT_FORM (dialog));
	}

	g_free (selected_path);
}

#define LABEL_WIDTH 40

static gboolean
transform_cwd_for_label (GBinding     *binding,
                         const GValue *from_value,
                         GValue       *to_value,
                         gpointer      user_data)
{
	const char *cwd = g_value_get_string (from_value);
	const char *p;
	char *label;
	int len;

	len = strlen (cwd);
	if (len < LABEL_WIDTH - 1) {
		label = g_strdup_printf ("%s:%*s", cwd, LABEL_WIDTH - 1 - len, "");
		g_value_take_string (to_value, label);
		return TRUE;
	}

	for (p = strchr (cwd + 1, '/'); p; p = strchr (p + 1, '/')) {
		len = strlen (p);
		if (len < LABEL_WIDTH - 4) {
			label = g_strdup_printf ("...%s:%*s", p, LABEL_WIDTH - 4 - len, "");
			g_value_take_string (to_value, label);
			return TRUE;
		}
	}

	/* Even just the final path component is too long. Truncate it. */
	label = g_strdup_printf ("...%s:", cwd + strlen (cwd) - (LABEL_WIDTH - 4));
	g_value_take_string (to_value, label);
	return TRUE;
}

static void
nmt_newt_file_dialog_constructed (GObject *object)
{
	NmtNewtFileDialog *dialog = NMT_NEWT_FILE_DIALOG (object);
	NmtNewtFileDialogPrivate *priv = NMT_NEWT_FILE_DIALOG_GET_PRIVATE (dialog);
	NmtNewtWidget *vbox, *cwd, *list, *buttons, *ok, *cancel;

	vbox = nmt_newt_grid_new ();

	cwd = nmt_newt_label_new (NULL);
	g_object_bind_property_full (dialog, "display-cwd",
	                             cwd, "text", 
	                             G_BINDING_SYNC_CREATE,
	                             transform_cwd_for_label,
	                             NULL, NULL, NULL);

	nmt_newt_grid_add (NMT_NEWT_GRID (vbox), cwd, 0, 0);

	list = NMT_NEWT_WIDGET (priv->list);
	nmt_newt_grid_add (NMT_NEWT_GRID (vbox), list, 0, 1);
	nmt_newt_widget_set_padding (list, 0, 1, 0, 1);

	buttons = nmt_newt_grid_new ();
	nmt_newt_grid_add (NMT_NEWT_GRID (vbox), buttons, 0, 2);

	cancel = g_object_ref_sink (nmt_newt_button_new (_("Cancel")));
	nmt_newt_widget_set_exit_on_activate (cancel, TRUE);
	nmt_newt_grid_add (NMT_NEWT_GRID (buttons), cancel, 0, 0);
	nmt_newt_grid_set_flags (NMT_NEWT_GRID (buttons), cancel,
	                         NMT_NEWT_GRID_EXPAND_X | NMT_NEWT_GRID_ANCHOR_RIGHT |
	                         NMT_NEWT_GRID_FILL_Y);

	ok = g_object_ref_sink (nmt_newt_button_new (_("OK")));
	g_signal_connect (ok, "clicked", G_CALLBACK (path_selected), dialog);
	nmt_newt_grid_add (NMT_NEWT_GRID (buttons), ok, 1, 0);
	nmt_newt_widget_set_padding (ok, 1, 0, 0, 0);

	nmt_newt_form_set_content (NMT_NEWT_FORM (dialog), vbox);

	G_OBJECT_CLASS (nmt_newt_file_dialog_parent_class)->constructed (object);
}

static void
nmt_newt_file_dialog_finalize (GObject *object)
{
	NmtNewtFileDialogPrivate *priv = NMT_NEWT_FILE_DIALOG_GET_PRIVATE (object);

	g_free (priv->cwd);
	g_free (priv->display_cwd);
	g_free (priv->selection);
	g_free (priv->display_selection);

	if (priv->filter_destroy)
		priv->filter_destroy (priv->filter_data);

	G_OBJECT_CLASS (nmt_newt_file_dialog_parent_class)->finalize (object);
}

static void
nmt_newt_file_dialog_set_cwd (NmtNewtFileDialog *dialog,
                              const char        *cwd)
{
	NmtNewtFileDialogPrivate *priv = NMT_NEWT_FILE_DIALOG_GET_PRIVATE (dialog);

	if (cwd && priv->cwd && !strcmp (cwd, priv->cwd))
		return;

	g_free (priv->cwd);
	g_free (priv->display_cwd);

	if (cwd)
		priv->cwd = g_strdup (cwd);
	else
		priv->cwd = g_get_current_dir ();
	priv->display_cwd = nmt_newt_filename_to_utf8 (priv->cwd);

	rebuild_dialog (dialog);

	g_object_notify (G_OBJECT (dialog), "cwd");
	g_object_notify (G_OBJECT (dialog), "display-cwd");
}

static void
nmt_newt_file_dialog_set_selection (NmtNewtFileDialog *dialog,
                                    const char        *selection)
{
	NmtNewtFileDialogPrivate *priv = NMT_NEWT_FILE_DIALOG_GET_PRIVATE (dialog);

	if (selection && !*selection)
		selection = NULL;
	if (!g_strcmp0 (selection, priv->selection) && priv->display_selection != NULL)
		return;

	g_free (priv->selection);
	priv->selection = g_strdup (selection);

	g_free (priv->display_selection);
	if (selection)
		priv->display_selection = nmt_newt_filename_to_utf8 (selection);
	else
		priv->display_selection = g_strdup (_("(none)"));

	update_selection (dialog);

	g_object_notify (G_OBJECT (dialog), "selection");
	g_object_notify (G_OBJECT (dialog), "display-selection");
}

static void
nmt_newt_file_dialog_set_property (GObject      *object,
                                   guint         prop_id,
                                   const GValue *value,
                                   GParamSpec   *pspec)
{
	NmtNewtFileDialog *dialog = NMT_NEWT_FILE_DIALOG (object);

	switch (prop_id) {
	case PROP_CWD:
		nmt_newt_file_dialog_set_cwd (dialog, g_value_get_string (value));
		break;
	case PROP_SELECTION:
		nmt_newt_file_dialog_set_selection (dialog, g_value_get_string (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_file_dialog_get_property (GObject    *object,
                                   guint       prop_id,
                                   GValue     *value,
                                   GParamSpec *pspec)
{
	NmtNewtFileDialogPrivate *priv = NMT_NEWT_FILE_DIALOG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CWD:
		g_value_set_string (value, priv->cwd);
		break;
	case PROP_DISPLAY_CWD:
		g_value_set_string (value, priv->display_cwd);
		break;
	case PROP_SELECTION:
		g_value_set_string (value, priv->selection);
		break;
	case PROP_DISPLAY_SELECTION:
		g_value_set_string (value, priv->display_selection);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_file_dialog_class_init (NmtNewtFileDialogClass *dialog_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (dialog_class);

	g_type_class_add_private (dialog_class, sizeof (NmtNewtFileDialogPrivate));

	/* virtual methods */
	object_class->constructed  = nmt_newt_file_dialog_constructed;
	object_class->set_property = nmt_newt_file_dialog_set_property;
	object_class->get_property = nmt_newt_file_dialog_get_property;
	object_class->finalize     = nmt_newt_file_dialog_finalize;

	g_object_class_override_property (object_class, PROP_CWD, "cwd");
	g_object_class_override_property (object_class, PROP_DISPLAY_CWD, "display-cwd");
	g_object_class_override_property (object_class, PROP_SELECTION, "selection");
	g_object_class_override_property (object_class, PROP_DISPLAY_SELECTION, "display-selection");
}

static void
nmt_newt_file_dialog_set_filter (NmtNewtFilePicker       *picker,
                                 NmtNewtFilePickerFilter  filter,
                                 gpointer                 filter_data,
                                 GDestroyNotify           filter_destroy)
{
	NmtNewtFileDialogPrivate *priv = NMT_NEWT_FILE_DIALOG_GET_PRIVATE (picker);

	if (priv->filter_destroy)
		priv->filter_destroy (priv->filter_data);

	priv->filter = filter;
	priv->filter_data = filter_data;
	priv->filter_destroy = filter_destroy;

	rebuild_dialog (NMT_NEWT_FILE_DIALOG (picker));
}

static const char *
nmt_newt_file_dialog_get_cwd (NmtNewtFilePicker *picker)
{
	return NMT_NEWT_FILE_DIALOG_GET_PRIVATE (picker)->cwd;
}

static const char *
nmt_newt_file_dialog_get_selection (NmtNewtFilePicker *picker)
{
	return NMT_NEWT_FILE_DIALOG_GET_PRIVATE (picker)->selection;
}

static void
nmt_newt_file_dialog_file_picker_interface_init (NmtNewtFilePickerInterface *iface,
                                                 gpointer iface_data)
{
	iface->set_filter = nmt_newt_file_dialog_set_filter;
	iface->get_cwd = nmt_newt_file_dialog_get_cwd;
	iface->get_selection = nmt_newt_file_dialog_get_selection;
}
