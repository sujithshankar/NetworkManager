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
 * SECTION:nmt-newt-file-button
 * @short_description: File-selection button
 *
 * #NmtNewtFileButton provides a label showing a filename, and a button that will
 * pop up a dialog for selecting a new file.
 */

#include "config.h"

#include <glib/gi18n-lib.h>

#include "nmt-newt-file-button.h"
#include "nmt-newt-file-picker.h"

static void nmt_newt_file_button_file_picker_interface_init (NmtNewtFilePickerInterface *iface, gpointer iface_data);

G_DEFINE_TYPE_WITH_CODE (NmtNewtFileButton, nmt_newt_file_button, NMT_TYPE_NEWT_GRID,
                         G_IMPLEMENT_INTERFACE (NMT_TYPE_NEWT_FILE_PICKER,
                                                nmt_newt_file_button_file_picker_interface_init);
                         )

#define NMT_NEWT_FILE_BUTTON_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_FILE_BUTTON, NmtNewtFileButtonPrivate))

typedef struct {
	NmtNewtLabel *label;
	NmtNewtButton *button;
	NmtNewtFileDialog *dialog;
} NmtNewtFileButtonPrivate;

enum {
	PROP_0,
	PROP_DIALOG_TITLE,
	PROP_SENSITIVE,
	PROP_CWD,
	PROP_DISPLAY_CWD,
	PROP_SELECTION,
	PROP_DISPLAY_SELECTION,

	LAST_PROP
};

/**
 * nmt_newt_file_button_new:
 * @dialog_title: the title to use for the #NmtNewtFileDialog
 *
 * Creates a new #NmtNewtFileButton
 *
 * Returns: a new #NmtNewtFileButton
 */
NmtNewtWidget *
nmt_newt_file_button_new (const char *dialog_title)
{
	return g_object_new (NMT_TYPE_NEWT_FILE_BUTTON,
	                     "dialog-title", dialog_title,
	                     NULL);
}

static void
dialog_notify (GObject    *dialog,
               GParamSpec *pspec,
               gpointer    button)
{
	if (   !strcmp (pspec->name, "cwd")
	    || !strcmp (pspec->name, "display-cwd")
	    || !strcmp (pspec->name, "selection")
	    || !strcmp (pspec->name, "display-selection"))
		g_object_notify (button, pspec->name);
}

static void
nmt_newt_file_button_init (NmtNewtFileButton *button)
{
	NmtNewtFileButtonPrivate *priv = NMT_NEWT_FILE_BUTTON_GET_PRIVATE (button);

	priv->dialog = NMT_NEWT_FILE_DIALOG (nmt_newt_file_dialog_new ());
	g_signal_connect (priv->dialog, "notify", G_CALLBACK (dialog_notify), button);
}

static void
select_file (NmtNewtButton *select_button,
             gpointer user_data)
{
	NmtNewtFileButton *button = user_data;
	NmtNewtFileButtonPrivate *priv = NMT_NEWT_FILE_BUTTON_GET_PRIVATE (button);

	nmt_newt_form_run_sync (NMT_NEWT_FORM (priv->dialog));
}

static gboolean
transform_selection_for_label (GBinding     *binding,
                               const GValue *from_value,
                               GValue       *to_value,
                               gpointer      user_data)
{
	const char *selection = g_value_get_string (from_value);
	char *label;

	label = g_path_get_basename (selection);
	g_value_take_string (to_value, label);
	return TRUE;
}

static void
nmt_newt_file_button_constructed (GObject *object)
{
	NmtNewtFileButtonPrivate *priv = NMT_NEWT_FILE_BUTTON_GET_PRIVATE (object);
	NmtNewtGrid *grid = NMT_NEWT_GRID (object);
	NmtNewtWidget *widget;

	widget = nmt_newt_label_new ("");
	priv->label = NMT_NEWT_LABEL (widget);
	nmt_newt_label_set_style (priv->label, NMT_NEWT_LABEL_PLAIN);
	nmt_newt_grid_add (grid, widget, 0, 0);

	widget = nmt_newt_button_new (_("Select..."));
	priv->button = NMT_NEWT_BUTTON (widget);
	nmt_newt_grid_add (grid, widget, 1, 0);
	nmt_newt_widget_set_padding (widget, 1, 0, 0, 0);
	g_signal_connect (priv->button, "clicked",
	                  G_CALLBACK (select_file), object);

	g_object_bind_property_full (priv->dialog, "display-selection",
	                             priv->label, "text",
	                             G_BINDING_SYNC_CREATE,
	                             transform_selection_for_label,
	                             NULL, NULL, NULL);

	G_OBJECT_CLASS (nmt_newt_file_button_parent_class)->constructed (object);
}

static void
nmt_newt_file_button_dispose (GObject *object)
{
	NmtNewtFileButtonPrivate *priv = NMT_NEWT_FILE_BUTTON_GET_PRIVATE (object);

	g_clear_object (&priv->dialog);

	G_OBJECT_CLASS (nmt_newt_file_button_parent_class)->dispose (object);
}

static void
nmt_newt_file_button_set_property (GObject      *object,
                                   guint         prop_id,
                                   const GValue *value,
                                   GParamSpec   *pspec)
{
	NmtNewtFileButtonPrivate *priv = NMT_NEWT_FILE_BUTTON_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SENSITIVE:
		g_object_set_property (G_OBJECT (priv->button), pspec->name, value);
		break;
	case PROP_DIALOG_TITLE:
		g_object_set_property (G_OBJECT (priv->dialog), "title", value);
		break;
	case PROP_CWD:
	case PROP_SELECTION:
		g_object_set_property (G_OBJECT (priv->dialog), pspec->name, value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_file_button_get_property (GObject    *object,
                                   guint       prop_id,
                                   GValue     *value,
                                   GParamSpec *pspec)
{
	NmtNewtFileButtonPrivate *priv = NMT_NEWT_FILE_BUTTON_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SENSITIVE:
		g_object_get_property (G_OBJECT (priv->button), pspec->name, value);
		break;
	case PROP_DIALOG_TITLE:
		g_object_get_property (G_OBJECT (priv->dialog), "title", value);
		break;
	case PROP_CWD:
	case PROP_DISPLAY_CWD:
	case PROP_SELECTION:
	case PROP_DISPLAY_SELECTION:
		g_object_get_property (G_OBJECT (priv->dialog), pspec->name, value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_file_button_class_init (NmtNewtFileButtonClass *entry_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (entry_class);

	g_type_class_add_private (entry_class, sizeof (NmtNewtFileButtonPrivate));

	/* virtual methods */
	object_class->constructed  = nmt_newt_file_button_constructed;
	object_class->set_property = nmt_newt_file_button_set_property;
	object_class->get_property = nmt_newt_file_button_get_property;
	object_class->dispose      = nmt_newt_file_button_dispose;

	/**
	 * NmtNewtFileButton:dialog-title:
	 *
	 * The title to use for the #NmtNewtFileDialog.
	 */
	g_object_class_install_property
		(object_class, PROP_DIALOG_TITLE, 
		 g_param_spec_string ("dialog-title", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NmtNewtFileButton:sensitive:
	 *
	 * Whether the widget is sensitive; this is just a proxy for the embedded
	 * #NmtNewtButton's #NmtNewtComponent:sensitive property.
	 */
	g_object_class_install_property
		(object_class, PROP_SENSITIVE,
		 g_param_spec_boolean ("sensitive", "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_override_property (object_class, PROP_CWD, "cwd");
	g_object_class_override_property (object_class, PROP_DISPLAY_CWD, "display-cwd");
	g_object_class_override_property (object_class, PROP_SELECTION, "selection");
	g_object_class_override_property (object_class, PROP_DISPLAY_SELECTION, "display-selection");
}

static void
nmt_newt_file_button_set_filter (NmtNewtFilePicker       *picker,
                                 NmtNewtFilePickerFilter  filter,
                                 gpointer                 filter_data,
                                 GDestroyNotify           filter_destroy)
{
	NmtNewtFileButtonPrivate *priv = NMT_NEWT_FILE_BUTTON_GET_PRIVATE (picker);

	nmt_newt_file_picker_set_filter (NMT_NEWT_FILE_PICKER (priv->dialog),
	                                 filter, filter_data, filter_destroy);
}

static const char *
nmt_newt_file_button_get_cwd (NmtNewtFilePicker *picker)
{
	NmtNewtFileButtonPrivate *priv = NMT_NEWT_FILE_BUTTON_GET_PRIVATE (picker);

	return nmt_newt_file_picker_get_cwd (NMT_NEWT_FILE_PICKER (priv->dialog));
}

static const char *
nmt_newt_file_button_get_selection (NmtNewtFilePicker *picker)
{
	NmtNewtFileButtonPrivate *priv = NMT_NEWT_FILE_BUTTON_GET_PRIVATE (picker);

	return nmt_newt_file_picker_get_selection (NMT_NEWT_FILE_PICKER (priv->dialog));
}

static void
nmt_newt_file_button_file_picker_interface_init (NmtNewtFilePickerInterface *iface,
                                                 gpointer iface_data)
{
	iface->set_filter = nmt_newt_file_button_set_filter;
	iface->get_cwd = nmt_newt_file_button_get_cwd;
	iface->get_selection = nmt_newt_file_button_get_selection;
}
