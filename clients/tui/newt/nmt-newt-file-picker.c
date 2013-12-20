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
 * SECTION:nmt-newt-file-picker
 * @short_description: Abstract interface for file selection widgets
 *
 * #NmtNewtFilePicker is the interface implemented by #NmtNewtFileButton and
 * #NmtNewtFileDialog.
 */

#include "config.h"

#include "nmt-newt-file-picker.h"

static void nmt_newt_file_picker_default_init (NmtNewtFilePickerInterface *iface);

G_DEFINE_INTERFACE (NmtNewtFilePicker, nmt_newt_file_picker, NMT_TYPE_NEWT_WIDGET)

/**
 * NmtNewtFilePickerFilter:
 * @picker: the #NmtNewtFilePicker
 * @info: the #GFileInfo to possibly filter
 * @user_data: the data passed to nmt_newt_file_picker_set_filter()
 *
 * Callback to decide whether to show a file in @picker. Currently this is only
 * called for files, not directories, and @info is only guaranteed to have the
 * information associated with %G_FILE_ATTRIBUTE_STANDARD_NAME,
 * %G_FILE_ATTRIBUTE_STANDARD_DISPLAY_NAME, and %G_FILE_ATTRIBUTE_STANDARD_TYPE.
 *
 * Returns: %TRUE if the file should be shown, %FALSE if not.
 */

static void
nmt_newt_file_picker_default_init (NmtNewtFilePickerInterface *iface)
{
	/**
	 * NmtNewtFilePicker:cwd:
	 *
	 * The current working directory of the #NmtNewtFilePicker. Setting this
	 * property to %NULL will cause it to be set to the process's current
	 * working directory.
	 *
	 * Note that this is not guaranteed to be a UTF-8 string.
	 *
	 * You cannot change this while the widget is realized.
	 *
	 * Type: filename
	 */
	g_object_interface_install_property
		(iface,
		 g_param_spec_string ("cwd", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NmtNewtFilePicker:display-cwd:
	 *
	 * The current working directory of the picker, in UTF-8.
	 *
	 * Type: utf8
	 */
	g_object_interface_install_property
		(iface,
		 g_param_spec_string ("display-cwd", "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NmtNewtFilePicker:selection:
	 *
	 * The selected file. If the user cancels the picker, this will be %NULL
	 * when the picker exits.
	 *
	 * Note that this is not guaranteed to be a UTF-8 string.
	 *
	 * You cannot change this while the widget is realized.
	 *
	 * Type: filename
	 */
	g_object_interface_install_property
		(iface,
		 g_param_spec_string ("selection", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NmtNewtFilePicker:display-selection:
	 *
	 * The selected file, in UTF-8.
	 *
	 * Type: utf8
	 */
	g_object_interface_install_property
		(iface,
		 g_param_spec_string ("display-selection", "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
}

/**
 * nmt_newt_file_picker_set_filter:
 * @picker: the #NmtNewtFilePicker
 * @filter: the filter callback
 * @filter_data: data to pass to @filter
 * @filter_destroy: #GDestroyNotify for @filter_data
 *
 * Sets the filter used to determine what files to show in @picker. Note that
 * the filter is only called for regular files; directories are always shown.
 */
void
nmt_newt_file_picker_set_filter (NmtNewtFilePicker       *picker,
                                 NmtNewtFilePickerFilter  filter,
                                 gpointer                 filter_data,
                                 GDestroyNotify           filter_destroy)
{
	NMT_NEWT_FILE_PICKER_GET_INTERFACE (picker)->set_filter (picker, filter, filter_data, filter_destroy);
}


/**
 * nmt_newt_file_picker_set_cwd:
 * @picker: the #NmtNewtFilePicker
 * @cwd: (allow-none) (type filename): the new current working directory
 *
 * Sets @picker's current working directory. If @cwd is %NULL, it will be set
 * to the process's current working directory.
 *
 * This will also clear #NmtNewtFilePicker:selection.
 */
void
nmt_newt_file_picker_set_cwd (NmtNewtFilePicker *picker,
                              const char        *cwd)
{
	g_object_set (picker,
	              "cwd", cwd,
	              "selection", NULL,
	              NULL);
}

/**
 * nmt_newt_file_picker_get_cwd:
 * @picker: the #NmtNewtFilePicker
 *
 * Gets @picker's current working directory.
 *
 * Returns: (type filename): @picker's current working directory.
 */
const char *
nmt_newt_file_picker_get_cwd (NmtNewtFilePicker *picker)
{
	return NMT_NEWT_FILE_PICKER_GET_INTERFACE (picker)->get_cwd (picker);
}

/**
 * nmt_newt_file_picker_set_selection:
 * @picker: the #NmtNewtFilePicker
 * @selection: (allow-none) (type filename): the selected file
 *
 * Sets @picker's current selection.
 */
void
nmt_newt_file_picker_set_selection (NmtNewtFilePicker *picker,
                                    const char        *selection)
{
	g_object_set (picker,
	              "selection", selection,
	              NULL);
}

/**
 * nmt_newt_file_picker_get_selection:
 * @picker: the #NmtNewtFilePicker
 *
 * Gets @picker's current selection.
 *
 * Returns: (type filename): @picker's current selection.
 */
const char *
nmt_newt_file_picker_get_selection (NmtNewtFilePicker *picker)
{
	return NMT_NEWT_FILE_PICKER_GET_INTERFACE (picker)->get_selection (picker);
}
