SUBDIRS = . tests

@GNOME_CODE_COVERAGE_RULES@

# Work around bad generated code
AM_CFLAGS = $(filter-out @AM_CFLAGS@,-Wfloat-equal)

nm-ifcfg-rh-generated.h nm-ifcfg-rh-generated.c: nm-ifcfg-rh.xml
	$(AM_V_GEN) gdbus-codegen			\
		--generate-c-code nm-ifcfg-rh-generated	\
		--c-namespace=NM			\
		--c-generate-object-manager		\
		$<

BUILT_SOURCES = \
	nm-ifcfg-rh-generated.h	\
	nm-ifcfg-rh-generated.c

pkglib_LTLIBRARIES = libnm-settings-plugin-ifcfg-rh.la

noinst_LTLIBRARIES = libifcfg-rh-io.la

libifcfg_rh_io_la_SOURCES = \
	shvar.c \
	shvar.h \
	reader.c \
	reader.h \
	writer.c \
	writer.h \
	errors.c \
	common.h \
	utils.c \
	utils.h

INCLUDES = \
	-I$(top_srcdir)/src/wifi \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/src/posix-signals \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util

libifcfg_rh_io_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(NSS_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DSBINDIR=\"$(sbindir)\"

libifcfg_rh_io_la_LIBADD = \
	$(top_builddir)/src/wifi/libwifi-utils.la \
	$(top_builddir)/src/posix-signals/libnm-posix-signals.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS) \
	$(NSS_LIBS)

libnm_settings_plugin_ifcfg_rh_la_SOURCES = \
	plugin.c \
	plugin.h \
	nm-ifcfg-rh-generated.c \
	nm-ifcfg-rh-generated.h \
	nm-ifcfg-connection.c \
	nm-ifcfg-connection.h

libnm_settings_plugin_ifcfg_rh_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GMODULE_CFLAGS) \
	$(GIO_UNIX_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\"

libnm_settings_plugin_ifcfg_rh_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_ifcfg_rh_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	libifcfg-rh-io.la \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(GIO_UNIX_LIBS)

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = nm-ifcfg-rh.conf

EXTRA_DIST = \
	$(dbusservice_DATA) \
	nm-ifcfg-rh.xml

CLEANFILES = $(BUILT_SOURCES)

