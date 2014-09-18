include $(GLIB_MAKEFILE)

@GNOME_CODE_COVERAGE_RULES@

SUBDIRS =				\
	.				\
	devices/adsl			\
	devices/wifi			\
	dhcp-manager			\
	ppp-manager			\
	settings/plugins

if WITH_MODEM_MANAGER_1
SUBDIRS +=				\
	devices/wwan			\
	devices/bluetooth
endif

if WITH_WIMAX
SUBDIRS += devices/wimax
endif

if WITH_TEAMDCTL
SUBDIRS += devices/team
endif

if ENABLE_TESTS
SUBDIRS += \
	dhcp-manager/tests \
	dnsmasq-manager/tests \
	platform \
	rdisc \
	supplicant-manager/tests \
	tests
endif

AM_CPPFLAGS =				\
	-I$(top_srcdir)/include		\
	-I$(top_srcdir)/introspection	\
	-I$(top_srcdir)/libnm-core	\
	-I$(top_builddir)/libnm-core	\
	-I$(top_srcdir)/callouts	\
	-DPREFIX=\"$(prefix)\"          \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION	\
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE

# add each subdirectory that contains a libNM source file. $(sort) is being used
# primarily for its side effect of removing duplicates.
AM_CPPFLAGS += $(foreach d,$(sort $(dir $(libNetworkManager_la_SOURCES))),-I$(top_srcdir)/src/$d)

###########################################
# NetworkManager
###########################################

sbin_PROGRAMS = NetworkManager

NetworkManager_SOURCES = \
	$(nm_device_sources) $(nm_device_headers) \
	main.c

NetworkManager_LDADD = libNetworkManager.la

noinst_LTLIBRARIES = libNetworkManager.la

nm_device_sources = \
	devices/nm-device-bond.c \
	devices/nm-device-bridge.c \
	devices/nm-device-ethernet.c \
	devices/nm-device-gre.c \
	devices/nm-device-infiniband.c \
	devices/nm-device-macvlan.c \
	devices/nm-device-tun.c \
	devices/nm-device-veth.c \
	devices/nm-device-vlan.c \
	devices/nm-device-vxlan.c \
	$(NULL)

nm_device_headers = \
	devices/nm-device-bond.h \
	devices/nm-device-bridge.h \
	devices/nm-device-ethernet.h \
	devices/nm-device-gre.h \
	devices/nm-device-infiniband.h \
	devices/nm-device-macvlan.h \
	devices/nm-device-tun.h \
	devices/nm-device-veth.h \
	devices/nm-device-vlan.h \
	devices/nm-device-vxlan.h

libNetworkManager_la_SOURCES = \
	$(nm_device_headers) \
	devices/nm-device.c \
	devices/nm-device.h \
	devices/nm-device-ethernet-utils.c \
	devices/nm-device-ethernet-utils.h \
	devices/nm-device-factory.c \
	devices/nm-device-factory.h \
	devices/nm-device-generic.c \
	devices/nm-device-generic.h \
	devices/nm-device-logging.h \
	devices/nm-device-private.h \
	\
	dhcp-manager/nm-dhcp-client.c \
	dhcp-manager/nm-dhcp-client.h \
	dhcp-manager/nm-dhcp-utils.c \
	dhcp-manager/nm-dhcp-utils.h \
	dhcp-manager/nm-dhcp-dhclient.c \
	dhcp-manager/nm-dhcp-dhclient.h \
	dhcp-manager/nm-dhcp-dhclient-utils.c \
	dhcp-manager/nm-dhcp-dhclient-utils.h \
	dhcp-manager/nm-dhcp-dhcpcd.c \
	dhcp-manager/nm-dhcp-dhcpcd.h \
	dhcp-manager/nm-dhcp-manager.c \
	dhcp-manager/nm-dhcp-manager.h \
	\
	dns-manager/nm-dns-dnsmasq.c \
	dns-manager/nm-dns-dnsmasq.h \
	dns-manager/nm-dns-unbound.c \
	dns-manager/nm-dns-unbound.h \
	dns-manager/nm-dns-manager.c \
	dns-manager/nm-dns-manager.h \
	dns-manager/nm-dns-plugin.c \
	dns-manager/nm-dns-plugin.h \
	dns-manager/nm-dns-utils.c \
	dns-manager/nm-dns-utils.h \
	\
	dnsmasq-manager/nm-dnsmasq-manager.c \
	dnsmasq-manager/nm-dnsmasq-manager.h \
	dnsmasq-manager/nm-dnsmasq-utils.c \
	dnsmasq-manager/nm-dnsmasq-utils.h \
	\
	firewall-manager/nm-firewall-manager.c \
	firewall-manager/nm-firewall-manager.h \
	\
	platform/nm-fake-platform.c \
	platform/nm-fake-platform.h \
	platform/nm-linux-platform.c \
	platform/nm-linux-platform.h \
	platform/nm-platform.c \
	platform/nm-platform.h \
	platform/wifi/wifi-utils-nl80211.c \
	platform/wifi/wifi-utils-nl80211.h \
	platform/wifi/wifi-utils-private.h \
	platform/wifi/wifi-utils.c \
	platform/wifi/wifi-utils.h \
	\
	rdisc/nm-fake-rdisc.c \
	rdisc/nm-fake-rdisc.h \
	rdisc/nm-lndp-rdisc.c \
	rdisc/nm-lndp-rdisc.h \
	rdisc/nm-rdisc.c \
	rdisc/nm-rdisc.h \
	\
	ppp-manager/nm-ppp-manager.c \
	ppp-manager/nm-ppp-manager.h \
	ppp-manager/nm-ppp-status.h \
	\
	settings/nm-agent-manager.c \
	settings/nm-agent-manager.h \
	settings/nm-inotify-helper.c \
	settings/nm-inotify-helper.h \
	settings/nm-secret-agent.c \
	settings/nm-secret-agent.h \
	settings/nm-settings-connection.c \
	settings/nm-settings-connection.h \
	settings/nm-settings-error.c \
	settings/nm-settings-error.h \
	settings/nm-settings.c \
	settings/nm-settings.h \
	settings/nm-system-config-interface.c \
	settings/nm-system-config-interface.h \
	\
	settings/plugins/keyfile/common.h \
	settings/plugins/keyfile/errors.c \
	settings/plugins/keyfile/nm-keyfile-connection.c \
	settings/plugins/keyfile/nm-keyfile-connection.h \
	settings/plugins/keyfile/plugin.c \
	settings/plugins/keyfile/plugin.h \
	settings/plugins/keyfile/reader.c \
	settings/plugins/keyfile/reader.h \
	settings/plugins/keyfile/utils.c \
	settings/plugins/keyfile/utils.h \
	settings/plugins/keyfile/writer.c \
	settings/plugins/keyfile/writer.h \
	\
	supplicant-manager/nm-supplicant-config.c \
	supplicant-manager/nm-supplicant-config.h \
	supplicant-manager/nm-supplicant-interface.c \
	supplicant-manager/nm-supplicant-interface.h \
	supplicant-manager/nm-supplicant-manager.c \
	supplicant-manager/nm-supplicant-manager.h \
	supplicant-manager/nm-supplicant-settings-verify.c \
	supplicant-manager/nm-supplicant-settings-verify.h \
	supplicant-manager/nm-supplicant-types.h \
	\
	vpn-manager/nm-vpn-connection.c \
	vpn-manager/nm-vpn-connection.h \
	vpn-manager/nm-vpn-manager.c \
	vpn-manager/nm-vpn-manager.h \
	vpn-manager/nm-vpn-service.c \
	vpn-manager/nm-vpn-service.h \
	\
	nm-activation-request.c \
	nm-activation-request.h \
	nm-active-connection.c \
	nm-active-connection.h \
	nm-config.c \
	nm-config.h \
	nm-connection-provider.c \
	nm-connection-provider.h \
	nm-connectivity.c \
	nm-connectivity.h \
	nm-dbus-manager.c \
	nm-dbus-manager.h \
	nm-dcb.c \
	nm-dcb.h \
	nm-dhcp4-config.c \
	nm-dhcp4-config.h \
	nm-dhcp6-config.c \
	nm-dhcp6-config.h \
	nm-dispatcher.c \
	nm-dispatcher.h \
	nm-enum-types.c \
	nm-enum-types.h \
	nm-ip4-config.c \
	nm-ip4-config.h \
	nm-ip6-config.c \
	nm-ip6-config.h \
	nm-logging.c \
	nm-logging.h \
	nm-manager-auth.c \
	nm-manager-auth.h \
	nm-auth-subject.c \
	nm-auth-subject.h \
	nm-manager.c \
	nm-manager.h \
	nm-object.c \
	nm-object.h \
	nm-policy.c \
	nm-policy.h \
	nm-posix-signals.c \
	nm-posix-signals.h \
	nm-properties-changed-signal.c \
	nm-properties-changed-signal.h \
	nm-rfkill-manager.c \
	nm-rfkill-manager.h \
	nm-session-monitor.h \
	nm-session-utils.c \
	nm-session-utils.h \
	nm-sleep-monitor.h \
	nm-types.h \
	NetworkManagerUtils.c \
	NetworkManagerUtils.h

if SESSION_TRACKING_SYSTEMD
libNetworkManager_la_SOURCES += nm-session-monitor-systemd.c
else
if SESSION_TRACKING_CK
libNetworkManager_la_SOURCES += nm-session-monitor-ck.c
else
libNetworkManager_la_SOURCES += nm-session-monitor-null.c
endif
endif

if SUSPEND_RESUME_SYSTEMD
libNetworkManager_la_SOURCES += nm-sleep-monitor-systemd.c
else
# UPower suspend/resume used whenever systemd is not enabled
libNetworkManager_la_SOURCES += nm-sleep-monitor-upower.c
endif

if WITH_WEXT
libNetworkManager_la_SOURCES += \
	platform/wifi/wifi-utils-wext.c \
	platform/wifi/wifi-utils-wext.h
endif


GLIB_GENERATED = nm-enum-types.h nm-enum-types.c
GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM
nm_enum_types_sources = $(libNetworkManager_la_SOURCES)

if WITH_WIMAX
nm_enum_types_sources += devices/wimax/nm-device-wimax.h
AM_CPPFLAGS += -I$(top_srcdir)/src/devices/wimax
endif

BUILT_SOURCES = $(GLIB_GENERATED)

AM_CPPFLAGS += \
	$(GLIB_CFLAGS) \
	$(GUDEV_CFLAGS) \
	$(LIBNL_CFLAGS) \
	$(LIBNDP_CFLAGS) \
	$(LIBSOUP_CFLAGS) \
	$(POLKIT_CFLAGS) \
	$(SYSTEMD_LOGIN_CFLAGS) \
	\
	-DBINDIR=\"$(bindir)\" \
	-DDATADIR=\"$(datadir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DSBINDIR=\"$(sbindir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DRUNDIR=\"$(rundir)\" \
	\
	-DNMCONFDIR=\"$(nmconfdir)\" \
	-DNMLOCALEDIR=\"$(datadir)/locale\" \
	-DNMPLUGINDIR=\"$(pkglibdir)\" \
	-DNMRUNDIR=\"$(nmrundir)\" \
	-DNMSTATEDIR=\"$(nmstatedir)\" \
	\
	-DDHCLIENT_PATH=\"$(DHCLIENT_PATH)\" \
	-DDHCPCD_PATH=\"$(DHCPCD_PATH)\" \
	-DPPPD_PLUGIN_DIR=\"$(PPPD_PLUGIN_DIR)\" \
	\
	$(NULL)

if SESSION_TRACKING_CK
AM_CPPFLAGS += -DCKDB_PATH=\"${CKDB_PATH}\"
endif

libNetworkManager_la_LIBADD = \
	$(top_builddir)/libnm-core/libnm-core.la \
	$(top_builddir)/introspection/libnmdbus.la \
	$(GLIB_LIBS) \
	$(GUDEV_LIBS) \
	$(LIBNL_LIBS) \
	$(POLKIT_LIBS) \
	$(SYSTEMD_LOGIN_LIBS) \
	$(LIBNDP_LIBS) \
	$(LIBDL) \
	$(LIBM)

if WITH_LIBSOUP
libNetworkManager_la_LIBADD += $(LIBSOUP_LIBS)
endif

NetworkManager_LDFLAGS = -rdynamic

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = org.freedesktop.NetworkManager.conf

EXTRA_DIST = \
	$(dbusservice_DATA) \
	$(NetworkManager_DATA)

rundir=$(localstatedir)/run/NetworkManager
statedir=$(localstatedir)/lib/NetworkManager
install-data-hook:
	$(mkinstalldirs) -m 0700 $(DESTDIR)$(rundir)
	$(mkinstalldirs) -m 0700 $(DESTDIR)$(statedir)
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(pkglibdir)

CLEANFILES = \
	$(BUILT_SOURCES)
