#!/bin/sh

# This ifcfg-rh-specific script runs
# /etc/sysconfig/network-scripts/ifup-routes when bringing up
# interfaces that have routing rules associated with them that can't
# be expressed by NMSettingIPConfig. (Eg, policy-based routing.)

# This should be installed in dispatcher.d/pre-up.d/

dir=$(dirname "$CONNECTION_FILENAME")
if [ "$dir" != "/etc/sysconfig/network-scripts" ]; then
    exit 0
fi
profile=$(basename "$CONNECTION_FILENAME" | sed -ne 's/^ifcfg-//p')
if [ -z "$profile" ]; then
    exit 0
fi

if [ -f "$dir/rule-$profile" -o -f "$dir/rule6-$profile" ]; then
    /etc/sysconfig/network-scripts/ifup-routes "$DEVICE_IP_IFACE" "$profile"
fi
