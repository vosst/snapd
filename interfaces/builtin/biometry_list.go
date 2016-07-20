// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package builtin

import (
	"bytes"

	"github.com/snapcore/snapd/interfaces"
)

var biometryListPermanentSlotAppArmor = []byte(`
# Description: Allow operating as biometryd. Reserved because this
#  gives privileged access to the system.
# Usage: reserved

# DBus accesses
#include <abstractions/dbus-strict>
dbus (send)
    bus=system
    path=/org/freedesktop/DBus
    interface=org.freedesktop.DBus
    member="{Request,Release}Name"
    peer=(name=org.freedesktop.DBus, label=unconfined),

dbus (send)
    bus=system
    path=/org/freedesktop/DBus
    interface=org.freedesktop.DBus
    member="GetConnectionUnix{ProcessID,User}"
    peer=(label=unconfined),

# Allow binding the service to the requested connection name
dbus (bind)
    bus=system
    name="com.ubuntu.biometryd.Service",

dbus (receive, send)
    bus=system
    path=/**
    interface=org.freedesktop.DBus**
    peer=(label=unconfined),
`)

var biometryListConnectedSlotAppArmor = []byte(`
# Allow connected clients to interact with the service

# Allow clients to query the default device
dbus (receive)
    bus=system
    path=/
    interface=com.ubuntu.biometryd.Service
    member=DefaultDevice
    peer=(label=###PLUG_SECURITY_TAGS###),

# Allow clients to list to the default device
dbus (receive)
    bus=system
    path=/default_device/template_store
    interface=com.ubuntu.biometryd.Device.TemplateStore
    member="List"
    peer=(label=###PLUG_SECURITY_TAGS###),

# Allow clients to interact with ongoing operations
dbus (receive)
    bus=system
    path=/default_device/template_store/operation/list/###PLUG_SECURITY_TAGS###/**
    interface=com.ubuntu.biometryd.Operation
    member="StartWithObserver"
    peer=(label=###PLUG_SECURITY_TAGS###),

dbus (receive)
    bus=system
    path=/default_device/template_store/operation/list/###PLUG_SECURITY_TAGS###/**
    interface=com.ubuntu.biometryd.Operation
    member="Cancel"
    peer=(label=###PLUG_SECURITY_TAGS###),

# Allow the service to send updates to clients
dbus (send)
    bus=system
    interface=com.ubuntu.biometryd.Operation.Observer
    member="On{Started, Progress, Cancelled, Failed, Succeeded}"
    peer=(label=###PLUG_SECURITY_TAGS###),
`)

var biometryListConnectedPlugAppArmor = []byte(`
# Allow connected clients to interact with the service

# Allow clients to query the default device
dbus (send)
    bus=system
    path=/
    interface=com.ubuntu.biometryd.Service
    member=DefaultDevice
    peer=(label=###SLOT_SECURITY_TAGS###),

# Allow clients to list to the default device
dbus (send)
    bus=system
    path=/default_device/template_store
    interface=com.ubuntu.biometryd.Device
    member="List"
    peer=(label=###SLOT_SECURITY_TAGS###),

# Allow clients to interact with ongoing operations
dbus (send)
    bus=system
    path=/default_device/template_store/operation/list/###PLUG_SECURITY_TAGS###/**
    interface=com.ubuntu.biometryd.Operation
    member="StartWithObserver"
    peer=(label=###SLOT_SECURITY_TAGS###),

dbus (send)
    bus=system
    path=/default_device/template_store/operation/list/###PLUG_SECURITY_TAGS###/**
    interface=com.ubuntu.biometryd.Operation
    member="Cancel"
    peer=(label=###SLOT_SECURITY_TAGS###),

# Allow the service to send updates to clients
dbus (receive)
    bus=system
    interface=com.ubuntu.biometryd.Operation.Observer
    member="On{Started, Progress, Cancelled, Failed, Succeeded}"
    peer=(label=###SLOT_SECURITY_TAGS###),
`)

var biometryListPermanentSlotSecComp = []byte(`
getsockname
recvmsg
sendmsg
sendto
`)

var biometryListConnectedPlugSecComp = []byte(`
getsockname
recvmsg
sendmsg
sendto
`)

var biometryListPermanentSlotDBus = []byte(`
<policy user="root">
    <allow own="com.ubuntu.biometryd.Service"/>
    <allow send_destination="com.ubuntu.biometryd.Service"/>
    <allow send_destination="com.ubuntu.biometryd.Device"/>
    <allow send_destination="com.ubuntu.biometryd.Identifier"/>
    <allow send_destination="com.ubuntu.biometryd.TemplateStore"/>
    <allow send_destination="com.ubuntu.biometryd.Operation"/>
    <allow send_destination="com.ubuntu.biometryd.Operation.Observer"/>
    <allow send_interface="com.ubuntu.biometryd.Service"/>
    <allow send_interface="com.ubuntu.biometryd.Device"/>
    <allow send_interface="com.ubuntu.biometryd.Identifier"/>
    <allow send_interface="com.ubuntu.biometryd.TemplateStore"/>
    <allow send_interface="com.ubuntu.biometryd.Operation"/>
    <allow send_interface="com.ubuntu.biometryd.Operation.Observer"/>
</policy>
`)

var biometryListConnectedPlugDBus = []byte(`
<policy context="default">
    <deny own="com.ubuntu.biometryd.Service"/>               
    <allow own="com.ubuntu.biometryd.Operation.Observer"/>
    <allow send_destination="com.ubuntu.biometryd.Service"/>
    <allow send_destination="com.ubuntu.biometryd.Device"/>
    <allow send_destination="com.ubuntu.biometryd.Identifier"/>
    <allow send_destination="com.ubuntu.biometryd.TemplateStore"/>
    <allow send_destination="com.ubuntu.biometryd.Operation"/>
    <allow send_destination="com.ubuntu.biometryd.Operation.Observer"/>
    <allow send_interface="com.ubuntu.biometryd.Service"/>
    <allow send_interface="com.ubuntu.biometryd.Device"/>
    <allow send_interface="com.ubuntu.biometryd.Identifier"/>
    <allow send_interface="com.ubuntu.biometryd.TemplateStore"/>
    <allow send_interface="com.ubuntu.biometryd.Operation"/>
    <allow send_interface="com.ubuntu.biometryd.Operation.Observer"/>
</policy>
`)

type BiometryListInterface struct{}

func (iface *BiometryListInterface) Name() string {
	return "biometry-list"
}

func (iface *BiometryListInterface) PermanentPlugSnippet(plug *interfaces.Plug, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityDBus, interfaces.SecurityAppArmor, interfaces.SecuritySecComp, interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *BiometryListInterface) ConnectedPlugSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		old := []byte("###SLOT_SECURITY_TAGS###")
		new := slotAppLabelExpr(slot)
		snippet := bytes.Replace(biometryListConnectedPlugAppArmor, old, new, -1)
		return snippet, nil
	case interfaces.SecurityDBus:
		return biometryListConnectedPlugDBus, nil
	case interfaces.SecuritySecComp:
		return biometryListConnectedPlugSecComp, nil
	case interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *BiometryListInterface) PermanentSlotSnippet(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		return biometryListPermanentSlotAppArmor, nil
	case interfaces.SecurityDBus:
		return biometryListPermanentSlotDBus, nil
	case interfaces.SecuritySecComp:
		return biometryListPermanentSlotSecComp, nil
	case interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *BiometryListInterface) ConnectedSlotSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		old := []byte("###PLUG_SECURITY_TAGS###")
		new := plugAppLabelExpr(plug)
		snippet := bytes.Replace(biometryListConnectedSlotAppArmor, old, new, -1)
		return snippet, nil
	case interfaces.SecurityDBus, interfaces.SecuritySecComp, interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *BiometryListInterface) SanitizePlug(plug *interfaces.Plug) error {
	return nil
}

func (iface *BiometryListInterface) SanitizeSlot(slot *interfaces.Slot) error {
	return nil
}

func (iface *BiometryListInterface) AutoConnect() bool {
	return false
}
