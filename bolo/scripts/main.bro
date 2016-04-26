##! Be on the look out for MAC addresses seen in DHCP requests.
#
# Grant Stavely gstavely@evernote.com

module Bolo;

type IdxMac: record {
	bolo_mac: string;
};

type BoloAttributes: record {
	comment: string;
};

export {
	## This file will be loaded by the input framework.
	## Redefine this in your local.bro to be in e.g.
	## /opt/bro/share/bro/site/input/bolo_mac_addresses.bolo
	global file_of_mac_addresses= "mac_addresses.bolo" &redef;
	
	## A table of mac addresses and the provided comment about each.
	global mac_addresses: table[string] of string = table() &redef;
	
	## Notice what we're on the lookout for specifically
	redef enum Notice::Type += {
		MAC_Seen_In_DHCP_Request,
	};
}

event bro_init()
	{
	## The input framework needs to load htings at bro_init()
	## New items can be added and will load without restarting bro
	local mac_addresses_path = fmt(file_of_mac_addresses);
	Reporter::info(fmt("Loading MAC addresses to be on the lookout for:  %s...", mac_addresses_path));
	Input::add_table([$source=mac_addresses_path,
		$name="mac_address_stream",
		$idx=IdxMac,
		$val=BoloAttributes,
		$destination=Bolo::mac_addresses,
		$mode=Input::REREAD]);
	}

event dhcp_request(c: connection, msg: dhcp_msg, req_addr: addr, serv_addr: addr, host_name: string)
	{
	if ( msg$h_addr == "" )
		return;
	
	if ( msg$h_addr in mac_addresses )
		NOTICE([$note=MAC_Seen_In_DHCP_Request,
				$msg=fmt("BOLO: %s spotted: %s (%s) has just requested a DHCP lease for %s.", 
						 mac_addresses[msg$h_addr], msg$h_addr, host_name, req_addr),
				$conn=c,
				$suppress_for=1day,
				$identifier=cat(msg$h_addr)]);
	}