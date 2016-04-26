##! This script will generate a notice if an apparent protocol session,
##! long flow, or excessive short flows originate or terminate at a host,
##! net, or reverse DNS zone that isn't whitelisted.
##!
##! The input framework is used to populate tables of whitelists of subnets,
##! and zones, optionally with peers. Kinda the inverse of this BotFlex script:
##! https://github.com/sheharbano/BotFlex/blob/master/services/blacklist_mgr.bro

@load base/frameworks/input
@load evernote/human

module Exfiltration;

## Subnets used to supress alerts are loaded dynamically using the input framework
type IdxNet: record {
	whitelist_subnet: subnet;
};

## Hostnames used to supress alerts are loaded dynamically using the input framework
type IdxName: record {
	whitelist_hostname: string;
};

## Domains will read once and concatentated into to a single large regular 
## expression at bro_init() 
type IdxZone: record {
	whitelist_zone: string;
};

## Comments can be used to describe whitelisted subnets, domains, and hostnames.
type WhitelistAttributes: record {
	comment: string;
};

export {
	## Context notices provide both superssion justification and a record of important 
	## knowns about flows.
	redef enum Notice::Type += {
		Context,
	};

	## Hostname and Subnet whitelists can be loaded by the input framework.
	## Redefine them in your local.bro to be in e.g.
	## /opt/bro/share/bro/site/input/hostnames.whitelist
	global file_of_whitelisted_hostnames = "hostnames.whitelist" &redef;
	global file_of_whitelisted_subnets = "subnets.whitelist" &redef;

	## Store each whitelist in a table
	global whitelisted_hostnames: table[string] of WhitelistAttributes = table() &redef;
	global whitelisted_subnets: table[subnet] of WhitelistAttributes = table() &redef;

	## Regular expressions can only be generated at init, which can happen
	## before the input framework has loaded. Redefine them in local.bro
	global common_zones: set[string] &redef;
	global whitelisted_zones_regex: pattern = /MATCH_NOTHING/ &redef;
	global local_zones_regex: pattern = /MATCH_NOTHING/ &redef;

	## Begin caching contextual findings since bro_init() so that incidators found in one
	## connection persist at simpler levels in future connections.
	global whitelist_cache: table[addr] of string &redef;
}

# Notice context so that connections can be annotated when they match whitelists.
function provide_context(c: connection, meta: string)
	{
	NOTICE([$note=Context,
	        $msg=meta,
	        $conn=c]);
	}

# Notice context so that connections can be annotated even when a full
# connection record is not available at notice time.
function provide_connectionless_context(id: conn_id, meta: string)
	{
	NOTICE([$note=Context,
	        $msg=meta,
	        $id=id]);
	}

event bro_init()
	{
	# Notice and log the full regular expression assembled from the domain
	# whitelist.
	Reporter::info("Building zone regex");
	whitelisted_zones_regex = set_to_regex(common_zones, "(\\.?|\\.)(~~)$");
	local_zones_regex = set_to_regex(Site::local_zones, "(\\.?|\\.)(~~)$");
	Reporter::info(fmt("Zone regex complete: %s", whitelisted_zones_regex));

	# Load and watch the file of whitelisted subnets so that it can be
	# updated without restarting Bro.
	local whitelist_path = fmt(file_of_whitelisted_subnets);
	Reporter::info(fmt("Loading subnet whitelists from %s...",whitelist_path));
	Input::add_table([$source=whitelist_path,
	                  $name="whitelist_subnet_stream",
	                  $idx=IdxNet,
	                  $val=WhitelistAttributes,
	                  $destination=Exfiltration::whitelisted_subnets,
	                  $mode=Input::REREAD]);

	# Load and watch the file of whitelisted hostnames so that it can be
	# updated without restarting Bro.
	whitelist_path = fmt(file_of_whitelisted_hostnames);
	Reporter::info(fmt("Loading hostname whitelists from %s...",whitelist_path));
	Input::add_table([$source=whitelist_path,
	                  $name="whitelist_hostname_stream",
	                  $idx=IdxName,
	                  $val=WhitelistAttributes,
	                  $destination=Exfiltration::whitelisted_hostnames,
	                  $mode=Input::REREAD]);
	}

event Input::end_of_data(name: string, source:string)
	{
	Reporter::info(fmt("Input file: %s is ready", source));
	}

# TODO: consider moving this to evernote/human
function x509_subject_common_name(distinguished_name: string): string
	{
	const match_common_name: pattern = /CN=(.*?),/;
	local extracted_common_name = match_pattern(distinguished_name, match_common_name);
	if (extracted_common_name$matched)
		{
		const extract_common_name: pattern = /\.[^,]*/;
		local extracted_common_name_domain = match_pattern(extracted_common_name$str, extract_common_name);
		if (extracted_common_name_domain$matched)
			return extracted_common_name_domain$str;
		}
	else
		return "no_match";
	}

## Whitelist context does not assert an identity relationship to observables and knowns.
## Whitelist context is merely a suppression tool. Do not assert anything beyond prior 
## known association.
function add_to_whitelist_cache(a: addr, uid: string, comment: string)
	{
	whitelist_cache[a] = fmt("%s was previously associated with %s in %s", a, comment, uid);
	}

function whitelisted_connection_in_cache(c: connection): bool
	{
	if (c$id$resp_h in whitelist_cache)
		{
		provide_context(c, whitelist_cache[c$id$resp_h]);
		return T;
		}
	else
		{
		return F;
		}
	}

function whitelisted_id_in_cache(id: conn_id): bool
	{
	if (id$resp_h in whitelist_cache)
		{
		provide_connectionless_context(id, whitelist_cache[id$resp_h]);
		return T;
		}
	else
		{
		return F;
		}
	}

function whitelisted_address_by_subnet(a: addr): bool
	{
	if (a in whitelisted_subnets)
		{
		local meta = "";
		for (whitelisted_subnet in whitelisted_subnets)
			{
			if (a in whitelisted_subnet)
				meta += fmt("%s -> %s: %s ",
				             a,
				             whitelisted_subnet,
				             whitelisted_subnets[whitelisted_subnet]$comment);
			}
		return T;
		}
	else
		{
		return F;
		}
	}

function whitelisted_connection_by_subnet(c: connection): bool
	{
	if (c$id$resp_h in whitelisted_subnets)
		{
		local meta = "";
		for (whitelisted_subnet in whitelisted_subnets)
			{
			if (c$id$resp_h in whitelisted_subnet)
				meta += fmt("%s -> %s: %s",
				             c$id$resp_h,
				             whitelisted_subnet,
				             whitelisted_subnets[whitelisted_subnet]$comment);
			}
		provide_context(c, meta);
		return T;
		}
	else
		{
		return F;
		}
	}

function whitelisted_connection_by_hostname(c: connection, name: string): bool
	{
	if (name in whitelisted_hostnames)
		{
		local meta = fmt("%s: %s.", name, whitelisted_hostnames[name]$comment);
		provide_context(c, meta);
		return T;
		}
	else
		{
		return F;
		}
	}

function whitelisted_connection_by_hostname_zone(c: connection, name: string): bool
	{
	if (whitelisted_zones_regex in name)
		{
		local match = match_pattern(name, whitelisted_zones_regex);
		local meta = fmt("%s: %s", name, match$str);
		provide_context(c, meta);
		return T;
		}
	else
		{
		return F;
		}
	}

function whitelisted_id_by_hostname(id: conn_id, name: string): bool
	{
	if (name in whitelisted_hostnames)
		{
		local meta = fmt("%s: %s.", name, whitelisted_hostnames[name]$comment);
		provide_connectionless_context(id, meta);
		return T;
		}
	else
		{
		return F;
		}
	}

function whitelisted_id_by_hostname_zone(id: conn_id, name: string): bool
	{
	if (whitelisted_zones_regex in name)
		{
		local match = match_pattern(name, whitelisted_zones_regex);
		local meta = fmt("%s: %s", name, match$str);
		provide_connectionless_context(id, meta);
		return T;
		}
	else
		{
		return F;
		}
	}