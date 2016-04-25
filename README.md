# A few bro scripts.

* bolo - Be on the lookout for MAC addresses in DHCP requests
* exfiltration - Flow and protocol IDS concepts applied to bro egress whitelisting with the input and sumstats frameworks (an extension of [largeUpload](https://github.com/sooshie/bro-scripts/blob/master/2.4-scripts/largeUpload.bro) and the inverse of [blacklist_mgr](https://github.com/sheharbano/BotFlex/blob/master/services/blacklist_mgr.bro))
* human - Utility functions to represent bro data types as strings
* notice_ext - Extend bro's notice actions with a more verbose email delivery action
* ssl_ext_san - Extend bro's SSL logs to record Subject Alternative Name attributes

## Loading and configuring these in local.bro
```bro
# Evernote scripts
@load evernote/human
@load evernote/ssl_ext_san
@load evernote/exfiltration
@load evernote/bolo
@load evernote/notice_ext

# Bolo
redef Bolo::file_of_mac_addresses = "/opt/bro/share/bro/site/input/bolos/mac_addresses.bolo";

# Exfiltration
redef Exfiltration::file_of_whitelisted_hostnames = "/opt/bro/share/bro/site/input/whitelists/hostnames.whitelist";
redef Exfiltration::file_of_whitelisted_subnets = "/opt/bro/share/bro/site/input/whitelists/subnets.whitelist";
# DNS zones to whitelist
# define here instead of using the input framework becuase we can't reliably load a table before bro_init completes
# and converting this to a regex requires bro_init.
redef Exfiltration::common_zones = {
	#".zombo.com", # Welcome to zombocom
}

# Flow
# single conn Tx bytes over which we want to alert on immediately
redef Exfiltration::flow_bytes_tx_to_notice= 20000000;
# destination hosts to record if over this many bytes
redef Exfiltration::flow_bytes_tx_to_log_and_track= 1000000;
# number of large uploads per IP before an email is generated for that IP
redef Exfiltration::count_of_tracked_flows_to_notice = 13;
# how long to suppress re-notices
redef Exfiltration::flow_suppression_interval = 480mins;
# flow producer consumer ratio floor
redef Exfiltration::min_flow_producer_consumer_ratio = 0.4;

# DNS
redef Exfiltration::query_interval = 1min;
redef Exfiltration::queries_per_query_interval = 800.0;
redef Exfiltration::query_length_sum_per_interval = 10000.0;
redef Exfiltration::txt_answer_types_per_interval = 5.0;
redef Exfiltration::null_answer_types_per_interval = 1.0;
redef Exfiltration::frequent_queriers = {
	# A cool host
	192.168.0.1/32,
	# A cool net
	192.168.1.0/24,
	};


# ICMP
redef Exfiltration::icmp_interval = 1min;
redef Exfiltration::icmp_per_query_interval = 60.0;
redef Exfiltration::frequent_icmp_senders = {
	# A cool host
	192.168.0.1/32,
	# A cool net
	192.168.1.0/24,
};

# Notices

# Use notice_ext for emailed alert types
redef Notice::ext_emailed_types = {
	Exfiltration::Large_Flow,
	Exfiltration::DNS_Excessive_Query_Velocity,
	Exfiltration::DNS_Excessive_Query_Length,
	Exfiltration::DNS_too_many_TXT_Answers,
	Exfiltration::DNS_too_many_NULL_Answers,
	Exfiltration::FTP_Upload,
	Exfiltration::ICMP_Velocity,
	Exfiltration::SSH,
	Bolo::MAC_Seen_In_DHCP_Request,
};

# Add links to Context for notices that email
module Notice;
hook notice(n: Notice::Info) &priority=5
	{
	if ( ACTION_EMAIL_EXT !in n$actions )
		return;

	# I'm not recovering gracefully from the when statements because I want
	# the notice framework to detect that something has exceeded the maximum
	# allowed email delay and tell the user.
	local uid = unique_id("");

	# We have to store references to the notices here because the when statement
	# clones the frame which doesn't give us access to modify values outside
	# of it's execution scope. (we get a clone of the notice instead of a
	# reference to the original notice)
	tmp_notice_storage[uid] = n;

	local output = "";
	if ( n?$uid && n?$src && n?$dst)
		{
		# Brownian
		add n$email_delay_tokens["brownian-link"];
		output = string_cat("https://brownian.example.com/?time=1h&query=uid%3A%22", n$uid, "%22");
		tmp_notice_storage[uid]$email_body_sections[|tmp_notice_storage[uid]$email_body_sections|] = output;
		delete tmp_notice_storage[uid]$email_delay_tokens["brownian-link"];

		# Snorby
		add n$email_delay_tokens["snorby-link"];
		output = string_cat(
			"https://snorby.example.com/results?match_all=false&search=%7B%220%22%3A%7B%22column%22%3A%22source_ip%22%2C%22operator%22%3A%22is%22%2C%22value%22%3A%22",
			cat(n$src),
			"%22%2C%22enabled%22%3Atrue%7D%2C%221%22%3A%7B%22column%22%3A%22destination_ip%22%2C%22operator%22%3A%22is%22%2C%22value%22%3A%22",
			cat(n$dst),
			"%22%2C%22enabled%22%3Atrue%7D%7D");
		tmp_notice_storage[uid]$email_body_sections[|tmp_notice_storage[uid]$email_body_sections|] = output;
		delete tmp_notice_storage[uid]$email_delay_tokens["snorby-link"];

		# Stenographer
		add n$email_delay_tokens["stenographer-link"];
		local rfc3339_time = Human::time_to_rfc3339(n$ts);
		output = string_cat(
			"* Stenographer: {{sudo stenoread 'host ",
			cat(n$src),
			" and host ",
			cat(n$dst),
			" and before ",
			rfc3339_time,
			"' -w /nsm/tmp/",
			cat(n$uid),
			".pcap}}\n");
		tmp_notice_storage[uid]$email_body_sections[|tmp_notice_storage[uid]$email_body_sections|] = output;
		delete tmp_notice_storage[uid]$email_delay_tokens["stenographer-link"];
		}
	else if ( n?$src )
		{
		add n$email_delay_tokens["brownian-link"];
		output = string_cat("* [Brownian|https://brownian.example.com/?time=1h&query=id.orig_h%3A%22", cat(n$src), "%22]");
		tmp_notice_storage[uid]$email_body_sections[|tmp_notice_storage[uid]$email_body_sections|] = output;
		delete tmp_notice_storage[uid]$email_delay_tokens["brownian-link"];

		add n$email_delay_tokens["snorby-link"];
		output = string_cat(
			"* [Snorby|https://snorby.example.com/results?match_all=false&search=%7B%220%22%3A%7B%22column%22%3A%22source_ip%22%2C%22operator%22%3A%22is%22%2C%22value%22%3A%22",
			cat(n$src),
			"%22%2C%22enabled%22%3Atrue%7D%7D\n]");
		tmp_notice_storage[uid]$email_body_sections[|tmp_notice_storage[uid]$email_body_sections|] = output;
		delete tmp_notice_storage[uid]$email_delay_tokens["snorby-link"];
		}
	}
```