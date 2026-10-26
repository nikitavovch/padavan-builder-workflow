# Sourced by the workflow before build_firmware.sh (cwd: repo root)

# nilabsent config builds LuaJIT, whose host tools need 32-bit headers
apt-get update -qq && apt-get install -y -qq gcc-multilib >/dev/null

# Safer factory defaults: survive a reset-button NVRAM wipe
d=padavan-ng/trunk/user/shared/defaults.c
sed -i \
  -e 's/{ "telnetd", "1" }/{ "telnetd", "0" }/' \
  -e 's/{ "sshd_enable", "0" }/{ "sshd_enable", "1" }/' \
  -e 's/{ "upnp_enable_x", "1" }/{ "upnp_enable_x", "0" }/' \
  -e 's/{ "wl_channel", "0" }/{ "wl_channel", "36" }/' \
  -e 's/{ "rt_channel", "0" }/{ "rt_channel", "11" }/' \
  -e 's/{ "http_access", "0" }/{ "http_access", "2" }/' \
  -e 's/{ "fw_dos_x", "0" }/{ "fw_dos_x", "1" }/' \
  -e 's/{ "fw_syn_cook", "0" }/{ "fw_syn_cook", "1" }/' \
  -e 's/{ "sfe_enable",  "0" }/{ "sfe_enable",  "2" }/' \
  -e 's/{ "lltd_enable", "1" }/{ "lltd_enable", "0" }/' \
  -e 's/{ "u2ec_enable", "1" }/{ "u2ec_enable", "0" }/' \
  -e 's/{ "lprd_enable", "1" }/{ "lprd_enable", "0" }/' \
  -e 's/{ "st_samba_mode", "1" }/{ "st_samba_mode", "4" }/' \
  "$d"

# SSH: keys only (authorized_keys lives in /etc/storage and survives NVRAM reset)
sed -i 's/{ "sshd_enable", "1" }/{ "sshd_enable", "2" }/' "$d"

# httpd CSRF: state-changing requests must come from the admin UI itself
h=padavan-ng/trunk/user/httpd/httpd.c
perl -0pi -e '
s/\*authorization, \*boundary;/*authorization, *boundary, *referer = NULL;/;
s/(\t\telse if \(strncasecmp\( cur, "Content-Length:", 15\) == 0\) \{)/\t\telse if (strncasecmp(cur, "Referer:", 8) == 0) {\n\t\t\treferer = cur + 8 + strspn(cur + 8, " \\t");\n\t\t\tcur = referer + strlen(referer) + 1;\n\t\t}\n$1/;
' "$h"
# Referer must be http(s)://<lan_ipaddr>[:port]/...
cat > /tmp/csrf_check.c <<'EOF'
	if (handler->need_auth && login_state != 1 &&
	    (method_id == HTTP_METHOD_POST || strstr(file, ".cgi") || strstr(file, "onsole"))) {
		const char *r = referer, *lan_ip = nvram_safe_get("lan_ipaddr");
		size_t n = strlen(lan_ip);
		int ref_ok = 0;

		if (r) {
			if (strncmp(r, "https://", 8) == 0)
				r += 8;
			else if (strncmp(r, "http://", 7) == 0)
				r += 7;
			else
				r = NULL;
		}
		if (r && n && strncmp(r, lan_ip, n) == 0 && (r[n] == '/' || r[n] == ':'))
			ref_ok = 1;
		if (!ref_ok) {
			if (method_id == HTTP_METHOD_POST)
				eat_post_data(conn_fp, clen);
			send_error( 403, "Forbidden", NULL, "Bad Referer.", conn_fp );
			return;
		}
	}
EOF
perl -0pi -e 'BEGIN { local $/; open(F, "/tmp/csrf_check.c") or die; $c = <F>; }
s/(\tlogin_state = http_login_check\(&conn_ip\);\n)/$1$c/;' "$h"
grep -c 'Bad Referer' "$h"

# HTTPS admin by default (falls back to HTTP until a cert exists in /etc/storage/https);
# TLS 1.2+ only, ECDHE + AEAD ciphers only
sed -i 's/{ "http_proto", "0" }/{ "http_proto", "1" }/' "$d"
perl -pi -e 's/^#define DEF_HTTPS_CIPH_LIST\t.*$/#define DEF_HTTPS_CIPH_LIST\t"ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS"/' \
  padavan-ng/trunk/user/shared/defaults.h
perl -pi -e 's/SSL_OP_NO_SSLv3 \|/SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |/' \
  padavan-ng/trunk/user/httpd/https.c
grep -n DEF_HTTPS_CIPH_LIST padavan-ng/trunk/user/shared/defaults.h
grep -n 'SSL_OP_NO_TLSv1_1' padavan-ng/trunk/user/httpd/https.c

# no ICMP redirects from the router
perl -pi -e 's/^(\tset_interface_conf_int\("ipv4", "default", "rp_filter", 2\);.*)$/$1\n\tset_interface_conf_int("ipv4", "all", "send_redirects", 0);\n\tset_interface_conf_int("ipv4", "default", "send_redirects", 0);/' \
  padavan-ng/trunk/user/rc/init.c
grep -c send_redirects padavan-ng/trunk/user/rc/init.c

# MT7612 beamforming is compiled out by default; wl_txbf is a no-op without it
sed -i 's/# CONFIG_MT76X2_AP_TXBF_SUPPORT is not set/CONFIG_MT76X2_AP_TXBF_SUPPORT=y/' \
  padavan-ng/trunk/configs/boards/XIAOMI/MI-MINI/kernel-3.4.x.config
grep -n MT76X2_AP_TXBF padavan-ng/trunk/configs/boards/XIAOMI/MI-MINI/kernel-3.4.x.config
# dnsmasq: block DNS rebinding (sites resolving to LAN IPs to reach the admin UI);
# allow Beeline/2day domains, which may legitimately answer with private addresses
sed -i 's|"bogus-priv\\n"|"bogus-priv\\n"\n\t\t    "domain-needed\\n"\n\t\t    "stop-dns-rebind\\n"\n\t\t    "rebind-localhost-ok\\n"\n\t\t    "rebind-domain-ok=/beeline.kz/2day.kz/\\n"|' \
  padavan-ng/trunk/user/rc/services_ex.c
grep -n -A5 '"bogus-priv' padavan-ng/trunk/user/rc/services_ex.c

# Kazakhstan is UTC+5 since 2024-03-01
sed -i 's/\(#define DEF_TIMEZONE[[:space:]]*\)"GMT0"/\1"UCT-5"/' padavan-ng/trunk/user/shared/defaults.h
grep -nE '"(telnetd|sshd_enable|upnp_enable_x|wl_channel|rt_channel|http_access|fw_dos_x|fw_syn_cook|sfe_enable)"' "$d"
grep -n DEF_TIMEZONE padavan-ng/trunk/user/shared/defaults.h
