# Sourced by the workflow before build_firmware.sh (cwd: repo root).
# The workflow runs it as `. pre-build.sh || :`, so failures must `exit 1` explicitly.

fail() { echo "PRE-BUILD FAIL: $*" >&2; exit 1; }
# want <file> <fixed string> [expected count]
want() {
	n=$(grep -cF -- "$2" "$1")
	[ "$n" -eq "${3:-1}" ] || fail "$1: expected ${3:-1}x '$2', got $n"
}

t=padavan-ng/trunk
d=$t/user/shared/defaults.c
dh=$t/user/shared/defaults.h

# nilabsent config builds LuaJIT, whose host tools need 32-bit headers
apt-get update -qq && apt-get install -y -qq gcc-multilib >/dev/null || fail "gcc-multilib"

# --- Factory defaults (apply after an NVRAM reset) ---
sed -i \
  -e 's/{ "telnetd", "1" }/{ "telnetd", "0" }/' \
  -e 's/{ "sshd_enable", "0" }/{ "sshd_enable", "2" }/' \
  -e 's/{ "upnp_enable_x", "1" }/{ "upnp_enable_x", "0" }/' \
  -e 's/{ "wl_channel", "0" }/{ "wl_channel", "36" }/' \
  -e 's/{ "rt_channel", "0" }/{ "rt_channel", "11" }/' \
  -e 's/{ "http_proto", "0" }/{ "http_proto", "1" }/' \
  -e 's/{ "http_access", "0" }/{ "http_access", "2" }/' \
  -e 's/{ "fw_dos_x", "0" }/{ "fw_dos_x", "1" }/' \
  -e 's/{ "fw_syn_cook", "0" }/{ "fw_syn_cook", "1" }/' \
  -e 's/{ "sfe_enable",  "0" }/{ "sfe_enable",  "2" }/' \
  -e 's/{ "lltd_enable", "1" }/{ "lltd_enable", "0" }/' \
  -e 's/{ "u2ec_enable", "1" }/{ "u2ec_enable", "0" }/' \
  -e 's/{ "lprd_enable", "1" }/{ "lprd_enable", "0" }/' \
  -e 's/{ "st_samba_mode", "1" }/{ "st_samba_mode", "4" }/' \
  "$d"
want "$d" '{ "telnetd", "0" }'
want "$d" '{ "sshd_enable", "2" }'      # keys only; authorized_keys lives in /etc/storage
want "$d" '{ "upnp_enable_x", "0" }'
want "$d" '{ "wl_channel", "36" }'
want "$d" '{ "rt_channel", "11" }'
want "$d" '{ "http_proto", "1" }'       # falls back to HTTP until a cert exists
want "$d" '{ "http_access", "2" }'
want "$d" '{ "fw_dos_x", "1" }'
want "$d" '{ "fw_syn_cook", "1" }'
want "$d" '{ "sfe_enable",  "2" }'
want "$d" '{ "lltd_enable", "0" }'
want "$d" '{ "u2ec_enable", "0" }'
want "$d" '{ "lprd_enable", "0" }'
want "$d" '{ "st_samba_mode", "4" }'

# Kazakhstan is UTC+5 since 2024-03-01
sed -i 's/\(#define DEF_TIMEZONE[[:space:]]*\)"GMT0"/\1"UCT-5"/' "$dh"
want "$dh" '"UCT-5"'

# HTTPS: ECDHE + AEAD only (TLS 1.3 suites are unaffected)
perl -pi -e 's/^#define DEF_HTTPS_CIPH_LIST\t.*$/#define DEF_HTTPS_CIPH_LIST\t"ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS"/' "$dh"
want "$dh" '"ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS"' 2

# --- httpd ---
# TLS 1.2+ only
s=$t/user/httpd/https.c
perl -pi -e 's/SSL_OP_NO_SSLv3 \|/SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |/' "$s"
want "$s" 'SSL_OP_NO_TLSv1_1'

# CSRF: state-changing requests (POST, *.cgi) and nvram-backed *.js must carry a
# Referer whose host matches the request Host. Every request is still Basic-auth
# checked, so a foreign origin (incl. DNS rebinding) cannot pass.
h=$t/user/httpd/httpd.c
perl -0pi -e '
s/\*authorization, \*boundary;/*authorization, *boundary, *referer = NULL, *host = NULL;/;
s/(\t\telse if \(strncasecmp\( cur, "Content-Length:", 15\) == 0\) \{)/\t\telse if (strncasecmp(cur, "Referer:", 8) == 0) {\n\t\t\treferer = cur + 8 + strspn(cur + 8, " \\t");\n\t\t\treferer[strcspn(referer, "\\r\\n")] = 0;\n\t\t\tcur = referer + strlen(referer) + 1;\n\t\t}\n\t\telse if (strncasecmp(cur, "Host:", 5) == 0) {\n\t\t\thost = cur + 5 + strspn(cur + 5, " \\t");\n\t\t\thost[strcspn(host, "\\r\\n")] = 0;\n\t\t\tcur = host + strlen(host) + 1;\n\t\t}\n$1/;
' "$h"
want "$h" '*referer = NULL, *host = NULL;'
want "$h" 'strncasecmp(cur, "Referer:", 8)'
want "$h" 'strncasecmp(cur, "Host:", 5)'
cat > /tmp/csrf_check.c <<'EOF'
	if (handler->need_auth && login_state != 1 &&
	    (method_id == HTTP_METHOD_POST || strstr(file, ".cgi") || strstr(file, ".js"))) {
		const char *r = referer;
		size_t n = host ? strlen(host) : 0;
		int ref_ok = 0;

		if (r) {
			if (strncmp(r, "https://", 8) == 0)
				r += 8;
			else if (strncmp(r, "http://", 7) == 0)
				r += 7;
			else
				r = NULL;
		}
		if (r && n && strncasecmp(r, host, n) == 0 && (r[n] == '/' || r[n] == 0))
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
want "$h" 'Bad Referer.'

# --- rc ---
# no ICMP redirects from the router
i=$t/user/rc/init.c
perl -pi -e 's/^(\tset_interface_conf_int\("ipv4", "default", "rp_filter", 2\);.*)$/$1\n\tset_interface_conf_int("ipv4", "all", "send_redirects", 0);\n\tset_interface_conf_int("ipv4", "default", "send_redirects", 0);/' "$i"
want "$i" '"send_redirects", 0);' 2

# dnsmasq: block DNS rebinding (external names resolving to LAN IPs);
# Beeline/2day domains may legitimately answer with private addresses
x=$t/user/rc/services_ex.c
sed -i 's|"bogus-priv\\n"|"bogus-priv\\n"\n\t\t    "domain-needed\\n"\n\t\t    "stop-dns-rebind\\n"\n\t\t    "rebind-localhost-ok\\n"\n\t\t    "rebind-domain-ok=/beeline.kz/2day.kz/\\n"|' "$x"
want "$x" '"stop-dns-rebind\n"'
want "$x" '"rebind-domain-ok=/beeline.kz/2day.kz/\n"'

echo "pre-build: all patches applied"
