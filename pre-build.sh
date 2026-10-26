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
  "$d"
grep -nE '"(telnetd|sshd_enable|upnp_enable_x|wl_channel|rt_channel)"' "$d"
