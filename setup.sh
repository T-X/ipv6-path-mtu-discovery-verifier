#!/bin/sh

URLS="https://www.heise.de/
https://netzpolitik.org/
https://google.com/
https://play.google.com/
https://cloud.google.com/
https://openstreetmap.org/
https://youtube.com/
https://ccc.de/
https://media.ccc.de/
https://torproject.org/
https://mozilla.org/
https://signal.org/
https://matrix.org/
https://open-mesh.org/
https://debian.org/
https://ubuntu.com/
https://facebook.com/
https://spotify.com/
https://accounts.spotify.com/
https://jamendo.com/
https://iphh.net/
https://de-cix.net/
https://mit.edu/
https://microsoft.com/
https://code.visualstudio.com/
https://login.microsoftonline.com/
https://learn.microsoft.com/
https://techcommunity.microsoft.com/
https://apps.microsoft.com/
https://xbox.com/
https://office.com/
https://microsoft365.com/
https://bing.com/
https://azure.microsoft.com/
https://docs.microsoft.com/
https://launcher.mojang.com/download/MinecraftInstaller.exe
https://js.monitor.azure.com/scripts/c/ms.analytics-web-3.gbl.min.js
https://cloudflare.com/
https://kernel.org/
https://www.linuxfoundation.org/
https://wikipedia.org/
https://akamai.com/
https://www.nintendo.com/
https://instagram.com/
https://aws.amazon.com/
https://yahoo.com/
https://linked.in/
https://netflix.com/
https://weather.com/
https://t.me/
https://ripe.net/
https://afrinic.net/
https://apnic.net/
https://freifunk.net/
https://ffmuc.net/
https://hamburg.freifunk.net/
https://luebeck.freifunk.net/
https://ietf.org/
https://iana.org/
https://fcc.gov/
https://europa.eu/"

NS_NAME="ipv6-mtu-testnet"

NSROUTER_NAME="${NS_NAME}-router"
NSCLIENT_NAME="${NS_NAME}-client"

etcdir="/tmp/$NS_NAME"
mkdir -p "$etcdir/alternatives"
mkdir -p "$etcdir/ssl/certs"
cp /etc/nsswitch.conf "$etcdir/nsswitch.conf"
cp /etc/ssl/openssl.cnf "$etcdir/ssl/openssl.cnf"

echo "nameserver 2001:678:e68:f000::" > "$etcdir/resolv.conf"
#echo "nameserver 2001:678:ed0:f000::" > "$etcdir/resolv.conf"
#echo "nameserver 2a01:4f8:251:554::2" > "$etcdir/resolv.conf"

cat <<EOF > "$etcdir/hosts"
2620:1ec:29:1::45 code.visualstudio.com
EOF

cat <<EOF > "$etcdir/passwd"
root:x:0:0:root:/root:/bin/bash
tcpdump:x:117:127::/nonexistent:/usr/sbin/nologin
EOF

#echo "root:x:0:0:root:/root:/bin/bash" > "$etcdir/passwd"


#NSROUTER_UNSHARE="unshare --mount-proc -Urm"
#NSROUTER_UNSHARE="unshare --mount-proc -Urm bash -c \"mount --bind $tmpdir /etc; \$0\""
NS_UNSHARE="bwrap --dev-bind / / --ro-bind $etcdir /etc/ --ro-bind /etc/alternatives /etc/alternatives --ro-bind /etc/ssl/certs/ /etc/ssl/certs/"

NSROUTER="ip netns exec ${NSROUTER_NAME} ${NS_UNSHARE}"
NSCLIENT="ip netns exec ${NSCLIENT_NAME} ${NS_UNSHARE}"

ROUTER_WAN_BRIDGE="br0"
#MTU_CAP="1480"
MTUS="1500 1492 1480 1350 1280"
#MTU_CAP="1490"
#MTU_CAP="1492"
#MTU_CAP="1500"

#prv_mnt() {
#	unshare --mount-proc -Urm bash <<END
#	mount --bind $tmpdir /etc
#	lmutil    # REPLACE WITH YOUR COMMAND
#END
#}

dec2hex() {
	printf "%x\n" "$1"
}

dec22hex() {
	printf "%02x:%02x\n" "$(($1/256))" "$(($1%256))"
}

nsclient() {
	local mtu="$1"

	echo ip netns exec ${NSCLIENT_NAME}-$mtu ${NS_UNSHARE}
}

nsrouter() {
	local mtu="$1"

	echo ip netns exec ${NSROUTER_NAME}-$mtu ${NS_UNSHARE}
}

setup_router() {
	local mtu="$1"

	ip netns add "${NSROUTER_NAME}-$mtu"

	ip link add vmtu-test-$mtu type veth peer name veth-router-wan

	ip link set dev vmtu-test-$mtu master "${ROUTER_WAN_BRIDGE}" address 02:00:00:00:00:00 up
	ip link set dev veth-router-wan netns "${NSROUTER_NAME}-$mtu" address 02:00:00:$(dec22hex "$mtu"):01 up

	$(nsrouter "$mtu") ip6tables -t nat -A POSTROUTING -o veth-router-wan -j MASQUERADE
	$(nsrouter "$mtu") sh -c "echo 2 > /proc/sys/net/ipv6/conf/veth-router-wan/accept_ra"
	$(nsrouter "$mtu") sh -c "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding"
}

setup_client() {
	local mtu="$1"

	ip netns add "${NSCLIENT_NAME}-$mtu"

	ip link add veth-router-tx type veth peer name veth-client-rx
	ip link add veth-router-rx type veth peer name veth-client-tx

	ip link set dev veth-router-rx netns "${NSROUTER_NAME}-$mtu" address 02:00:00:00:01:01 up
	ip link set dev veth-client-tx netns "${NSCLIENT_NAME}-$mtu" address 02:00:00:00:01:02 up
	ip link set dev veth-router-tx netns "${NSROUTER_NAME}-$mtu" address 02:00:00:00:02:01 mtu $mtu up
	ip link set dev veth-client-rx netns "${NSCLIENT_NAME}-$mtu" address 02:00:00:00:02:02 mtu $mtu up
#	ip link set dev vrtr-tx netns "${NSROUTER_NAME}" address 02:00:00:00:02:01 up
#	ip link set dev veth-client-rx netns "${NSCLIENT_NAME}" address 02:00:00:00:02:02 up

	$(nsrouter "$mtu") ip -6 route add fd00::$(dec2hex "$mtu"):2/128 via fe80::ff:fe00:202 dev veth-router-tx

	$(nsclient "$mtu") ip -6 link set up dev lo
	$(nsclient "$mtu") ip -6 address add fd00::$(dec2hex "$mtu"):2/128 dev lo
	$(nsclient "$mtu") ip -6 route add default via fe80::ff:fe00:101 dev veth-client-tx
}

setup() {
	local mtu

	for mtu in $MTUS; do
		setup_router "$mtu"
		setup_client "$mtu"
	done
}

teardown_client() {
	local mtu="$1"

	$(nsclient "$mtu") ip -6 route del default via fe80::ff:fe00:101 dev veth-client-tx
	$(nsclient "$mtu") ip -6 address del fd00::$(dec2hex "$mtu"):2/128 dev lo
	$(nsclient "$mtu") ip -6 link set down dev lo

	$(nsrouter "$mtu") ip -6 route del fd00::$(dec2hex "$mtu"):2/128 via fe80::ff:fe00:202 dev veth-router-tx

	$(nsclient "$mtu") ip link del veth-client-tx
	$(nsclient "$mtu") ip link del veth-client-rx

	ip netns del "${NSCLIENT_NAME}-$mtu"
}

teardown_router() {
	$(nsrouter "$mtu") echo 0 > /proc/sys/net/ipv6/conf/all/forwarding
	$(nsrouter "$mtu") ip6tables -t nat -D POSTROUTING -o veth-router-wan -j MASQUERADE

	$(nsrouter "$mtu") ip link del veth-router-wan

	ip netns del "${NSROUTER_NAME}-$mtu"
}

teardown() {
	local mtu

	for mtu in $MTUS; do
		teardown_client "$mtu"
		teardown_router "$mtu"
	done

}

test() {
	local mtu

	echo "### IPv6 MTU Path Discovery Tester ###"
	echo

#	printf "%-40s%-5s%-5s%-5s%-5s%-5s%-5s\n" "URL" "1500" "1492" "1480" "1350" "1280"
	printf "%-40s" "URL"
	for mtu in $MTUS; do
		printf "%-5s" "$mtu"
	done
	echo

	for url in $URLS; do
#		echo "-- $url";
		printf "%-40s" "$url:"

		for mtu in $MTUS; do
			sleep 0.5

			bytes="$($(nsclient "$mtu") wget -q -6 "$url" --timeout=10 -O - | wc -c)"
			ret="$?"
#		echo "~~ ret: $ret, bytes: $bytes"
#

			if [ "$ret" -eq 0 -a "$bytes" -gt 1500 ]; then
				printf "\033[32m%-7s\033[0m" "✔"
			else
				printf "\033[31m%-7s\033[0m" "✗"
			fi
		done
		echo
	done
}

case "$1" in
setup)
  setup
  ;;
teardown)
  teardown
  ;;
test)
  test
  ;;
*)
  echo "Unknown command"
  ;;
esac
