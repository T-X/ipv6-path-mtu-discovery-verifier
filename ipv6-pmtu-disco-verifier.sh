#!/bin/bash
# SPDX-FileCopyrightText: 2025 Linus Lüssing <linus.luessing@c0d3.blue>
# SPDX-License-Identifier: CC0-1.0

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
NSETCDIR="/tmp/$NS_NAME"
NSETCHOSTS="/etc/hosts"
NSETCRESOLVCONF="nameserver 2001:678:e68:f000::"

NSROUTER_NAME="${NS_NAME}-router"
NSCLIENT_NAME="${NS_NAME}-client"

NS_UNSHARE="bwrap --dev-bind / / --ro-bind $NSETCDIR /etc/ --ro-bind /etc/alternatives /etc/alternatives --ro-bind /etc/ssl/certs/ /etc/ssl/certs/"

NSROUTER="ip netns exec ${NSROUTER_NAME} ${NS_UNSHARE}"
NSCLIENT="ip netns exec ${NSCLIENT_NAME} ${NS_UNSHARE}"

ROUTER_WAN_BRIDGE="br0"

MTUS="1500 1492 1491 1490 1489 1488 1486 1480 1460 1440 1420 1400 1350 1280"
MAX_PROCS="8"
WAIT_RETRIES="1 5 15 60"

echo "########################################"
echo "### IPv6 Path MTU Discovery Verifier ###"
echo "########################################"
echo

usage() {
	echo "# Check if IPv6 websites/hosts correctly honour ICMPv6 Packet Too Big packets"
	echo "# and if these hosts reduce their packet size accordingly."
	echo "# "
	echo "# To test this this simulates a) asymmetric routes where b) only one"
	echo "# direction has a lower MTU (like a VPN tunnel would have)."
	echo "# It creates the following, virtual test topology via network namespaces"
	echo "# for each configured test MTU:"
	echo "#"
	echo '#   ~~~~~~~     /----------------------------------------------------------\'
	echo '# ~ Internet ~  |This    ```````````````````````    `````````````````````` |'
	echo '#    ~~~~       |host    `ns:vrtr   <veth-tx>-------->><veth-rx>  ns:vcli` |'
	echo '#     ||        |        `         ^           `    `           v        ` |'
	echo '# { Local  }=======[br0]==<veth-wan>           `    `           <lo>     ` |'
	echo '#   Router      |        `         ^           `    `           v        ` |'
	echo '#               |        `          <veth-rx><<========<veth-tx>         ` |'
	echo '#               |        ```````````````````````    `````````````````````` |'
	echo '#               \----------------------------------------------------------/'
	echo "#"
	echo "# 1) Packets from the virtual client to the internet host"
	echo "#    (vcli: [lo => veth-tx] =>"
	echo "#     vrtr: [veth-rx => veth-wan] => br0 =>"
	echo "#     Local Router => Internet => Website)"
	echo "#    will do normal, full MTU roaming."
	echo "# 2) But: Packets from the internet host to the virtual client"
	echo "#    (Website => Internet => Local Router =>"
	echo "#     vrtr: [ veth-wan => veth-tx ] ->"
	echo "#     vcli: [ veth-rx => lo ])"
	echo "#   will have a **reduced MTU** (note: ->/- vs. =>/=) to e.g. simulate"
	echo "#   a tunnel, like a VPN or PPPoE."
	echo
	echo "# Test output:"
	echo "# * TCP-S+A column: basic check via nmap, does a TCP-SYN packet get a TCP-SYN-ACK reply?"
	echo "# * 1280-1500 columns: HTTP GET via wget from vcli, with reduced MTU in RX direction"
	echo "#   * (✔/✗): same, but with the TCP-MSS mangled to the low MTU via ip6tables on vcli:veth-tx"
	echo "#     => NOTE: When this check works, but without the TCP-MSS mangling it doesn't then this"
	echo "#              is a very strong indicator that the ICMPv6 Packet Too Big packets did not"
	echo "#              make it to the target website!"
	echo

	echo -e "Usage: $0"
	echo -e "\t[-b <br-iface>]            bridge interface with uplink+radvd (def.: br0)"
	echo -e "\t[-u <URLS-FILE|->]         file with URLs to check (def.: misc. ~60 URLs)"
	echo -e "\t[-m \"<MTU> <MTU> ...\"]     MTUs to test, between 1280 and 1500 (def.: misc. 14)"
	echo -e "\t[-j <num-parallel>]        number of parallel jobs (def.: ${MAX_PROCS})"
	echo -e "\t[-w \"<sec> <sec> ...\"]     wait seconds before retry (def.: \"${WAIT_RETRIES}\")"
	echo -e "\t[-r <RESOLV-CONF-FILE>]    resolv.conf with IPv6 nameserver (def.: ffmuc.net nameserver)"
	echo -e "\t[-H <HOSTS-FILE>]          an \"/etc/\"hosts file (def.: from setup host)"
	echo -e "\t[-c setup|run|teardown]    (def.: setup+run+teardown)"
	echo -e "\t[-h]                       this help + usage page"
}

while getopts "b:c:j:u:m:r:H:h" o; do
  case "${o}" in
    b)
	ROUTER_WAN_BRIDGE="${OPTARG}"
	;;
    c)
	CMD="${OPTARG}"
	case "${CMD}" in
	  setup|run|teardown)
		;;
	  *)
		echo "Error: Unknown command \"$CMD\"" >&2
		exit 1
		;;
	esac
	;;
    j)
	MAX_PROCS="${OPTARG}"
	case "${MAX_PROCS}" in
	  [1-9]|[1-9][0-9])
		;;
	  *)
		echo "Error: invalid value \"${MAX_PROCS}\" for -j, choose 1-99" >&2
		exit 1
		;;
	esac
	;;
    r)
	if [ ! -f "${OPTARG}" ]; then
		echo "Error: resolv.conf file \"${OPTARG}\" does not exist" >&2
		exit 1
	fi
	NSETCRESOLVCONF="$(cat "${OPTARG}")"
	if [ "$?" -ne 0 -o -z "$NSETCRESOLVCONF" ]; then
		echo "Error: resolv.conf file \"${OPTARG}\" could not be read or is empty" >&2
		exit 1
	fi
	;;
    u)
	if [ "${OPTARG}" = "-" ]; then
		URLS="$(cat)"
	else
		if [ ! -f "${OPTARG}" ]; then
			echo "Error: URLs file \"${OPTARG}\" does not exist" >&2
			exit 1
		fi
		URLS="$(cat "${OPTARG}")"
	fi
	;;
    m)
	if ! echo "${OPTARG}" | grep -q "^[0-9 ]*$"; then
		echo "Error: Invalid format for MTUs in \"${OPTARG}\"" >&2
		exit 1
	fi
	for mtu in ${OPTARG}; do
		if [ "$mtu" -lt 1280 -o "$mtu" -gt 1500 ]; then
			echo "Error: MTUs in \"${OPTARG}\" out-of-range, must be bet. 1280 and 1500" >&2
			exit 1
		fi
	done
	MTUS="${OPTARG}"
	;;
    H)
	if [ ! -f "${OPTARG}" ]; then
		echo "Error: hosts file \"${OPTARG}\" does not exist" >&2
		exit 1
	fi
	NSETCHOSTS="${OPTARG}"
	;;
    h)
	usage
	exit 0
	;;
    *)
	echo "Error: Unknown argument \"-${o}\"" >&2
	usage >&2
	exit 1
	;;
  esac
done
shift $((OPTIND-1))

check_commands() {
	local cmds="ip sed grep stdbuf wget ip6tables flock xargs nmap bwrap"

	for cmd in $cmds; do
		if command -v "$cmd" > /dev/null; then
			continue
		else
			echo "Error: Could not find command \"$cmd\"" >&2
			return 1
		fi
	done

	return 0
}

check_brif() {
	if [ -d "/sys/class/net/${ROUTER_WAN_BRIDGE}/bridge/" ]; then
		return 0
	else
		echo "Error: bridge interface \"${ROUTER_WAN_BRIDGE}\" does not exist" >&2
		return 1
	fi
}

check_root() {
	if [ "$(id -u)" -eq 0 ]; then
		return 0
	else
		echo "Error: not running as root user\n" >&2
		return 1
	fi
}

setup_etcdir() {
	if ! mkdir -p "$NSETCDIR"; then
		echo "Error: Could not create namespace etc directory \"$NSETCDIR\"" >&2
		exit 1
	fi

	if ! cp "$NSETCHOSTS" "$NSETCDIR/hosts"; then
		echo "Error: Could not copy hosts file \"$NSETCHOSTS\" to \"$NSETCDIR/hosts\"" >&2
		exit 1
	fi

	if ! echo "$NSETCRESOLVCONF" > "$NSETCDIR/resolv.conf"; then
		echo "Error: Could not create resolv.conf file at \"$NSETCDIR/resolv.conf\"" >&2
		exit 1
	fi

	mkdir -p "$NSETCDIR/alternatives"
	mkdir -p "$NSETCDIR/ssl/certs"
	[ -f "/etc/nsswitch.conf" ] && cp /etc/nsswitch.conf "$NSETCDIR/nsswitch.conf"
	[ -f "/etc/ssl/openssl.cnf" ] && cp /etc/ssl/openssl.cnf "$NSETCDIR/ssl/openssl.cnf"

	cat <<EOF > "$NSETCDIR/passwd"
root:x:0:0:root:/root:/bin/bash
tcpdump:x:117:127::/nonexistent:/usr/sbin/nologin
EOF
}

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
	local mssfixed="$2"
	local ehb="00"

	teardown_router "$mtu" "$mssfixed" 2> /dev/null

	[ -n "$mssfixed" ] && ehb="01"

	ip netns add "${NSROUTER_NAME}-${mtu}${mssfixed}"

	ip link add vmtu-test-${mtu}${mssfixed} type veth peer name veth-router-wan

	ip link set dev vmtu-test-${mtu}${mssfixed} master "${ROUTER_WAN_BRIDGE}" address 02:00:00:00:00:00 up
	ip link set dev veth-router-wan netns "${NSROUTER_NAME}-${mtu}${mssfixed}" address 02:00:${ehb}:$(dec22hex "$mtu"):01 up

	$(nsrouter "${mtu}${mssfixed}") ip6tables -t nat -A POSTROUTING -o veth-router-wan -j MASQUERADE
	$(nsrouter "${mtu}${mssfixed}") sh -c "echo 2 > /proc/sys/net/ipv6/conf/veth-router-wan/accept_ra"
	$(nsrouter "${mtu}${mssfixed}") sh -c "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding"
}

setup_client() {
	local mtu="$1"
	local mssfixed="$2"
	local ihb=""

	teardown_client "$mtu" "$mssfixed" 2> /dev/null

	[ -n "$mssfixed" ] && ihb="1:"

	ip netns add "${NSCLIENT_NAME}-${mtu}${mssfixed}"

	ip link add veth-router-tx type veth peer name veth-client-rx
	ip link add veth-router-rx type veth peer name veth-client-tx

	ip link set dev veth-router-rx netns "${NSROUTER_NAME}-${mtu}${mssfixed}" address 02:00:00:00:01:01 up
	ip link set dev veth-client-tx netns "${NSCLIENT_NAME}-${mtu}${mssfixed}" address 02:00:00:00:01:02 up
	ip link set dev veth-router-tx netns "${NSROUTER_NAME}-${mtu}${mssfixed}" address 02:00:00:00:02:01 mtu $mtu up
	ip link set dev veth-client-rx netns "${NSCLIENT_NAME}-${mtu}${mssfixed}" address 02:00:00:00:02:02 mtu $mtu up

	$(nsrouter "${mtu}${mssfixed}") ip -6 route add fd00::${ihb}$(dec2hex "$mtu"):2/128 via fe80::ff:fe00:202 dev veth-router-tx

	$(nsclient "${mtu}${mssfixed}") ip -6 link set up dev lo
	$(nsclient "${mtu}${mssfixed}") ip -6 address add fd00::${ihb}$(dec2hex "$mtu"):2/128 dev lo
	$(nsclient "${mtu}${mssfixed}") ip -6 route add default via fe80::ff:fe00:101 dev veth-client-tx

	[ -n "$mssfixed" ] && \
		$(nsclient "${mtu}${mssfixed}") ip6tables -I OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $(($mtu - 60))
}

setup() {
	local mtu

	echo "# Starting setup..."

	setup_etcdir

	for mtu in $MTUS; do
		setup_router "$mtu"
		setup_router "$mtu" "m"
		setup_client "$mtu"
		setup_client "$mtu" "m"
	done
}

teardown_client() {
	local mtu="$1"
	local mssfixed="$2"
	local ihb=""

	[ -n "$mssfixed" ] && ihb="1:" && \
		$(nsclient "${mtu}${mssfixed}") ip6tables -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $(($mtu - 60))

	$(nsclient "${mtu}${mssfixed}") ip -6 route del default via fe80::ff:fe00:101 dev veth-client-tx
	$(nsclient "${mtu}${mssfixed}") ip -6 address del fd00::${ihb}$(dec2hex "$mtu"):2/128 dev lo
	$(nsclient "${mtu}${mssfixed}") ip -6 link set down dev lo

	$(nsrouter "${mtu}${mssfixed}") ip -6 route del fd00::${ihb}$(dec2hex "$mtu"):2/128 via fe80::ff:fe00:202 dev veth-router-tx

	$(nsclient "${mtu}${mssfixed}") ip link del veth-client-tx
	$(nsclient "${mtu}${mssfixed}") ip link del veth-client-rx

	ip netns del "${NSCLIENT_NAME}-${mtu}${mssfixed}"
}

teardown_router() {
	local mtu="$1"
	local mssfixed="$2"

	$(nsrouter "${mtu}${mssfixed}") echo 0 > /proc/sys/net/ipv6/conf/all/forwarding
	$(nsrouter "${mtu}${mssfixed}") ip6tables -t nat -D POSTROUTING -o veth-router-wan -j MASQUERADE

	$(nsrouter "${mtu}${mssfixed}") ip link del veth-router-wan

	ip netns del "${NSROUTER_NAME}-${mtu}${mssfixed}"
}

teardown_etcdir() {
	rm -r "$NSETCDIR"
}

teardown() {
	local netns
	local host
	local mtu
	local mssfixed

	echo "# Starting teardown..."

	sudo ip netns list | sed -n "s/^${NS_NAME}-\([a-z]*\)-\([0-9]*\)\([m]*\) .*/\1 \2 \3/p" | \
	while read netns; do
		host="${netns%% *}"; netns="${netns#$host }"
		mtu="${netns%% *}";  netns="${netns#$mtu}"
		mssfixed="${netns# }"

		teardown_${host} "${mtu}" "$mssfixed" 2> /dev/null
	done

	teardown_etcdir 2> /dev/null
}

print_default() {
	printf "%-${2}s" "$1"
}

print_green() {
	printf "\033[32m%-${2}s\033[0m" "$1"
}

print_red() {
	printf "\033[31m%-${2}s\033[0m" "$1"
}

test_url_call() {
	local url="$1"
	local mtu="$2"
	local sleeplen="$3"
	local bytes
	local ret

	sleep "$sleeplen"

	# Set non-wget user agent to have sites like akamai.com and
	# fcc.gov to respond to us...
	# But with a real Firefox agent then Facebook wants us to set
	# --header="Sec-Fetch-Site: none"...
	bytes="$($(nsclient "$mtu") timeout 60 wget --header="Sec-Fetch-Site: none" --user-agent="$agent" -q -6 "$url" --timeout=10 -O - | wc -c)"
	ret="$?"

	if [ "$ret" -eq 0 -a "$bytes" -gt 1500 ]; then
		return 0
	else
		return 1
	fi
}

url2domain() {
	echo "$@" | sed 's#^https://\([^/]*\).*#\1#'
}

test_run_print_retried() {
	local url="$1"
	local mtu="$2"
	local ivals="$3"
	local call_func="$4"
	local ok_func="$5"
	local err_func="$6"
	local i
	local ret

	for i in $ivals; do
		eval ${call_func}
		ret="$?"

		if [ "$ret" -eq 0 ]; then break; fi
	done

	if [ "$ret" -eq 0 ]; then
		eval ${ok_func}
	else
		eval ${err_func}
	fi
}

test_url_run() {
	local url="$1"
	local mtu
	local ret
	local i
	local agent="Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"

	printf "%-40s" "$url:"

	test_run_print_retried "$url" "$mtu" "1 5 15 60" \
		'nmap -6 -oG - -PS -p 443 "$(url2domain "$url")" | grep -q "Ports: 443/open/tcp//https///"' \
		'print_green "✔" "10"' \
		'print_red "✗" "10"'

	for mtu in $MTUS; do
		test_run_print_retried "$url" "$mtu" "1 5 15 60" \
			'test_url_call "$url" "$mtu" "$i"' \
			'print_green "✔" "3"' \
			'print_red "✗" "3"'

		mtu="${mtu}m"
		test_run_print_retried "$url" "$mtu" "1 5 15 60" \
			'test_url_call "$url" "$mtu" "$i"' \
			'print_green "(✔)" "6"' \
			'print_red "(✗)" "6"'
	done
	echo
}

test_url() {
	local output

	output="$(test_url_run "$@")"

	# print output under lock, to avoid mangling lines
	# with parallel calls
	exec 100>/var/tmp/testlock.lock || exit 1
	flock 100 || exit 1

	stdbuf -oL echo "$output"
}

run() {
	local mtu
	local url

	echo "# Starting run..."
	echo "# Settings:"
	echo "# * parallel: ${MAX_PROCS}"
	echo "# * wait seconds on (re)try: ${WAIT_RETRIES}"
	echo

	print_default "URL" "40"
	print_default "TCP-S+A" "8"
	for mtu in $MTUS; do
		printf "%-5s" "$mtu"
	done
	echo

	export MTUS
	export NSCLIENT_NAME
	export NSETCDIR
	export NS_UNSHARE
	export -f nsclient
	export -f print_green
	export -f print_red
	export -f url2domain
	export -f test_url_call
	export -f test_run_print_retried
	export -f test_url_run
	export -f test_url

	echo "$URLS" | xargs -I {} --max-args=1 --max-procs=${MAX_PROCS} bash -c 'test_url "$@"' _ {}
}

check_commands || exit 1
check_brif || exit 2
check_root || exit 3

if [ -z "$CMD" ]; then
	trap 'teardown' EXIT
	trap 'exit 0' SIGINT

	setup
	run

	exit 0
fi

case "$CMD" in
setup)
  trap 'teardown' EXIT
  trap 'exit 0' SIGINT

  setup

  trap -
  ;;
teardown)
  teardown
  ;;
run)
  run
  ;;
*)
  echo "Unknown command"
  ;;
esac
