#!/usr/bin/env python3
"""
wlan_test_suite.py  -  unified WLAN test runner (run from TM device)

Menu:
  1) Load driver on all DUTs        (Code A)
  2) Broadcast a command + collect  (Code B)
  3) TX traffic test  (DUT SoftAP -> clients)
  4) RX traffic test  (clients -> DUT SoftAP)
  5) Edit a dependency file + scp to devices
  0) Exit

Rules:
  - Per device path:  ASTRA -> /lib/firmware   VIM3 -> /build
  - IP entry:         X.X only (e.g. 1.4)  ->  mgmt 172.16.X.X
  - Data-plane IP:    from mgmt octet, 172.16.X.X -> 192.168.X.X
                      DUT SoftAP wlan1 fixed at 192.168.1.2
  - Blank bucket:     leave ASTRA blank -> run is all VIM3 (and vice versa)
  - RSSI MAC:         read live via `ifconfig` (no hardcoded MAC)
"""

import os
import re
import time
import subprocess
import random

ASTRA_PATH = "/lib/firmware"
VIM3_PATH  = "/build"

# ---- SoftAP DUT: fixed constant across all test cases ----
SOFTAP_XX   = "1.4"                          # DUT SoftAP, VIM3
SOFTAP_IP   = f"172.16.{SOFTAP_XX}"          # mgmt IP  = 172.16.1.4
SOFTAP_DATA = f"192.168.{SOFTAP_XX}"         # wlan1 IP = 192.168.1.4
SOFTAP_PATH = VIM3_PATH                      # /build

SSH_USER   = "root"
DEPS = ["dynamic_client.sh", "dynamic_server.sh", "assoc.sh", "RSSI.sh", "ping.sh",
        "dynamic_client_bd.sh", "dynamic_server_bd.sh"]

# Full menu names used in the Excel iteration title
TEST_NAMES = {
    "TX":   "TX traffic test  (DUT SoftAP -> clients)",
    "RX":   "RX traffic test  (clients -> DUT SoftAP)",
    "BD":   "Bidirectional traffic (DUT <-> clients)",
    "PING": "Ping test (DUT <-> clients)",
}

# Full lab device lists (last two octets) for "scp to all devices"
ALL_ASTRA = ["1.2", "1.3", "1.6", "1.7", "1.11", "1.12", "1.15", "1.16", "1.10", "1.13", "1.14", "1.17", "1.19"]
ALL_VIM3  = ["1.4", "1.5", "1.8", "1.9"]

# Sniffer (separate capture box)
SNIFFER_IP   = "10.45.142.12"
SNIFFER_PATH = "/root/43756E_Sniffer"
PCAP_DIR     = "/root/MC_Pcap"
TM_PCAP_DIR  = "/root/MultiClient/debug/MC_Pcap"   # pull pcaps here on TM

# ======================================================================
# Embedded dependency templates (written locally if file is missing)
# ======================================================================
TEMPLATES = {}

TEMPLATES["ping.sh"] = r'''#!/bin/bash
# Usage: ./ping.sh <IP_ADDRESS> <OUTPUT_FILE>
ping -c 10 "$1" | tee "$2"
'''

TEMPLATES["dynamic_client.sh"] = r'''#!/bin/bash
# killall -9 iperf
SERVER_IP=$1
TYPE=$2
PORT=$3
DURATION=$5
OUTPUT_FILE=$4
# dmesg -c
# wl reset_cnts
# echo "collecting counters"

if [ -z "$SERVER_IP" ] || [ -z "$TYPE" ] || [ -z "$PORT" ]; then
    echo "Usage: $0 <server IP> <tcp|udp|vi|vo> <PORT> <OUTPUT_FILE>"
    exit 1
fi

if [ "$TYPE" == "tcp" ]; then
    iperf -c $SERVER_IP -f m -i 1 -w 12M -t $DURATION -p $PORT -l 1470 | tee $OUTPUT_FILE
elif [ "$TYPE" == "udp" ]; then
    iperf -c $SERVER_IP -f m -i 1 -w 12M -u -b 80.0M -t $DURATION -p $PORT -l 1470 | tee $OUTPUT_FILE
elif [ "$TYPE" == "vi" ]; then
    iperf -c $SERVER_IP -f m -i 1 -w 12M -u -S 0xA0 -b 500.0M -t $DURATION -p $PORT -l 1470 | tee $OUTPUT_FILE
elif [ "$TYPE" == "vo" ]; then
    iperf -c $SERVER_IP -f m -i 1 -w 12M -u -S 0xE0 -b 500.0M -t $DURATION -p $PORT -l 1470 | tee $OUTPUT_FILE
elif [ "$TYPE" == "be" ]; then
    iperf -c $SERVER_IP -f m -i 1 -w 12M -u -S 0x00 -b 500.0M -t $DURATION -p $PORT -l 1470 | tee $OUTPUT_FILE
elif [ "$TYPE" == "bk" ]; then
    iperf -c $SERVER_IP -f m -i 1 -w 12M -u -S 0x20 -b 500.0M -t $DURATION -p $PORT -l 1470 | tee $OUTPUT_FILE
else
    echo "Invalid TYPE specified. Use tcp, udp, vi, or vo."
    exit 1
fi

IPERF_PID=$!

# polite stop after DURATION seconds
sleep $((DURATION + 3)) && kill -SIGINT -$
killall -9 iperf

# wait up to 5s for exit
for i in {1..5}; do
  if ! kill -0 "$IPERF_PID" 2>/dev/null; then
    break
  fi
  sleep 1
done

# force kill if still alive
kill -9 "$IPERF_PID" 2>/dev/null || true
'''

TEMPLATES["dynamic_server.sh"] = r'''#!/bin/bash
# killall -9 iperf
# dmesg -c
# wl reset_cnts
# echo "collecting counters"
PORT="$2"
OUTPUT_FILE=$3
TYPE="$1"
DURATION="$4"

if [ -z "$TYPE" ] || [ -z "$PORT" ] || [ -z "$OUTPUT_FILE" ]; then
    echo "Usage: $0 <tcp|udp|vi|vo> <PORT> <OUTPUT_FILE>"
    exit 1
fi

if [ "$TYPE" == "tcp" ]; then
    iperf -s -f m -i 1 -w 12M -p $PORT -l 1470 | tee $OUTPUT_FILE &
    IPERF_PID=$!
elif [ "$TYPE" == "udp" ]; then
    iperf -s -f m -i 1 -w 12M -u -p $PORT -l 1470 | tee $OUTPUT_FILE &
    IPERF_PID=$!
elif [ "$TYPE" == "vi" ]; then
    iperf -s -f m -i 1 -w 12M -u -S 0xA0 -p $PORT -l 1470 | tee $OUTPUT_FILE &
    IPERF_PID=$!
elif [ "$TYPE" == "vo" ]; then
    iperf -s -f m -i 1 -w 12M -u -S 0xE0 -p $PORT -l 1470 | tee $OUTPUT_FILE &
    IPERF_PID=$!
elif [ "$TYPE" == "be" ]; then
    iperf -s -f m -i 1 -w 12M -u -S 0x00 -p $PORT -l 1470 | tee $OUTPUT_FILE &
    IPERF_PID=$!
elif [ "$TYPE" == "bk" ]; then
    iperf -s -f m -i 1 -w 12M -u -S 0x20 -p $PORT -l 1470 | tee $OUTPUT_FILE &
    IPERF_PID=$!
else
    echo "Invalid Type specified. Use tcp, udp, vi, or vo."
    exit 1
fi

sleep $((DURATION + 3)) && kill -SIGINT -$
killall -9 iperf
# request graceful stop
kill -SIGINT "$IPERF_PID" 2>/dev/null

# wait a short time for exit
for i in {1..5}; do
  if ! kill -0 "$IPERF_PID" 2>/dev/null; then
    echo "iperf $IPERF_PID exited"
    exit 0
  fi
  sleep 1
done

# force kill if still running
kill -9 "$IPERF_PID" 2>/dev/null || true
echo "iperf $IPERF_PID terminated"
'''

TEMPLATES["RSSI.sh"] = r'''#!/bin/sh
# RSSI.sh
# Usage: ./RSSI.sh [seconds] [t]
#   seconds - duration to run (default 40)
#   t       - if present, prepend timestamp to each line

# Defaults
DURATION=${1:-40}
TS_FLAG=${2:-}

# validate DURATION is integer, fallback to 40
case "$DURATION" in
  ''|*[!0-9]*)
    DURATION=40
    ;;
esac

# get first IP from hostname -I, fallback to no_ip
FIRST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$FIRST_IP" ] && FIRST_IP="no_ip"

# sanitize dots to underscores
SAFE_IP=$(echo "$FIRST_IP" | tr '.' '_')

OUTFILE="rssi_${SAFE_IP}.log"

# truncate/create output file
: > "$OUTFILE"

START=$(date +%s)
END=$((START + DURATION))

while [ "$(date +%s)" -lt "$END" ]; do
  out=$(wl -i wlan0 phy_rssi_ant 2>/dev/null)
  if [ -n "$TS_FLAG" ]; then
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    line="$ts $out"
  else
    line="$out"
  fi
  printf '%s\n' "$line" >> "$OUTFILE"
  printf '%s\n' "$line"
  sleep 1
done
'''

TEMPLATES["assoc.sh"] = r'''#!/bin/bash
# assoc.sh  (converted from assoc.py)
# Usage: ./assoc.sh <SSID> <security_type>
#   security_type: open | wpa2 | wpa3 | sae_gcmp | gcmp256

SSID="$1"
SEC="$2"

DEFAULT_PASSWORD="9876543210"
PASSWORD="12345678"
CLI="./wpa_cli -i wpa_wlan0_cmd"

if [ -z "$SSID" ] || [ -z "$SEC" ]; then
  echo "Usage: $0 <SSID> <open|wpa2|wpa3|sae_gcmp|gcmp256>"
  exit 1
fi

run() {
  echo "Command: $*"
  out="$("$@" 2>&1)"
  echo "Output: $out"
  echo
}

connect_open() {
  run $CLI IFNAME=wlan0 remove_net all
  run $CLI IFNAME=wlan0 add_net
  run $CLI IFNAME=wlan0 set_net 0 ssid "\"$SSID\""
  run $CLI IFNAME=wlan0 set_net 0 key_mgmt NONE
  run $CLI IFNAME=wlan0 enable_n 0
  sleep 7
  run wl -i wlan0 status
}

connect_wpa2() {
  run $CLI IFNAME=wlan0 remove_net all
  run $CLI IFNAME=wlan0 add_net
  run $CLI IFNAME=wlan0 set_net 0 ssid "\"$SSID\""
  run $CLI IFNAME=wlan0 set_net 0 ieee80211w 0
  run $CLI IFNAME=wlan0 set_net 0 key_mgmt WPA-PSK
  run $CLI IFNAME=wlan0 set_net 0 proto WPA2
  run $CLI IFNAME=wlan0 set_net 0 pairwise CCMP
  run $CLI IFNAME=wlan0 set_net 0 psk "\"$DEFAULT_PASSWORD\""
  run $CLI IFNAME=wlan0 enable_n 0
  sleep 7
  run wl -i wlan0 status
}

connect_wpa3() {
  run $CLI IFNAME=wlan0 remove_net all
  run $CLI IFNAME=wlan0 add_net
  run $CLI IFNAME=wlan0 set_net 0 ssid "\"$SSID\""
  run $CLI IFNAME=wlan0 set pmf 1
  run $CLI IFNAME=wlan0 set_net 0 key_mgmt SAE
  run $CLI IFNAME=wlan0 set_net 0 ieee80211w 2
  run $CLI IFNAME=wlan0 set_net 0 psk "\"$DEFAULT_PASSWORD\""
  run $CLI IFNAME=wlan0 set_net 0 pairwise CCMP
  run $CLI IFNAME=wlan0 set sae_pwe 2
  run $CLI IFNAME=wlan0 save_config
  run $CLI IFNAME=wlan0 enable_n 0
  sleep 5
  run wl -i wlan0 status
}

connect_sae_gcmp() {
  run $CLI IFNAME=wlan0 remove_n all
  run $CLI IFNAME=wlan0 add_n
  run $CLI IFNAME=wlan0 set_n 0 ssid "\"$SSID\""
  run $CLI IFNAME=wlan0 set_n 0 proto RSN
  run $CLI IFNAME=wlan0 set_n 0 key_mgmt SAE WPA-PSK
  run $CLI IFNAME=wlan0 set_n 0 pairwise CCMP GCMP-256
  run $CLI IFNAME=wlan0 set_n 0 psk "\"$PASSWORD\""
  run $CLI IFNAME=wlan0 set_n 0 group GCMP-256 CCMP
  run $CLI IFNAME=wlan0 set_n 0 priority 1
  run $CLI IFNAME=wlan0 set_n 0 ieee80211w 1
  run $CLI IFNAME=wlan0 enable_n 0
  sleep 9
  run wl -i wlan0 status
}

connect_gcmp256() {
  run $CLI IFNAME=wlan0 remove_network all
  run $CLI IFNAME=wlan0 add_network
  run $CLI IFNAME=wlan0 set_n 0 ssid "\"$SSID\""
  run $CLI IFNAME=wlan0 set_network 0 ieee80211w 2
  run $CLI IFNAME=wlan0 set_network 0 key_mgmt SAE
  run $CLI IFNAME=wlan0 set_network 0 pairwise GCMP-256
  run $CLI IFNAME=wlan0 set_network 0 group GCMP-256 CCMP
  run $CLI IFNAME=wlan0 set_network 0 sae_password "\"$PASSWORD\""
  run $CLI IFNAME=wlan0 set pmf 2
  run $CLI IFNAME=wlan0 set sae_pwe 2
  run $CLI IFNAME=wlan0 enable_network 0
  run $CLI IFNAME=wlan0 set sae_groups 19
  sleep 9
  run wl -i wlan0 status
}

case "$SEC" in
  open)      connect_open ;;
  wpa2)      connect_wpa2 ;;
  wpa3)      connect_wpa3 ;;
  sae_gcmp)  connect_sae_gcmp ;;
  gcmp256)   connect_gcmp256 ;;
  *) echo "Invalid security type. Use open, wpa2, wpa3, sae_gcmp, gcmp256."; exit 1 ;;
esac
'''

TEMPLATES["dynamic_client_bd.sh"] = r'''#!/bin/bash
SERVER_IP=$1
TYPE=$2
PORT=$3
DURATION=$5
OUTPUT_FILE=$4

if [ -z "$SERVER_IP" ] || [ -z "$TYPE" ] || [ -z "$PORT" ]; then
    echo "Usage: $0 <server IP> <tcp|udp|vi|vo> <PORT> <OUTPUT_FILE>"
    exit 1
fi

if [ "$TYPE" == "tcp" ]; then
    iperf -c $SERVER_IP -f m -i 1 -w 12M -t $DURATION -p $PORT -l 1470 -d| tee $OUTPUT_FILE
elif [ "$TYPE" == "udp" ]; then
    iperf -c $SERVER_IP -f m -i 1 -w 12M -u -b 100M -t $DURATION -p $PORT -l 1470 -d| tee $OUTPUT_FILE
elif [ "$TYPE" == "vi" ]; then
    iperf -c $SERVER_IP -f m -i 1 -w 12M -u -S 0xA0 -b 1000M -t $DURATION -p $PORT -l 1470 -d| tee $OUTPUT_FILE
elif [ "$TYPE" == "vo" ]; then
    iperf -c $SERVER_IP -f m -i 1 -w 12M -u -S 0xE0 -b 500.0M -t $DURATION -p $PORT -l 1470 -d| tee $OUTPUT_FILE
else
    echo "Invalid TYPE specified. Use tcp, udp, vi, or vo."
    exit 1
fi

IPERF_PID=$!

sleep $((DURATION + 3)) && kill -SIGINT -$
killall -9 iperf

for i in {1..5}; do
  if ! kill -0 "$IPERF_PID" 2>/dev/null; then
    break
  fi
  sleep 1
done

kill -9 "$IPERF_PID" 2>/dev/null || true
'''

TEMPLATES["dynamic_server_bd.sh"] = r'''#!/bin/bash
PORT="$2"
OUTPUT_FILE=$3
TYPE="$1"
DURATION="$4"

if [ -z "$TYPE" ] || [ -z "$PORT" ] || [ -z "$OUTPUT_FILE" ]; then
    echo "Usage: $0 <tcp|udp|vi|vo> <PORT> <OUTPUT_FILE>"
    exit 1
fi

if [ "$TYPE" == "tcp" ]; then
    iperf -s -f m -i 1 -w 12M -p $PORT -l 1470 -d| tee $OUTPUT_FILE &
    IPERF_PID=$!
elif [ "$TYPE" == "udp" ]; then
    iperf -s -f m -i 1 -w 12M -u -p $PORT -l 1470 -d| tee $OUTPUT_FILE &
    IPERF_PID=$!
elif [ "$TYPE" == "vi" ]; then
    iperf -s -f m -i 1 -w 12M -u -S 0xA0 -p $PORT -l 1470 -d| tee $OUTPUT_FILE &
    IPERF_PID=$!
elif [ "$TYPE" == "vo" ]; then
    iperf -s -f m -i 1 -w 12M -u -S 0xE0 -p $PORT -l 1470 -d| tee $OUTPUT_FILE &
    IPERF_PID=$!
else
    echo "Invalid Type specified. Use tcp, udp, vi, or vo."
    exit 1
fi

sleep $((DURATION + 3)) && kill -SIGINT -$
killall -9 iperf
kill -SIGINT "$IPERF_PID" 2>/dev/null

for i in {1..5}; do
  if ! kill -0 "$IPERF_PID" 2>/dev/null; then
    echo "iperf $IPERF_PID exited"
    exit 0
  fi
  sleep 1
done

kill -9 "$IPERF_PID" 2>/dev/null || true
echo "iperf $IPERF_PID terminated"
'''

# ======================================================================
# Helpers
# ======================================================================
def sh(cmd):
    """Run a local shell command; return (combined_output, returncode)."""
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
    return p.stdout, p.returncode


def execute_command(command, remote_host=None, new_terminal=False,
                    terminal_name=None, timeout=None):
    """Execute a command locally or remotely via SSH.
    Returns (stdout, stderr, returncode, timed_out)."""
    skip_printing = command.endswith(", dp")
    if skip_printing:
        command = command[:-4]

    full_command = f"ssh {SSH_USER}@{remote_host} '{command}'" if remote_host else command
    print(f"Executing: {full_command}")

    if new_terminal:
        if terminal_name:
            full_command = (f'gnome-terminal --title="{terminal_name}" -- '
                            f'bash -c "{full_command}; exec bash"')
        else:
            full_command = f'gnome-terminal -- bash -c "{full_command}; exec bash"'
        try:
            proc = subprocess.run(full_command, shell=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=timeout)
            return proc.stdout.decode(), proc.stderr.decode(), proc.returncode, False
        except subprocess.TimeoutExpired:
            return "", f"Timed out after {timeout} seconds", -1, True
    else:
        proc = subprocess.Popen(full_command, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        try:
            output, error = proc.communicate(timeout=timeout)
            if not skip_printing:
                if output:
                    print(output.decode())
                if error:
                    print(error.decode())
            return output.decode(), error.decode(), proc.returncode, False
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                output, error = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                output, error = b"", b""
            out_decoded = output.decode() if output else ""
            err_decoded = error.decode() if error else ""
            print(f"Command timed out after {timeout} seconds; process killed.")
            return out_decoded, err_decoded, -1, True


def fetch_file(remote_host, remote_path, local_path):
    """Fetch a file from a remote host via scp (uses same auth as system ssh)."""
    out, rc = sh(f"scp -o ConnectTimeout=10 {SSH_USER}@{remote_host}:{remote_path} {local_path}")
    if rc == 0:
        print(f"fetched {remote_path} from {remote_host}")
    else:
        print(f"FETCH FAILED {remote_path} from {remote_host} (rc={rc})")
        if out.strip():
            print(out.strip())


def get_mac(host, iface):
    """Read live MAC of an interface via ifconfig (ether or HWaddr)."""
    out, _, _, _ = execute_command(f"ifconfig {iface}", remote_host=host)
    out = out or ""
    m = re.search(r'ether\s+([0-9a-fA-F:]{17})', out)
    if not m:
        m = re.search(r'HWaddr\s+([0-9a-fA-F:]{17})', out)
    return m.group(1) if m else None


def valid_xx(s):
    return re.match(r'^\d{1,3}\.\d{1,3}$', s) is not None


def read_octets(prompt):
    line = input(prompt).strip()
    if not line:
        return []
    good = []
    for tok in line.split():
        if valid_xx(tok):
            good.append(tok)
        else:
            print(f"  skipping invalid entry: {tok} (expected X.X e.g. 1.4)")
    return good


def ask_buckets():
    """Prompt ASTRA then VIM3 IPs. Returns list of target dicts."""
    astra = read_octets("Enter ASTRA IPs as X.X (blank if none): ")
    vim3  = read_octets("Enter VIM3 IPs as X.X  (blank if none): ")
    targets = []
    for xx in astra:
        targets.append({"xx": xx, "ip": f"172.16.{xx}",
                        "path": ASTRA_PATH, "type": "ASTRA"})
    for xx in vim3:
        targets.append({"xx": xx, "ip": f"172.16.{xx}",
                        "path": VIM3_PATH, "type": "VIM3"})
    return targets


# def ask_setup():
#     """For TX/RX: one DUT (SoftAP) + N clients (ASTRA/VIM3 buckets)."""
#     while True:
#         dut_xx = input("DUT (SoftAP) IP as X.X: ").strip()
#         if valid_xx(dut_xx):
#             break
#         print("  enter as X.X e.g. 1.2")
#     if dut_xx == "1.4":
#         dut_type = "v"
#         print("DUT 1.4 -> VIM3 (auto)")
#     else:
#         dut_type = ""
#         while dut_type not in ("a", "v"):
#             dut_type = input("DUT type? (a=ASTRA / v=VIM3): ").strip().lower()
#     dut = {
#         "xx": dut_xx, "ip": f"172.16.{dut_xx}",
#         "path": ASTRA_PATH if dut_type == "a" else VIM3_PATH,
#         "type": "ASTRA" if dut_type == "a" else "VIM3",
#         "data": f"192.168.{dut_xx}",   # SoftAP data IP, derived from mgmt octet
#     }
#     print("\nEnter CLIENT IPs:")
#     clients = ask_buckets()
#     for c in clients:
#         c["data"] = f"192.168.{c['xx']}"
#     return dut, clients

def ask_setup():
    """For TX/RX: DUT SoftAP is FIXED at 1.4. Only clients are entered."""
    dut = {
        "xx": SOFTAP_XX, "ip": SOFTAP_IP,
        "path": SOFTAP_PATH, "type": "VIM3",
        "data": SOFTAP_DATA,
    }
    print(f"SoftAP (DUT) = {SOFTAP_IP} (wlan1 {SOFTAP_DATA}) [fixed]")
    print("\nEnter CLIENT IPs:")
    clients = ask_buckets()
    for c in clients:
        c["data"] = f"192.168.{c['xx']}"
    return dut, clients


def ask_traffic():
    print("\nTraffic type:  1) tcp   2) udp   3) vi   4) vo")
    choice = input("Choice (1-4): ").strip()
    ttype = {"1": "tcp", "2": "udp", "3": "vi", "4": "vo"}.get(choice, "tcp")
    print(f"Selected: {ttype}, {DURATION}s (fixed)")
    return ttype


def ask_sniffer():
    """Channel + pcap name for sniffer capture. Blank channel -> skip."""
    ch = input("Sniffer channel/chanspec (blank to SKIP capture): ").strip()
    if not ch:
        print("Sniffer capture skipped.")
        return None, None
    name = input("Pcap file name (without .pcap): ").strip()
    if not name:
        name = time.strftime("capture_%Y%m%d_%H%M%S")
    name = name.replace(" ", "_")
    return ch, name


# def start_sniffer(channel, pcap_name, cap_secs):
#     """Start sniffer setup + tshark on the sniffer box (own terminal)."""
#     cmd = (f"cd {SNIFFER_PATH} && mkdir -p {PCAP_DIR} && "
#            f"wl -i wlan0 monitor 0; wl -i wlan0 disassoc; "
#            f"wl -i wlan0 country US/0; wl -i wlan0 mpc 0; wl -i wlan0 wsec 0; "
#            f"wl -i wlan0 PM 0; wl -i wlan0 down; wl -i wlan0 chanspec {channel}; "
#            f"wl -i wlan0 up; wl -i wlan0 monitor 3; "
#            f"tshark -a duration:{cap_secs} -i 3 -w {PCAP_DIR}/{pcap_name}.pcap -q")
#     print(f"Starting sniffer on {SNIFFER_IP}, ch {channel}, {cap_secs}s "
#           f"-> {PCAP_DIR}/{pcap_name}.pcap")
#     execute_command(cmd, remote_host=SNIFFER_IP, new_terminal=True,
#                     terminal_name=f"Sniffer_{pcap_name}")

def start_sniffer(channel, pcap_name, cap_secs):
    # run setup + tshark -D to get correct radiotap0 interface number
    probe_cmd = (f"cd {SNIFFER_PATH} && "
                 f"wl -i wlan0 monitor 0; wl -i wlan0 disassoc; "
                 f"wl -i wlan0 country US/0; wl -i wlan0 mpc 0; wl -i wlan0 mpc; "
                 f"wl -i wlan0 wsec 0; wl -i wlan0 wsec; "
                 f"wl -i wlan0 PM 0; wl -i wlan0 PM; "
                 f"wl -i wlan0 down; wl -i wlan0 chanspec {channel}; "
                 f"wl -i wlan0 up; wl -i wlan0 monitor 3; "
                 f"ifconfig radiotap0 up; sleep 2; tshark -D")
    out, _, _, _ = execute_command(probe_cmd, remote_host=SNIFFER_IP)
    iface_num = "3"  # fallback
    for line in (out or "").splitlines():
        if "radiotap0" in line:
            iface_num = line.strip().split(".")[0].strip()
            break
    print(f"Sniffer radiotap0 -> interface {iface_num}")

    # now start actual capture in new terminal
    cap_cmd = (f"cd {SNIFFER_PATH} && mkdir -p {PCAP_DIR} && "
               f"wl -i wlan0 monitor 0; wl -i wlan0 disassoc; "
               f"wl -i wlan0 country US/0; wl -i wlan0 mpc 0; "
               f"wl -i wlan0 wsec 0; wl -i wlan0 PM 0; "
               f"wl -i wlan0 down; wl -i wlan0 chanspec {channel}; "
               f"wl -i wlan0 up; wl -i wlan0 monitor 3; "
               f"ifconfig radiotap0 up; sleep 2; "
               f"tshark -a duration:{cap_secs} -i {iface_num} "
               f"-w {PCAP_DIR}/{pcap_name}.pcap -q")
    print(f"Starting sniffer on {SNIFFER_IP}, ch {channel}, {cap_secs}s "
          f"-> {PCAP_DIR}/{pcap_name}.pcap  (iface {iface_num})")
    execute_command(cap_cmd, remote_host=SNIFFER_IP, new_terminal=True,
                    terminal_name=f"Sniffer_{pcap_name}")


def fetch_pcap(t_sniff, pcap_name, cap_secs):
    """Wait for the capture to finish, then scp the pcap from sniffer to TM."""
    if t_sniff is not None:
        # +8s buffer covers the wl setup time before tshark actually starts
        remaining = cap_secs + 8 - (time.time() - t_sniff)
        if remaining > 0:
            print(f"Waiting {remaining:.0f}s for sniffer capture ({cap_secs}s) to complete...")
            time.sleep(remaining)
    os.makedirs(TM_PCAP_DIR, exist_ok=True)
    src = f"{PCAP_DIR}/{pcap_name}.pcap"
    dst = f"{TM_PCAP_DIR}/{pcap_name}.pcap"
    out, rc = sh(f"scp -o ConnectTimeout=10 {SSH_USER}@{SNIFFER_IP}:{src} {dst}")
    if rc == 0:
        print(f"pcap pulled -> {dst}")
    else:
        print(f"PCAP FETCH FAILED from {SNIFFER_IP}:{src} (rc={rc})")
        if out.strip():
            print(out.strip())


def set_bandwidth(local_file, ttype, bval):
    """Edit only the selected type's iperf line in dynamic_client.sh, setting -b.
    udp line is identified by '-u -b', vi by '-S 0xA0', vo by '-S 0xE0'."""
    marker = {"udp": "-u -b", "vi": "-S 0xA0", "vo": "-S 0xE0",
             "be": "-S 0x00", "bk": "-S 0x20"}.get(ttype)
    if marker is None:
        return False
    try:
        with open(local_file) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return False
    changed = False
    for i, ln in enumerate(lines):
        if marker in ln and "-b " in ln:
            lines[i] = re.sub(r'-b\s+\S+', f'-b {bval}', ln)
            changed = True
    if changed:
        with open(local_file, "w") as f:
            f.writelines(lines)
    return changed


def _scp_dynamic_client(targets):
    fname = "dynamic_client.sh"
    for t in targets:
        dest = f"{SSH_USER}@{t['ip']}:{t['path']}/"
        print(f"--> scp -r {fname} {dest}")
        out, rc = sh(f"scp -r {fname} {dest}")
        if out.strip():
            print(out.strip())
        print("OK" if rc == 0 else f"FAILED (rc={rc})")


def configure_bandwidth_and_push(ttype):
    """For udp/vi/vo: ask -b, edit local dynamic_client.sh, scp to devices."""
    if ttype not in ("udp", "vi", "vo"):
        return
    bval = input(f"Enter -b bandwidth for {ttype} (e.g. 1000M): ").strip()
    if not bval:
        print("No -b entered; leaving dynamic_client.sh unchanged.")
        return
    if not bval[-1].isalpha():     # no unit -> default to M
        bval += "M"

    ensure_local("dynamic_client.sh")
    if set_bandwidth("dynamic_client.sh", ttype, bval):
        print(f"Set {ttype} -b to {bval} in local dynamic_client.sh")
    else:
        print(f"WARN: could not find {ttype} line in dynamic_client.sh; skipping scp")
        return

    print("Push updated dynamic_client.sh to:")
    print("  1) All devices (full lab list)")
    print("  2) Selected devices only")
    choice = input("Choice (1/2): ").strip()
    if choice == "1":
        targets = ([{"ip": f"172.16.{x}", "path": ASTRA_PATH} for x in ALL_ASTRA]
                   + [{"ip": f"172.16.{x}", "path": VIM3_PATH} for x in ALL_VIM3])
    elif choice == "2":
        targets = ask_buckets()
    else:
        print("Invalid choice; skipping scp.")
        return
    if not targets:
        print("No targets; skipping scp.")
        return
    _scp_dynamic_client(targets)


def ensure_local(fname):
    if not os.path.exists(fname):
        with open(fname, "w") as f:
            f.write(TEMPLATES[fname])
        os.chmod(fname, 0o755)
        print(f"(created local {fname} from template)")


# ======================================================================
# Option 1 : Code A  - load driver on all DUTs
# ======================================================================
def opt_load_all():
    print("\n--- Load driver on all DUTs ---")
    targets = ask_buckets()
    if not targets:
        print("No IPs entered.")
        return

    results = []   # (ip, type, driver_ok, supp_ok)
    for t in targets:
        last = t["xx"].split(".")[-1]
        path = t["path"]
        print(f"\n===== {t['ip']}  ({t['type']}, {path}) =====")
        remote = (
            f"cd {path} && ./load.sh {last}; ./supp.sh {last}; "
            f"echo '---WLVER---'; wl ver 2>&1; "
            f"echo '---SUPP---'; ps -aef | grep wpa_supplicant | grep -v grep"
        )
        out, rc = sh(f'ssh -o ConnectTimeout=20 -o BatchMode=yes '
                     f'{SSH_USER}@{t["ip"]} "{remote}"')
        print(out if out.strip() else "<no output>")

        # split sections
        wlver_sec, supp_sec = "", ""
        if "---WLVER---" in out:
            after = out.split("---WLVER---", 1)[1]
            if "---SUPP---" in after:
                wlver_sec, supp_sec = after.split("---SUPP---", 1)
            else:
                wlver_sec = after

        # driver ok: wl ver returned a real version string, not an error
        wv = wlver_sec.strip()
        driver_ok = bool(wv) and "error" not in wv.lower() and "not found" not in wv.lower() \
                    and "command not found" not in wv.lower()

        # supp ok: a wpa_supplicant process line contains this device's path
        supp_ok = any(path in ln for ln in supp_sec.splitlines() if "wpa_supplicant" in ln)

        results.append((t["ip"], t["type"], driver_ok, supp_ok))

    # ---- SUMMARY ----
    n = len(results)
    drv_pass  = sum(1 for (_, _, d, _) in results if d)
    supp_pass = sum(1 for (_, _, _, s) in results if s)
    drv_fail  = [ip for (ip, _, d, _) in results if not d]
    supp_fail = [ip for (ip, _, _, s) in results if not s]

    lines = []
    lines.append("=" * 60)
    lines.append("LOAD SUMMARY  " + time.strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("=" * 60)
    lines.append(f"{'IP':<16}{'Type':<8}{'Driver(wl ver)':<16}{'supp.sh':<10}")
    lines.append("-" * 60)
    for (ip, typ, d_ok, s_ok) in results:
        d = "PASS" if d_ok else "FAIL"
        s = "PASS" if s_ok else "FAIL"
        lines.append(f"{ip:<16}{typ:<8}{d:<16}{s:<10}")
    lines.append("-" * 60)
    lines.append(f"Driver: {drv_pass}/{n} passed   supp.sh: {supp_pass}/{n} passed")
    if drv_fail:
        lines.append(f"Driver FAILED: {', '.join(drv_fail)}")
    if supp_fail:
        lines.append(f"supp.sh FAILED: {', '.join(supp_fail)}")
    if not drv_fail and not supp_fail:
        lines.append("ALL PASSED")

    report = "\n".join(lines)
    print("\n" + report)
    with open("summary.txt", "w") as f:
        f.write(report + "\n")
    print("\nSummary -> summary.txt")


# ======================================================================
# Option 2 : Code B  - broadcast a command + collect
# ======================================================================
def opt_broadcast():
    print("\n--- Broadcast command + collect ---")
    cmd = input("Enter command to run on each host: ").strip()
    if not cmd:
        print("No command entered.")
        return
    targets = ask_buckets()
    if not targets:
        print("No IPs entered.")
        return
    for t in targets:
        print(f"\n===== {t['ip']}  ({t['type']}, {t['path']}) =====")
        remote = f"cd {t['path']} && {cmd}"
        out, rc = sh(f'ssh -o ConnectTimeout=10 {SSH_USER}@{t["ip"]} "{remote}"')
        print("Output:")
        print(out if out.strip() else "<no output>")
        print(f"Exit code: {rc}")


# ======================================================================
# Option 3 : TX  - DUT SoftAP transmits to clients
# ======================================================================
def opt_tx():
    print("\n--- TX traffic test (DUT -> clients) ---")
    dut, clients = ask_setup()
    if not clients:
        print("No clients entered.")
        return
    ttype = ask_traffic()
    ch = ask_channel()
    _run_traffic("TX", ttype, ch, dut, clients,
                 ping_dir="d2c", is_bd=False, server_side="client")


# ======================================================================
# Option 4 : RX  - clients transmit to DUT SoftAP
# ======================================================================
def opt_rx():
    print("\n--- RX traffic test (clients -> DUT) ---")
    dut, clients = ask_setup()
    if not clients:
        print("No clients entered.")
        return
    ttype = ask_traffic()
    ch = ask_channel()
    _run_traffic("RX", ttype, ch, dut, clients,
                 ping_dir="c2d", is_bd=False, server_side="dut")


# ======================================================================
# Shared summary writer (built-in log fetch for TX/RX)
# ======================================================================
def summarize(clients, ttype, direction):
    zero_clients, zero_servers = [], []
    for i, _ in enumerate(clients):
        try:
            with open(f"c{i+1}.txt") as f:
                d = f.read()
                if "0.000 Mbits/sec" in d or "0.00 Mbits/sec" in d:
                    zero_clients.append(f"c{i+1}")
        except FileNotFoundError:
            pass
        try:
            with open(f"s{i+1}.txt") as f:
                d = f.read()
                if "0.000 Mbits/sec" in d or "0.00 Mbits/sec" in d:
                    zero_servers.append(f"s{i+1}")
        except FileNotFoundError:
            pass

    outname = f"{ttype}_{direction}_traffic_summary.txt"
    with open(outname, "w") as s:
        for i, _ in enumerate(clients):
            try:
                cd = open(f"c{i+1}.txt").read()
                sd = open(f"s{i+1}.txt").read()
                pd = open(f"pc{i}.txt").read()
            except FileNotFoundError:
                s.write(f"Missing data for Client {i+1}\n\n")
                continue
            if direction == "RX":
                s.write(f"Client {i+1} to DUT traffic:\n")
            else:
                s.write(f"DUT to Client {i+1} traffic:\n")
            s.write(f"Client:\n{cd}\n")
            s.write(f"Server:\n{sd}\n")
            if direction == "RX":
                s.write(f"Ping from Client{i+1} to DUT:\n{pd}\n\n")
            else:
                s.write(f"Ping from DUT to Client{i+1}:\n{pd}\n\n")
        if zero_clients or zero_servers:
            s.write("\n" + "=" * 50 + "\n")
            s.write("ZERO THROUGHPUT INSTANCES DETECTED:\n")
            s.write("=" * 50 + "\n")
            if zero_clients:
                s.write(f"Clients with 0.000 Mbits/sec: {', '.join(zero_clients)}\n")
            if zero_servers:
                s.write(f"Servers with 0.000 Mbits/sec: {', '.join(zero_servers)}\n")
    print(f"\n{direction} traffic summary saved to {outname}")


# ======================================================================
# Results -> Excel (auto-run after TX/RX).  Falls back to CSV if openpyxl
# is not installed.
# ======================================================================
def _extract_interval(line):
    m = re.search(r'(\d+(?:\.\d+)?)\s*-\s*(\d+(?:\.\d+)?)\s+sec\s+'
                  r'(\d+(?:\.\d+)?)\s+MBytes\s+(\d+(?:\.\d+)?)\s+Mbits/sec', line)
    if not m:
        return None
    return (float(m.group(1)), float(m.group(2)),
            float(m.group(3)), float(m.group(4)))


def server_throughput(filepath):
    """Return (value_Mbps, method) -> method in summary|average|missing|no data."""
    try:
        lines = open(filepath).readlines()
    except FileNotFoundError:
        return None, "missing"
    parsed = [p for p in (_extract_interval(l) for l in lines) if p]
    if not parsed:
        return None, "no data"
    min_s = min(p[0] for p in parsed)
    max_e = max(p[1] for p in parsed)
    summary = None
    for p in parsed:
        if (abs(p[0] - min_s) < 0.01 and abs(p[1] - max_e) < 0.01
                and (p[1] - p[0]) > 1.5):
            if summary is None or (p[1] - p[0]) > (summary[1] - summary[0]):
                summary = p
    if summary:
        return summary[3], "summary"
    rates = [p[3] for p in parsed]
    return sum(rates) / len(rates), "average"


def ping_rtt(filepath):
    """Return avg RTT (ms) or None."""
    try:
        lines = open(filepath).readlines()
    except FileNotFoundError:
        return None
    for l in lines:
        m = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', l)
        if m:
            return float(m.group(1))
    return None


def rssi_mid(filepath, duration):
    """Return the RSSI line nearest the middle second of the run, or None.
    One sample per second is logged; line N ~= second N."""
    try:
        lines = [l.rstrip("\n") for l in open(filepath) if l.strip()]
    except FileNotFoundError:
        return None
    if not lines:
        return None
    try:
        target = max(1, int(float(duration)) // 2)   # 1-based line number
    except (ValueError, TypeError):
        target = 1
    idx = min(len(lines) - 1, target - 1)
    return re.sub(r'^\d+:\s*', '', lines[idx]).strip()


def _gather(direction, ttype, dur, dut, clients):
    """Collect throughput + ping rows for this run."""
    tput_rows = []
    total = 0.0
    for i, c in enumerate(clients):
        val, method = server_throughput(f"s{i+1}.txt")
        if val is not None:
            total += val
        rssi = rssi_mid(f"rssi{i+1}.log", dur)
        tput_rows.append((i + 1, c["ip"], c["type"], val, method, rssi))
    ping_rows = []
    for i, c in enumerate(clients):
        ping_rows.append((i + 1, c["ip"], c["type"], ping_rtt(f"pc{i}.txt")))
    return tput_rows, ping_rows, total


def save_results(direction, ttype, dur, dut, clients, xlsx_path="wlan_results.xlsx"):
    """Append this run as a new Iteration block to the Excel workbook
    (or CSV fallback). Auto-runs after TX/RX."""
    tput_rows, ping_rows, total = _gather(direction, ttype, dur, dut, clients)
    summary_file = f"{ttype}_{direction}_traffic_summary.txt"
    ts = time.strftime("%Y-%m-%d %H:%M:%S")

    try:
        import openpyxl
    except ImportError:
        _save_csv(direction, ttype, dur, dut, clients, tput_rows, ping_rows,
                  total, summary_file, ts)
        print("\nopenpyxl not installed -> results written to wlan_results.csv")
        print("For .xlsx output:  pip install openpyxl")
        return

    if os.path.exists(xlsx_path):
        wb = openpyxl.load_workbook(xlsx_path)
        ws = wb["Results"] if "Results" in wb.sheetnames else wb.active
    else:
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Results"

    # next iteration number
    iteration = 1
    for row in ws.iter_rows(values_only=True):
        if row and isinstance(row[0], str) and row[0].startswith("Iteration"):
            try:
                iteration = max(iteration, int(row[0].split()[1]) + 1)
            except (IndexError, ValueError):
                pass

    if ws.max_row and ws.max_row > 1:
        ws.append([])

    mid_label = max(1, int(float(dur)) // 2) if str(dur).replace('.', '', 1).isdigit() else 1

    ws.append([f"Iteration {iteration}", ts])
    ws.append([f"Summary file: {summary_file}",
               f"direction={direction}", f"type={ttype}", f"duration={dur}s"])
    ws.append([])

    ws.append(["Throughput (Mbits/sec)"])
    ws.append(["Client#", "IP", "Type", "Throughput", "Method", f"RSSI @ {mid_label}s"])
    for (idx, ip, typ, val, method, rssi) in tput_rows:
        ws.append([f"Client{idx}", ip, typ,
                   (round(val, 1) if val is not None else "NO DATA"),
                   method, (rssi if rssi else "NO DATA")])
    ws.append(["TOTAL", "", "", round(total, 1), "", ""])
    ws.append([])

    ws.append(["Ping RTT (ms)"])
    ws.append(["Client#", "IP", "Type", "Avg RTT (ms)"])
    for (idx, ip, typ, rtt) in ping_rows:
        ws.append([f"Client{idx}", ip, typ,
                   (round(rtt, 3) if rtt is not None else "NO DATA")])
    ws.append([])

    ws.append(["Devices", "IP", "Type"])
    ws.append(["DUT (SoftAP)", dut["ip"], dut["type"]])
    for i, c in enumerate(clients):
        ws.append([f"Client{i+1}", c["ip"], c["type"]])
    ws.append(["end of iteration"])

    wb.save(xlsx_path)
    print(f"\nResults appended as Iteration {iteration} -> {xlsx_path}")


def _save_csv(direction, ttype, dur, dut, clients, tput_rows, ping_rows,
              total, summary_file, ts, csv_path="wlan_results.csv"):
    import csv
    iteration = 1
    if os.path.exists(csv_path):
        with open(csv_path) as f:
            for line in f:
                if line.startswith("Iteration"):
                    try:
                        iteration = max(iteration, int(line.split(",")[0].split()[1]) + 1)
                    except (IndexError, ValueError):
                        pass
    with open(csv_path, "a", newline="") as f:
        w = csv.writer(f)
        if iteration > 1:
            w.writerow([])
        w.writerow([f"Iteration {iteration}", ts])
        w.writerow([f"Summary file: {summary_file}", direction, ttype, f"{dur}s"])
        w.writerow([])
        mid_label = max(1, int(float(dur)) // 2) if str(dur).replace('.', '', 1).isdigit() else 1
        w.writerow(["Throughput (Mbits/sec)"])
        w.writerow(["Client#", "IP", "Type", "Throughput", "Method", f"RSSI @ {mid_label}s"])
        for (idx, ip, typ, val, method, rssi) in tput_rows:
            w.writerow([f"Client{idx}", ip, typ,
                        (round(val, 1) if val is not None else "NO DATA"),
                        method, (rssi if rssi else "NO DATA")])
        w.writerow(["TOTAL", "", "", round(total, 1), "", ""])
        w.writerow([])
        w.writerow(["Ping RTT (ms)"])
        w.writerow(["Client#", "IP", "Type", "Avg RTT (ms)"])
        for (idx, ip, typ, rtt) in ping_rows:
            w.writerow([f"Client{idx}", ip, typ,
                        (round(rtt, 3) if rtt is not None else "NO DATA")])
        w.writerow([])
        w.writerow(["Devices", "IP", "Type"])
        w.writerow(["DUT (SoftAP)", dut["ip"], dut["type"]])
        for i, c in enumerate(clients):
            w.writerow([f"Client{i+1}", c["ip"], c["type"]])


# ======================================================================
# Option 5 : Edit a dependency file + scp to devices
# ======================================================================
def opt_edit_deps():
    print("\n--- Edit dependency file + scp ---")
    for i, f in enumerate(DEPS, 1):
        print(f"  {i}) {f}")
    sel = input(f"Pick file to edit (1-{len(DEPS)}): ").strip()
    try:
        fname = DEPS[int(sel) - 1]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return

    ensure_local(fname)
    editor = os.environ.get("EDITOR") or "vim"
    subprocess.call([editor, fname])

    ans = input(f"\nscp {fname} to devices now? (y/n): ").strip().lower()
    if ans != "y":
        print("Not scp'd.")
        return

    print("Select target devices (path auto: ASTRA -> /lib/firmware, VIM3 -> /build):")
    targets = ask_buckets()
    if not targets:
        print("No IPs entered; nothing scp'd.")
        return
    for t in targets:
        dest = f"{SSH_USER}@{t['ip']}:{t['path']}/"
        print(f"--> scp -r {fname} {dest}")
        out, rc = sh(f"scp -r {fname} {dest}")
        if out.strip():
            print(out)
        print("OK" if rc == 0 else f"FAILED (rc={rc})")


# ======================================================================
# Option 6 : Close all spawned terminals (keep current)
# ======================================================================
def opt_close_terminals():
    print("\n--- Close all spawned gnome-terminal windows (keeping this one) ---")
    cmd = (
        'S=$(pgrep -f gnome-terminal-server | head -1); '
        'if [ -z "$S" ]; then echo "gnome-terminal-server not found"; exit 0; fi; '
        'p=$$; K=; '
        'while [ "$p" -gt 1 ]; do '
        'pp=$(ps -o ppid= -p "$p" | tr -d " "); '
        '[ "$pp" = "$S" ] && K=$p && break; '
        'p=$pp; done; '
        'n=0; '
        'for x in $(pgrep -P "$S"); do '
        '[ "$x" = "$K" ] && continue; '
        'kill -9 "$x" 2>/dev/null && n=$((n+1)); '
        'done; '
        'echo "closed $n terminal window(s)"'
    )
    out, rc = sh(cmd)
    print(out.strip() if out.strip() else f"(done, rc={rc})")


# ======================================================================
# Option 7 : Ping test (DUT <-> clients)
# ======================================================================
def opt_ping():
    print("\n--- Ping test (DUT <-> clients) ---")
    dut, clients = ask_setup()
    if not clients:
        print("No clients entered.")
        return
    print("\nPing mode:")
    print("  1) Both directions sequentially (DUT->STA, then STA->DUT)")
    print("  2) Both directions simultaneously")
    mode = input("Choice (1/2): ").strip()
    if mode not in ("1", "2"):
        print("Invalid choice.")
        return
    _run_ping_only(dut, clients, mode)

def all_hardcoded_targets():
    return ([{"ip": f"172.16.{x}", "path": ASTRA_PATH} for x in ALL_ASTRA]
            + [{"ip": f"172.16.{x}", "path": VIM3_PATH} for x in ALL_VIM3])


def opt_push_custom():
    print("\n--- Push a custom file to devices ---")
    fname = input("Local file to push: ").strip()
    if not fname:
        print("No file given.")
        return
    if not os.path.exists(fname):
        print(f"Local file not found: {fname}")
        return
    print("\nTargets:")
    print("  1) All hardcoded devices (ASTRA + VIM3)")
    print("  2) Enter IPs manually")
    sel = input("Choice (1/2): ").strip()
    if sel == "1":
        targets = all_hardcoded_targets()
    elif sel == "2":
        raw = input("Enter IPs (space/comma separated, e.g. 172.16.1.3 172.16.1.5): ").strip()
        ips = [x for x in re.split(r"[,\s]+", raw) if x]
        if not ips:
            print("No IPs entered.")
            return
        dest = input("Destination dir on devices [/root]: ").strip() or "/root"
        targets = [{"ip": ip, "path": dest} for ip in ips]
    else:
        print("Invalid choice.")
        return
    if not targets:
        print("No targets.")
        return
    print(f"\nPushing {fname} to {len(targets)} device(s)...")
    _scp_file(fname, targets)


# ======================================================================
# Traffic / ping / results engine  (TX, RX, BD, ping, combo)
# ======================================================================
DURATION = "60"   # traffic duration fixed at 60s


def ask_channel():
    ch = input("Sniffer channel/chanspec [36/80]: ").strip()
    return ch if ch else "36/80"


def pcap_name(n, ttype, direction):
    return f"{n}{ttype}{direction}"


def compute_bw(n):
    return f"{1200 // max(1, n)}M"


def _scp_file(fname, targets):
    for t in targets:
        dest = f"{SSH_USER}@{t['ip']}:{t['path']}/"
        out, rc = sh(f"scp -r {fname} {dest}")
        print(f"  {fname} -> {t['ip']}:{t['path']}  {'OK' if rc == 0 else 'FAIL'}")


def auto_bandwidth_push(ttype, clients, script_name, targets):
    """udp/vi/vo: set -b = 1200/N in local script, scp to the given test devices only."""
    if ttype not in ("udp", "vi", "vo"):
        return
    n = len(clients)
    bval = compute_bw(n)
    ensure_local(script_name)
    if set_bandwidth(script_name, ttype, bval):
        print(f"Auto -b for {ttype}: {bval}  (1200/{n}) in {script_name}")
    else:
        print(f"WARN: could not set -b in {script_name}")
        return
    print(f"Auto-scp {script_name} to test devices ({len(targets)})...")
    _scp_file(script_name, targets)


def count_zero_intervals(filepath):
    """Count iperf interval lines whose throughput is exactly 0 Mbits/sec (a stall)."""
    try:
        lines = open(filepath).readlines()
    except FileNotFoundError:
        return 0
    cnt = 0
    for ln in lines:
        p = _extract_interval(ln)
        if p and p[3] == 0.0:
            cnt += 1
    return cnt


def detect_stalls(clients):
    """Return [(STA#, ip, role, file, zero_count)] for s/c logs with zero-Mbps intervals."""
    out = []
    for i, c in enumerate(clients):
        for role, fname in (("server", f"s{i+1}.txt"), ("client", f"c{i+1}.txt")):
            z = count_zero_intervals(fname)
            if z:
                out.append((f"STA{i+1}", c["ip"], role, fname, z))
    return out


def extract_iperf_cmd(script_file, ttype):
    """Pull the resolved iperf line for the given type from a local client/server script."""
    try:
        lines = open(script_file).readlines()
    except FileNotFoundError:
        return None
    cand = [ln.strip() for ln in lines if "iperf" in ln and "tee" in ln]
    for ln in cand:
        if ttype == "tcp" and "-u" not in ln and "-S 0x" not in ln:
            return ln
        if ttype == "udp" and "-u" in ln and "-S 0x" not in ln:
            return ln
        if ttype == "vi" and "-S 0xA0" in ln:
            return ln
        if ttype == "vo" and "-S 0xE0" in ln:
            return ln
    return None


def bd_throughput(filepath):
    try:
        lines = open(filepath).readlines()
    except FileNotFoundError:
        return None, "missing"
    cutoff = next((i for i, l in enumerate(lines) if "Server Report" in l), len(lines))
    pre = lines[:cutoff]
    # try full-duration summary line first
    for l in pre:
        if "[SUM-2]" not in l:
            continue
        p = _extract_interval(l)
        if p and p[0] < 0.5 and p[1] > 55:
            return p[3], "SUM-2"
    # fallback: average all 1-sec intervals
    rates = [_extract_interval(l)[3] for l in pre
             if "[SUM-2]" in l and _extract_interval(l)]
    if not rates:
        return None, "no SUM-2"
    return sum(rates) / len(rates), "SUM-2-avg"


def start_ping(dut, clients, direction, prefix):
    """direction d2c = DUT pings clients; c2d = clients ping DUT. Returns issued cmds."""
    issued = []
    for i, c in enumerate(clients):
        if direction == "d2c":
            cmd = f"cd {dut['path']} && ./ping.sh {c['data']} {prefix}_{i}.txt"
            host = dut["ip"]
        else:
            cmd = f"cd {c['path']} && ./ping.sh {dut['data']} {prefix}_{i}.txt"
            host = c["ip"]
        execute_command(cmd, remote_host=host, new_terminal=True,
                        terminal_name=f"{prefix}_STA{i+1}")
        issued.append(f"({host}) {cmd}")
    return issued


def fetch_ping(dut, clients, direction, prefix):
    for i, c in enumerate(clients):
        if direction == "d2c":
            fetch_file(dut["ip"], f"{dut['path']}/{prefix}_{i}.txt", f"{prefix}_{i}.txt")
        else:
            fetch_file(c["ip"], f"{c['path']}/{prefix}_{i}.txt", f"{prefix}_{i}.txt")


def gather_throughput(clients, is_bd):
    rows, total = [], 0.0
    for i, c in enumerate(clients):
        if is_bd:
            val, method = bd_throughput(f"s{i+1}.txt")
        else:
            val, method = server_throughput(f"s{i+1}.txt")
        if val is not None:
            total += val
        rssi = rssi_mid(f"rssi{i+1}.log", DURATION)
        rows.append((i + 1, c["ip"], c["type"], val, method, rssi))
    return rows, total


def gather_ping(clients, prefix):
    return [(i + 1, c["ip"], c["type"], ping_rtt(f"{prefix}_{i}.txt"))
            for i, c in enumerate(clients)]


def _next_iteration(xlsx_path="wlan_results.xlsx"):
    try:
        import openpyxl
    except ImportError:
        return 1
    if not os.path.exists(xlsx_path):
        return 1
    wb = openpyxl.load_workbook(xlsx_path)
    ws = wb["Results"] if "Results" in wb.sheetnames else wb.active
    it = 1
    for row in ws.iter_rows(values_only=True):
        if row and isinstance(row[0], str) and row[0].startswith("Iteration"):
            try:
                it = max(it, int(row[0].split()[1]) + 1)
            except (IndexError, ValueError):
                pass
    return it


# ---------------- result writers ----------------
def _fmt(v, nd):
    return (f"%.{nd}f" % v) if v is not None else "NO DATA"


def final_iperf_cmds(ttype, dut, clients, server_side, client_script, server_script):
    """Per-STA final iperf commands actually run, fully expanded (real IP/port/-b/file)."""
    ctmpl = extract_iperf_cmd(client_script, ttype)
    stmpl = extract_iperf_cmd(server_script, ttype)

    def expand(t, server_ip, port, outfile):
        if not t:
            return "(not found)"
        r = t
        for k, v in (("$SERVER_IP", server_ip), ("$PORT", port),
                     ("$DURATION", DURATION), ("$OUTPUT_FILE", outfile)):
            r = r.replace(k, v)
        return r

    rows = []
    for i, c in enumerate(clients):
        port = str(10001 + i)
        s_out, c_out = f"s{i+1}.txt", f"c{i+1}.txt"
        if server_side == "client":
            server_host, client_host, target = c["ip"], dut["ip"], c["data"]
        else:
            server_host, client_host, target = dut["ip"], c["ip"], dut["data"]
        rows.append((f"STA{i+1} {c['ip']}",
                     server_host, expand(stmpl, "", port, s_out),
                     client_host, expand(ctmpl, target, port, c_out)))
    return rows


def write_traffic_results(test, ttype, dut, clients, tput_rows, total,
                          pre_rows, dur_rows, iteration,
                          steps=None, cmds=None, server_side="client",
                          client_script="dynamic_client.sh",
                          server_script="dynamic_server.sh"):
    summary_file = f"{ttype}_{test}_traffic_summary.txt"

    def _dump(s, path):
        try:
            s.write(open(path).read())
        except FileNotFoundError:
            s.write("  (no data)\n")

    stalls = detect_stalls(clients)

    with open(summary_file, "w") as s:
        s.write(f"{test} traffic summary ({ttype}, {DURATION}s)\n")
        s.write(f"DUT (SoftAP): {dut['ip']} ({dut['type']})\n")

        # ---- ZERO STALLS (start) ----
        s.write("\n" + "=" * 60 + "\nZERO-THROUGHPUT STALLS\n" + "=" * 60 + "\n")
        if stalls:
            for (sta, ip, role, fname, z) in stalls:
                s.write(f"  [{test} {ttype}] {sta} {ip} {role} log ({fname}): "
                        f"{z} zero-Mbps interval(s)\n")
        else:
            s.write("  none\n")

        # ---- STEPS ----
        s.write("\nSTEPS:\n")
        for line in (steps or []):
            s.write(f"  {line.replace('{summary_file}', summary_file)}\n")

        # ---- COMMANDS USED ----
        s.write("\nCOMMANDS USED:\n")
        for line in (cmds or []):
            s.write(f"  {line}\n")

        # ---- FINAL IPERF (expanded, as run) ----
        s.write("\nFINAL IPERF COMMANDS (expanded, as run):\n")
        for (sta, sh_host, scmd, ch_host, ccmd) in final_iperf_cmds(
                ttype, dut, clients, server_side, client_script, server_script):
            s.write(f"  {sta}:\n")
            s.write(f"    server @{sh_host}: {scmd}\n")
            s.write(f"    client @{ch_host}: {ccmd}\n")

        # ---- parsed quick-view ----
        s.write("\n" + "=" * 60 + "\nPARSED SUMMARY\n" + "=" * 60 + "\n")
        s.write("Throughput:\n")
        for (idx, ip, typ, val, method, rssi) in tput_rows:
            s.write(f"  STA{idx} {ip} ({typ}): {_fmt(val,1)} Mbits/sec "
                    f"[{method}]  RSSI {rssi or 'NO DATA'}\n")
        s.write(f"  TOTAL: {total:.1f} Mbits/sec\n\n")
        s.write("Pre-traffic ping (avg ms, 10s):\n")
        for (idx, ip, typ, rtt) in pre_rows:
            s.write(f"  STA{idx} {ip} ({typ}): {_fmt(rtt,3)}\n")
        s.write("\nDuring-traffic ping (avg ms, 10s):\n")
        for (idx, ip, typ, rtt) in dur_rows:
            s.write(f"  STA{idx} {ip} ({typ}): {_fmt(rtt,3)}\n")

        # ---- full raw logs ----
        s.write("\n" + "=" * 60 + "\nRAW LOGS (ping + iperf)\n" + "=" * 60 + "\n")
        for i, (idx, ip, typ, *_rest) in enumerate(tput_rows):
            s.write("\n" + "-" * 60 + f"\nSTA{idx} {ip} ({typ})\n" + "-" * 60 + "\n")
            s.write("\n[Pre-traffic ping]\n"); _dump(s, f"ping_pre_{i}.txt")
            s.write("\n[iperf client log]\n"); _dump(s, f"c{i+1}.txt")
            s.write("\n[iperf server log]\n"); _dump(s, f"s{i+1}.txt")
            s.write("\n[During-traffic ping]\n"); _dump(s, f"ping_dur_{i}.txt")
    print(f"Summary -> {summary_file}")

    _excel_block(test, ttype, summary_file, iteration,
                 tput_rows=tput_rows, total=total,
                 ping_tables=[("Pre-traffic Ping (10s, ms)", pre_rows),
                              ("During-traffic Ping (10s, ms)", dur_rows)],
                 dur=DURATION, stalls=stalls)
    return (summary_file, test, ttype, stalls)


def write_ping_results(dut, clients, d2c_rows, c2d_rows, iteration,
                       steps=None, cmds=None):
    summary_file = "ping_results.txt"
    with open(summary_file, "w") as s:
        s.write(f"PING summary\nDUT (SoftAP): {dut['ip']} ({dut['type']})\n\n")

        s.write("STEPS:\n")
        for line in (steps or []):
            s.write(f"  {line.replace('{summary_file}', summary_file)}\n")
        s.write("\nCOMMANDS USED:\n")
        for line in (cmds or []):
            s.write(f"  {line}\n")

        s.write("\n" + "=" * 50 + "\nPARSED SUMMARY\n" + "=" * 50 + "\n")
        s.write("DUT -> STA (avg ms):\n")
        for (idx, ip, typ, rtt) in d2c_rows:
            s.write(f"  STA{idx} {ip} ({typ}): {_fmt(rtt,3)}\n")
        s.write("\nSTA -> DUT (avg ms):\n")
        for (idx, ip, typ, rtt) in c2d_rows:
            s.write(f"  STA{idx} {ip} ({typ}): {_fmt(rtt,3)}\n")

        s.write("\n" + "=" * 50 + "\nRAW PING OUTPUTS\n" + "=" * 50 + "\n")
        s.write("\n--- DUT -> STA ---\n")
        for i, (idx, ip, typ, rtt) in enumerate(d2c_rows):
            s.write(f"\nSTA{idx} {ip} ({typ}):\n")
            try:
                s.write(open(f"ping_d2c_{i}.txt").read())
            except FileNotFoundError:
                s.write("  (no data)\n")
        s.write("\n--- STA -> DUT ---\n")
        for i, (idx, ip, typ, rtt) in enumerate(c2d_rows):
            s.write(f"\nSTA{idx} {ip} ({typ}):\n")
            try:
                s.write(open(f"ping_c2d_{i}.txt").read())
            except FileNotFoundError:
                s.write("  (no data)\n")
    print(f"Summary -> {summary_file}")
    _excel_block("PING", "-", summary_file, iteration,
                 tput_rows=None, total=None,
                 ping_tables=[("DUT -> STA Ping (10s, ms)", d2c_rows),
                              ("STA -> DUT Ping (10s, ms)", c2d_rows)],
                 dur="10")
    return summary_file


def _excel_block(test, ttype, summary_file, iteration, tput_rows, total, ping_tables,
                 dur=DURATION, stalls=None):
    try:
        import openpyxl
        from openpyxl.styles import PatternFill, Font
    except ImportError:
        print("openpyxl not installed -> Excel skipped (pip install openpyxl)")
        return
    xlsx_path = "wlan_results.xlsx"
    if os.path.exists(xlsx_path):
        wb = openpyxl.load_workbook(xlsx_path)
        ws = wb["Results"] if "Results" in wb.sheetnames else wb.active
    else:
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Results"
    if iteration is None:
        iteration = _next_iteration(xlsx_path)
    if ws.max_row and ws.max_row > 1:
        ws.append([])

    label = TEST_NAMES.get(test, test)
    ws.append([f"Iteration {iteration} - {label}", time.strftime("%Y-%m-%d %H:%M:%S")])
    block_start = ws.max_row
    ws.append([f"Summary file: {summary_file}", f"type={ttype}", f"dur={dur}s"])
    ws.append([])

    if tput_rows is not None:
        ws.append(["Throughput (Mbits/sec)"])
        ws.append(["STA", "Throughput", "IP", "Method", "Type", "RSSI"])
        for (idx, ip, typ, val, method, rssi) in tput_rows:
            ws.append([f"STA{idx}",
                       (round(val, 1) if val is not None else "NO DATA"),
                       ip, method, typ, (rssi if rssi else "NO DATA")])
        ws.append(["TOTAL", round(total, 1), "", "", "", ""])
        ws.append([])

    for title, rows in ping_tables:
        ws.append([title])
        ws.append(["STA", "Latency", "IP", "Type"])
        for (idx, ip, typ, rtt) in rows:
            ws.append([f"STA{idx}",
                       (round(rtt, 3) if rtt is not None else "NO DATA"), ip, typ])
        ws.append([])

    ws.append(["end of block"])
    block_end = ws.max_row

    # highlight whole block; alternate tint by iteration parity
    tint = "FFF2CC" if iteration % 2 else "DDEBF7"
    fill = PatternFill("solid", fgColor=tint)
    for r in range(block_start, block_end + 1):
        for cc in range(1, 7):
            ws.cell(row=r, column=cc).fill = fill
    ws.cell(row=block_start, column=1).font = Font(bold=True)

    if stalls is not None:
        ws.append(["ZERO-THROUGHPUT STALLS"])
        if stalls:
            for (sta, ip, role, fname, z) in stalls:
                ws.append([f"  [{test} {ttype}] {sta} {ip} {role} ({fname}): {z} zero-Mbps interval(s)"])
        else:
            ws.append(["  none"])
        ws.append([])

    wb.save(xlsx_path)
    print(f"Excel: Iteration {iteration} - {test} -> {xlsx_path}")


# ---------------- core run flows ----------------
def _traffic_steps(test, ping_dir, ch):
    pdir = "DUT->STA" if ping_dir == "d2c" else "STA->DUT"
    return [
        "STEP1: Assign data-plane IPs (DUT wlan1, clients wlan0)",
        f"STEP2: Pre-traffic ping 10s ({pdir})",
        f"STEP3: Start sniffer (chanspec {ch}) ~5s before traffic",
        f"STEP4: {test} traffic 60s (iperf servers + clients) + RSSI capture",
        f"STEP5: During-traffic ping 10s ({pdir}), started 10s after traffic begins",
        "STEP6: Stop iperf; fetch iperf/ping/RSSI logs + pcap",
        "STEP7: Append all logs to {summary_file}",
    ]


def _run_traffic(test, ttype, ch, dut, clients, *, ping_dir, is_bd, server_side,
                 iteration=None):
    n = len(clients)
    client_script = "dynamic_client_bd.sh" if is_bd else "dynamic_client.sh"
    server_script = "dynamic_server_bd.sh" if is_bd else "dynamic_server.sh"
    dur = DURATION
    cmds = []
    ensure_local(client_script)
    ensure_local(server_script)

    # -b auto push -> all hardcoded lab devices
    auto_bandwidth_push(ttype, clients, client_script, all_hardcoded_targets())

    # ---- STEP1: data-plane IPs ----
    cmd = f"ifconfig wlan1 {dut['data']}"
    cmds.append(f"[STEP1 assign-ip][DUT {dut['ip']}] {cmd}")
    execute_command(cmd, remote_host=dut["ip"])
    for i, c in enumerate(clients):
        cmd = f"ifconfig wlan0 {c['data']}"
        cmds.append(f"[STEP1 assign-ip][STA{i+1} {c['ip']}] {cmd}")
        execute_command(cmd, remote_host=c["ip"])

    execute_command("killall -9 iperf", remote_host=dut["ip"])
    for c in clients:
        execute_command("killall -9 iperf", remote_host=c["ip"])

    # ---- STEP2: pre-traffic ping (10s) ----
    print("\nPre-traffic ping (10s)...")
    for x in start_ping(dut, clients, ping_dir, "ping_pre"):
        cmds.append(f"[STEP2 pre-ping] {x}")
    time.sleep(13)
    fetch_ping(dut, clients, ping_dir, "ping_pre")

    # ---- STEP3: sniffer (always), 5s before traffic ----
    pcap = pcap_name(n, ttype, test)
    cap_secs = int(dur) + 10
    cmds.append(f"[STEP3 sniffer][{SNIFFER_IP}] tshark -a duration:{cap_secs} -s 550 "
                f"-i 3 -w {PCAP_DIR}/{pcap}.pcap  (chanspec {ch})")
    start_sniffer(ch, pcap, cap_secs)
    t_sniff = time.time()
    time.sleep(5)

    # ---- STEP4: traffic ----
    if server_side == "client":
        for i, c in enumerate(clients):
            port = 10001 + i
            cmd = f"cd {c['path']} && ./{server_script} {ttype} {port} s{i+1}.txt {dur}"
            cmds.append(f"[STEP4 server][STA{i+1} {c['ip']}] {cmd}")
            execute_command(cmd, remote_host=c["ip"], new_terminal=True,
                            terminal_name=f"STA{i+1}_Server")
        for i, c in enumerate(clients):
            port = 10001 + i
            cmd = f"cd {dut['path']} && ./{client_script} {c['data']} {ttype} {port} c{i+1}.txt {dur}"
            cmds.append(f"[STEP4 iperf-client][DUT {dut['ip']}] {cmd}")
            execute_command(cmd, remote_host=dut["ip"], new_terminal=True,
                            terminal_name=f"DUT_STA{i+1}")
    else:
        for i, c in enumerate(clients):
            port = 10001 + i
            cmd = f"cd {dut['path']} && ./{server_script} {ttype} {port} s{i+1}.txt {dur}"
            cmds.append(f"[STEP4 server][DUT {dut['ip']}] {cmd}")
            execute_command(cmd, remote_host=dut["ip"], new_terminal=True,
                            terminal_name=f"STA{i+1}_Server")
        for i, c in enumerate(clients):
            port = 10001 + i
            cmd = f"cd {c['path']} && ./{client_script} {dut['data']} {ttype} {port} c{i+1}.txt {dur}"
            cmds.append(f"[STEP4 iperf-client][STA{i+1} {c['ip']}] {cmd}")
            execute_command(cmd, remote_host=c["ip"], new_terminal=True,
                            terminal_name=f"STA{i+1}_DUT")

    # RSSI on clients (bounded)
    for i, c in enumerate(clients):
        rcmd = (f"cd {c['path']} && for s in {{1..{dur}}}; do "
                f"wl -i wlan0 phy_rssi_ant; sleep 1; done | tee rssi{i+1}.log")
        cmds.append(f"[STEP4 rssi][STA{i+1} {c['ip']}] {rcmd}")
        execute_command(rcmd, remote_host=c["ip"], new_terminal=True,
                        terminal_name=f"RSSI_STA{i+1}")

    # ---- STEP5: during-traffic ping (start 10s after traffic) ----
    time.sleep(10)
    print("During-traffic ping (10s)...")
    for x in start_ping(dut, clients, ping_dir, "ping_dur"):
        cmds.append(f"[STEP5 during-ping] {x}")
    time.sleep(int(dur) - 10 + 3)

    execute_command("killall -9 iperf", remote_host=dut["ip"])
    for c in clients:
        execute_command("killall -9 iperf", remote_host=c["ip"])

    # ---- STEP6: fetch ----
    if server_side == "client":
        for i, c in enumerate(clients):
            fetch_file(c["ip"], f"{c['path']}/s{i+1}.txt", f"s{i+1}.txt")
        for i, c in enumerate(clients):
            fetch_file(dut["ip"], f"{dut['path']}/c{i+1}.txt", f"c{i+1}.txt")
    else:
        for i, c in enumerate(clients):
            fetch_file(dut["ip"], f"{dut['path']}/s{i+1}.txt", f"s{i+1}.txt")
        for i, c in enumerate(clients):
            fetch_file(c["ip"], f"{c['path']}/c{i+1}.txt", f"c{i+1}.txt")
    fetch_ping(dut, clients, ping_dir, "ping_dur")
    for i, c in enumerate(clients):
        fetch_file(c["ip"], f"{c['path']}/rssi{i+1}.log", f"rssi{i+1}.log")
    fetch_pcap(t_sniff, pcap, cap_secs)

    tput_rows, total = gather_throughput(clients, is_bd)
    pre_rows = gather_ping(clients, "ping_pre")
    dur_rows = gather_ping(clients, "ping_dur")
    steps = _traffic_steps(test, ping_dir, ch)
    return write_traffic_results(test, ttype, dut, clients, tput_rows, total,
                                 pre_rows, dur_rows, iteration,
                                 steps=steps, cmds=cmds, server_side=server_side,
                                 client_script=client_script, server_script=server_script)


def _run_ping_only(dut, clients, mode, iteration=None):
    cmds = []
    cmd = f"ifconfig wlan1 {dut['data']}"
    cmds.append(f"[STEP1 assign-ip][DUT {dut['ip']}] {cmd}")
    execute_command(cmd, remote_host=dut["ip"])
    for i, c in enumerate(clients):
        cmd = f"ifconfig wlan0 {c['data']}"
        cmds.append(f"[STEP1 assign-ip][STA{i+1} {c['ip']}] {cmd}")
        execute_command(cmd, remote_host=c["ip"])
    WAIT = 13
    if mode == "1":   # sequential
        print("Ping DUT -> STA...")
        for x in start_ping(dut, clients, "d2c", "ping_d2c"):
            cmds.append(f"[STEP2 ping d2c] {x}")
        time.sleep(WAIT)
        print("Ping STA -> DUT...")
        for x in start_ping(dut, clients, "c2d", "ping_c2d"):
            cmds.append(f"[STEP2 ping c2d] {x}")
        time.sleep(WAIT)
    else:             # simultaneous
        print("Ping both directions...")
        for x in start_ping(dut, clients, "d2c", "ping_d2c"):
            cmds.append(f"[STEP2 ping d2c] {x}")
        for x in start_ping(dut, clients, "c2d", "ping_c2d"):
            cmds.append(f"[STEP2 ping c2d] {x}")
        time.sleep(WAIT)
    fetch_ping(dut, clients, "d2c", "ping_d2c")
    fetch_ping(dut, clients, "c2d", "ping_c2d")
    modestr = "sequential" if mode == "1" else "simultaneous"
    steps = [
        "STEP1: Assign data-plane IPs (DUT wlan1, clients wlan0)",
        f"STEP2: Ping {modestr} - DUT->STA and STA->DUT, 10s each",
        "STEP3: Fetch ping logs",
        "STEP4: Append to {summary_file}",
    ]
    return write_ping_results(dut, clients,
                              gather_ping(clients, "ping_d2c"),
                              gather_ping(clients, "ping_c2d"), iteration,
                              steps=steps, cmds=cmds)


# ======================================================================
# Option 10 : VI+VO+BE+BK simultaneous traffic (DUT -> clients)
# ======================================================================
VVBB_TYPES = ["vi", "vo", "be", "bk"]


def _vvbb_port(i, typ):
    offsets = {"vi": 0, "vo": 1, "be": 2, "bk": 3}
    return 10001 + i * 4 + offsets[typ]


def opt_vi_vo_be_bk():
    print("\n--- VI+VO+BE+BK simultaneous traffic (DUT -> clients) ---")
    dut, clients = ask_setup()
    if not clients:
        print("No clients entered.")
        return
    ch = ask_channel()
    _run_vvbb(dut, clients, ch)


def _run_vvbb(dut, clients, ch, iteration=None):
    n = len(clients)
    dur = DURATION
    cmds = []
    ensure_local("dynamic_client.sh")
    ensure_local("dynamic_server.sh")

    # ---- even bandwidth split: 1200M / (n_clients * 4 types) ----
    bw = compute_bw(n * 4)
    for typ in VVBB_TYPES:
        set_bandwidth("dynamic_client.sh", typ, bw)
    print(f"VVBB bandwidth: {bw}  (1200 / ({n} clients x 4 types))")
    _scp_file("dynamic_client.sh", all_hardcoded_targets())
    _scp_file("dynamic_server.sh", all_hardcoded_targets())

    # ---- STEP1: data-plane IPs ----
    cmd = f"ifconfig wlan1 {dut['data']}"
    cmds.append(f"[STEP1 assign-ip][DUT {dut['ip']}] {cmd}")
    execute_command(cmd, remote_host=dut["ip"])
    for c in clients:
        cmd = f"ifconfig wlan0 {c['data']}"
        cmds.append(f"[STEP1 assign-ip][{c['ip']}] {cmd}")
        execute_command(cmd, remote_host=c["ip"])
    execute_command("killall -9 iperf", remote_host=dut["ip"])
    for c in clients:
        execute_command("killall -9 iperf", remote_host=c["ip"])

    # ---- STEP2: pre-traffic ping ----
    print("\nPre-traffic ping (10s)...")
    for x in start_ping(dut, clients, "d2c", "ping_pre"):
        cmds.append(f"[STEP2 pre-ping] {x}")
    time.sleep(13)
    fetch_ping(dut, clients, "d2c", "ping_pre")

    # ---- STEP3: sniffer ----
    pcap = f"{n}vvbbTX"
    cap_secs = int(dur) + 10
    cmds.append(f"[STEP3 sniffer][{SNIFFER_IP}] chanspec {ch}")
    start_sniffer(ch, pcap, cap_secs)
    t_sniff = time.time()
    time.sleep(5)

    # ---- STEP4: launch all 4 types, all clients, servers first then clients ----
    for i, c in enumerate(clients):
        for typ in VVBB_TYPES:
            port = _vvbb_port(i, typ)
            cmd = f"cd {c['path']} && ./dynamic_server.sh {typ} {port} s{i+1}_{typ}.txt {dur}"
            cmds.append(f"[STEP4 server][{c['ip']} {typ}] {cmd}")
            execute_command(cmd, remote_host=c["ip"], new_terminal=True,
                            terminal_name=f"STA{i+1}_{typ}_Server")
    for i, c in enumerate(clients):
        for typ in VVBB_TYPES:
            port = _vvbb_port(i, typ)
            cmd = f"cd {dut['path']} && ./dynamic_client.sh {c['data']} {typ} {port} c{i+1}_{typ}.txt {dur}"
            cmds.append(f"[STEP4 client][DUT->{c['ip']} {typ}] {cmd}")
            execute_command(cmd, remote_host=dut["ip"], new_terminal=True,
                            terminal_name=f"DUT_STA{i+1}_{typ}")

    # RSSI per client (one radio, covers all 4 streams)
    for i, c in enumerate(clients):
        rcmd = (f"cd {c['path']} && for s in {{1..{dur}}}; do "
                f"wl -i wlan0 phy_rssi_ant; sleep 1; done | tee rssi{i+1}.log")
        cmds.append(f"[STEP4 rssi][{c['ip']}] {rcmd}")
        execute_command(rcmd, remote_host=c["ip"], new_terminal=True,
                        terminal_name=f"RSSI_STA{i+1}")

    # ---- STEP5: during-traffic ping ----
    time.sleep(10)
    print("During-traffic ping (10s)...")
    for x in start_ping(dut, clients, "d2c", "ping_dur"):
        cmds.append(f"[STEP5 during-ping] {x}")
    time.sleep(int(dur) - 10 + 3)

    execute_command("killall -9 iperf", remote_host=dut["ip"])
    for c in clients:
        execute_command("killall -9 iperf", remote_host=c["ip"])

    # ---- STEP6: fetch everything ----
    for i, c in enumerate(clients):
        for typ in VVBB_TYPES:
            fetch_file(c["ip"], f"{c['path']}/s{i+1}_{typ}.txt", f"s{i+1}_{typ}.txt")
            fetch_file(dut["ip"], f"{dut['path']}/c{i+1}_{typ}.txt", f"c{i+1}_{typ}.txt")
    fetch_ping(dut, clients, "d2c", "ping_dur")
    for i, c in enumerate(clients):
        fetch_file(c["ip"], f"{c['path']}/rssi{i+1}.log", f"rssi{i+1}.log")
    fetch_pcap(t_sniff, pcap, cap_secs)

    # ---- gather per-client per-type throughput ----
    rows = []   # (i+1, ip, type, {vi:val, vo:val, be:val, bk:val}, {..methods..}, rssi)
    stalls = []
    total_all = 0.0
    for i, c in enumerate(clients):
        vals, methods = {}, {}
        for typ in VVBB_TYPES:
            val, method = server_throughput(f"s{i+1}_{typ}.txt")
            vals[typ] = val
            methods[typ] = method
            if val is not None:
                total_all += val
            z = count_zero_intervals(f"s{i+1}_{typ}.txt")
            if z:
                stalls.append((f"STA{i+1}", c["ip"], f"server-{typ}", f"s{i+1}_{typ}.txt", z))
            z2 = count_zero_intervals(f"c{i+1}_{typ}.txt")
            if z2:
                stalls.append((f"STA{i+1}", c["ip"], f"client-{typ}", f"c{i+1}_{typ}.txt", z2))
        rssi = rssi_mid(f"rssi{i+1}.log", dur)
        rows.append((i + 1, c["ip"], c["type"], vals, methods, rssi))
    pre_rows = gather_ping(clients, "ping_pre")
    dur_rows = gather_ping(clients, "ping_dur")

    write_vvbb_results(dut, clients, rows, total_all, pre_rows, dur_rows,
                       stalls, cmds, bw, iteration)


def write_vvbb_results(dut, clients, rows, total_all, pre_rows, dur_rows,
                       stalls, cmds, bw, iteration):
    summary_file = "VVBB_traffic_summary.txt"
    with open(summary_file, "w") as s:
        s.write(f"VI+VO+BE+BK simultaneous traffic summary ({DURATION}s, bw={bw}/stream)\n")
        s.write(f"DUT (SoftAP): {dut['ip']} ({dut['type']})\n")

        s.write("\n" + "=" * 60 + "\nZERO-THROUGHPUT STALLS\n" + "=" * 60 + "\n")
        if stalls:
            for (sta, ip, role, fname, z) in stalls:
                s.write(f"  {sta} {ip} {role} log ({fname}): {z} zero-Mbps interval(s)\n")
        else:
            s.write("  none\n")

        s.write("\nCOMMANDS USED:\n")
        for line in cmds:
            s.write(f"  {line}\n")

        s.write("\n" + "=" * 60 + "\nPARSED SUMMARY\n" + "=" * 60 + "\n")
        for (idx, ip, typ, vals, methods, rssi) in rows:
            s.write(f"  STA{idx} {ip} ({typ}):\n")
            for t in VVBB_TYPES:
                s.write(f"    {t.upper()}: {_fmt(vals[t],1)} Mbits/sec [{methods[t]}]\n")
            s.write(f"    RSSI: {rssi or 'NO DATA'}\n")
        s.write(f"\n  TOTAL (all STAs, all types): {total_all:.1f} Mbits/sec\n")

        s.write("\nPre-traffic ping (avg ms, 10s):\n")
        for (idx, ip, typ, rtt) in pre_rows:
            s.write(f"  STA{idx} {ip} ({typ}): {_fmt(rtt,3)}\n")
        s.write("\nDuring-traffic ping (avg ms, 10s):\n")
        for (idx, ip, typ, rtt) in dur_rows:
            s.write(f"  STA{idx} {ip} ({typ}): {_fmt(rtt,3)}\n")
    print(f"Summary -> {summary_file}")

    # ---- Excel ----
    try:
        import openpyxl
        from openpyxl.styles import PatternFill, Font
    except ImportError:
        print("openpyxl not installed -> Excel skipped")
        return
    xlsx_path = "wlan_results.xlsx"
    if os.path.exists(xlsx_path):
        wb = openpyxl.load_workbook(xlsx_path)
        ws = wb["Results"] if "Results" in wb.sheetnames else wb.active
    else:
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Results"
    if iteration is None:
        iteration = _next_iteration(xlsx_path)
    if ws.max_row and ws.max_row > 1:
        ws.append([])

    ws.append([f"Iteration {iteration} - VI+VO+BE+BK simultaneous (DUT->clients)",
               time.strftime("%Y-%m-%d %H:%M:%S")])
    block_start = ws.max_row
    ws.append([f"Summary file: {summary_file}", f"bw={bw}", f"dur={DURATION}s"])
    ws.append([])
    ws.append(["STA", "IP", "Type", "VI Mbps", "VO Mbps", "BE Mbps", "BK Mbps", "RSSI"])
    for (idx, ip, typ, vals, methods, rssi) in rows:
        ws.append([f"STA{idx}", ip, typ,
                   round(vals["vi"], 1) if vals["vi"] is not None else "NO DATA",
                   round(vals["vo"], 1) if vals["vo"] is not None else "NO DATA",
                   round(vals["be"], 1) if vals["be"] is not None else "NO DATA",
                   round(vals["bk"], 1) if vals["bk"] is not None else "NO DATA",
                   rssi or "NO DATA"])
    ws.append(["TOTAL (all types)", "", "", "", "", "", round(total_all, 1), ""])
    ws.append([])

    ws.append(["Pre-traffic Ping (10s, ms)"])
    ws.append(["STA", "Latency", "IP", "Type"])
    for (idx, ip, typ, rtt) in pre_rows:
        ws.append([f"STA{idx}", round(rtt,3) if rtt is not None else "NO DATA", ip, typ])
    ws.append([])
    ws.append(["During-traffic Ping (10s, ms)"])
    ws.append(["STA", "Latency", "IP", "Type"])
    for (idx, ip, typ, rtt) in dur_rows:
        ws.append([f"STA{idx}", round(rtt,3) if rtt is not None else "NO DATA", ip, typ])
    ws.append([])

    if stalls:
        ws.append(["ZERO-THROUGHPUT STALLS"])
        for (sta, ip, role, fname, z) in stalls:
            ws.append([f"  {sta} {ip} {role} ({fname}): {z} zero-Mbps interval(s)"])
        ws.append([])

    ws.append(["end of block"])
    block_end = ws.max_row
    tint = "FFF2CC" if iteration % 2 else "DDEBF7"
    fill = PatternFill("solid", fgColor=tint)
    for r in range(block_start, block_end + 1):
        for cc in range(1, 9):
            ws.cell(row=r, column=cc).fill = fill
    ws.cell(row=block_start, column=1).font = Font(bold=True)

    wb.save(xlsx_path)
    print(f"Excel: Iteration {iteration} - VVBB -> {xlsx_path}")

# ---------------- option entry points ----------------
def opt_bd():
    print("\n--- Bidirectional traffic (DUT <-> clients) ---")
    dut, clients = ask_setup()
    if not clients:
        print("No clients entered.")
        return
    ttype = ask_traffic()
    ch = ask_channel()
    _run_traffic("BD", ttype, ch, dut, clients,
                 ping_dir="d2c", is_bd=True, server_side="client")


def opt_combo():
    print("\n--- Combo: Ping + TX + RX + BD (one iteration) ---")
    dut, clients = ask_setup()
    if not clients:
        print("No clients entered.")
        return
    ttype = ask_traffic()
    ch = ask_channel()
    it = _next_iteration()
    print(f"\n[Combo iteration {it}] running PING, TX, RX, BD\n")
    ping_file = _run_ping_only(dut, clients, mode="2", iteration=it)
    results = []
    results.append(_run_traffic("TX", ttype, ch, dut, clients,
                   ping_dir="d2c", is_bd=False, server_side="client", iteration=it))
    opt_close_terminals()
    results.append(_run_traffic("RX", ttype, ch, dut, clients,
                   ping_dir="c2d", is_bd=False, server_side="dut", iteration=it))
    opt_close_terminals()
    results.append(_run_traffic("BD", ttype, ch, dut, clients,
                   ping_dir="d2c", is_bd=True, server_side="client", iteration=it))
    _write_combo_summary(it, dut, ttype, ping_file, results)
    opt_close_terminals()


def _write_combo_summary(iteration, dut, ttype, ping_file, results):
    combo_file = f"combo_iter{iteration}_summary.txt"
    with open(combo_file, "w") as s:
        s.write("=" * 60 + f"\nCOMBO SUMMARY - Iteration {iteration}\n" + "=" * 60 + "\n")
        s.write(f"DUT (SoftAP): {dut['ip']} ({dut['type']})  type={ttype}\n")
        s.write("Order: PING -> TX -> RX -> BD\n\n")
        # zero stalls at TOP, tagged with test type + which server/client log
        s.write("ZERO-THROUGHPUT STALLS (all traffic tests):\n")
        any_stall = False
        for (sfile, test, tt, stalls) in results:
            for (sta, ip, role, fname, z) in stalls:
                any_stall = True
                s.write(f"  [{test} {tt}] {sta} {ip} {role} log ({fname}): "
                        f"{z} zero-Mbps interval(s)\n")
        if not any_stall:
            s.write("  none\n")
        # concatenate each sub-test summary file (already has steps+cmds+raw logs)
        sections = [("PING", ping_file)] + [(test, sfile)
                                            for (sfile, test, tt, stalls) in results]
        for (label, fpath) in sections:
            s.write("\n" + "#" * 60 + f"\n# {label} section  ({fpath})\n" + "#" * 60 + "\n\n")
            try:
                s.write(open(fpath).read())
            except FileNotFoundError:
                s.write("  (no data)\n")
            s.write("\n")
    print(f"Combo summary -> {combo_file}")

# ======================================================================
# Option 8 : Memuse stress check (deauth + rejoin, SoftAP memuse tracking)
# ======================================================================
MEMUSE_DUT_IP   = SOFTAP_XX                  # 1.4, from global SoftAP constant
MEMUSE_DUT_PATH = SOFTAP_PATH

def _memuse_client_ips():
    """All hardcoded client IPs (ASTRA+VIM3), excluding the DUT (1.4)."""
    ips = []
    for xx in ALL_ASTRA + ALL_VIM3:
        if xx == MEMUSE_DUT_IP:
            continue
        path = ASTRA_PATH if xx in ALL_ASTRA else VIM3_PATH
        ips.append({"xx": xx, "ip": f"172.16.{xx}", "path": path})
    return ips


def _collect_memuse(dut_ip, dut_path, logfile, tag):
    """Append a tagged 'wl memuse' block from SoftAP into logfile."""
    print(f"\n--- {tag} (SoftAP {dut_ip}) ---")
    cmd = f"cd {dut_path} && wl -i wlan1 memuse"
    out, _, _, _ = execute_command(cmd, remote_host=dut_ip)
    with open(logfile, "a") as f:
        f.write("\n" + "=" * 60 + "\n")
        f.write(f"[{tag}]  {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"CMD: wl -i wlan1 memuse  (on SoftAP {dut_ip})\n")
        f.write("=" * 60 + "\n")
        f.write((out or "").strip() + "\n")
    print(f"memuse collected -> [{tag}]")
    return (out or "").strip() 


def _get_ap_bssid(dut_ip, dut_path):
    """Fetch SoftAP BSSID from DUT wlan1. Same BSSID for all clients."""
    cmd = f"cd {dut_path} && wl -i wlan1 status | grep BSSID"
    out, _, _, _ = execute_command(cmd + ", dp", remote_host=dut_ip)
    m = re.search(r'BSSID:\s*([0-9a-fA-F:]{17})', out or "")
    return m.group(1) if m else None


def _is_associated(host, path):
    """Run 'wl -i wlan0 status' on a client; True if it returns real status."""
    cmd = f"cd {path} && wl -i wlan0 status"
    out, _, _, _ = execute_command(cmd + ", dp", remote_host=host)
    return bool(out and "BSSID" in out)


def _wpa_status(host, path):
    """Return (rejoined_bool, raw_output). Rejoined if 'BSSID' present in wl status."""
    cmd = f"cd {path} && wl -i wlan0 status"
    out, _, _, _ = execute_command(cmd + ", dp", remote_host=host)
    out = out or ""
    return ("BSSID" in out), out

# ======================================================================
# Option 9 : Memuse stress check for N iterations (deauth + rejoin)
# ======================================================================
MEMUSE_REJOIN_TIMEOUT = 15   # seconds to wait for BSSID per deauthed STA
MEMUSE_SSH_TIMEOUT    = 7    # seconds; SSH timeout = device crash


def _all_clients():
    """All hardcoded clients (ASTRA+VIM3), excluding SoftAP 1.4."""
    out = []
    for xx in ALL_ASTRA + ALL_VIM3:
        if xx == SOFTAP_XX:
            continue
        path = ASTRA_PATH if xx in ALL_ASTRA else VIM3_PATH
        out.append({"xx": xx, "ip": f"172.16.{xx}", "path": path,
                    "data": f"192.168.{xx}",
                    "type": "ASTRA" if xx in ALL_ASTRA else "VIM3"})
    return out


def _client_cmd(host, path, wlcmd):
    """Direct SSH to a client with 7s timeout.
    Returns (out, crashed). crashed=True means SSH timed out (device dead)."""
    cmd = f"cd {path} && {wlcmd}"
    out, _, _, timed_out = execute_command(cmd + ", dp", remote_host=host,
                                           timeout=MEMUSE_SSH_TIMEOUT)
    return (out or ""), bool(timed_out)


def _softap_alive():
    """Ping SoftAP mgmt IP from TM. False => SoftAP crashed => abort test."""
    out, rc = sh(f"ping -c 2 -W 3 {SOFTAP_IP}")
    return rc == 0 and "0 received" not in out


def _dut_ping_client(dut_ip, data_ip):
    """DUT -> client ping (ping -c 2) over SSH-to-DUT. Returns True if reachable."""
    remote = f"ping -c 2 {data_ip}"
    out, _, _, _ = execute_command(f"ssh {SSH_USER}@{dut_ip} '{remote}'",
                                   remote_host=None, timeout=MEMUSE_SSH_TIMEOUT)
    out = out or ""
    if not out.strip() or "0 received" in out or " 0 packets received" in out:
        return False
    return True

def _arp_update_client(dut_ip, dut_path, data_ip, logfile):
    """On SoftAP: arping + ping to refresh ARP, verify via arp -an. One retry.
    Returns (ok_bool, log_text)."""
    def _run_once():
        block = []
        for c in (f"arping -U -I wlan1 {data_ip} -c 2",
                  f"ping -c 2 {data_ip}",
                  f"arp -an | grep {data_ip}"):
            remote = f"cd {dut_path} && {c}"
            out, _, _, _ = execute_command(f"ssh {SSH_USER}@{dut_ip} '{remote}'" + ", dp",
                                           remote_host=None, timeout=MEMUSE_SSH_TIMEOUT)
            out = out or ""
            block.append(f"$ {c}\n{out.strip() or '(no output)'}\n")
        arp_out = block[-1]
        # OK only if the IP line has a real MAC (not <incomplete>)
        ok = False
        for ln in arp_out.splitlines():
            if data_ip in ln and "incomplete" not in ln.lower():
                if re.search(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', ln):
                    ok = True
                    break
        return ok, "".join(block)

    ok, txt1 = _run_once()
    full = "--- ARP attempt 1 ---\n" + txt1
    if not ok:
        ok, txt2 = _run_once()
        full += "--- ARP attempt 2 (retry) ---\n" + txt2

    with open(logfile, "a") as f:
        f.write("\n" + "-" * 60 + f"\nARP UPDATE {data_ip}  -> {'OK' if ok else 'FAIL'}\n"
                + "-" * 60 + "\n")
        f.write(full)
    return ok, full


def _parse_memuse(text):
    """Pull 'Malloc failure count:' and 'Free:' lines from a memuse block.
    Returns (malloc_line, free_line, malloc_value_int)."""
    malloc_line, free_line, malloc_val = "NO DATA", "NO DATA", None
    for ln in (text or "").splitlines():
        s = ln.strip()
        if s.startswith("Malloc failure count:"):
            malloc_line = s
            m = re.search(r'Malloc failure count:\s*(\d+)', s)
            if m:
                malloc_val = int(m.group(1))
        elif s.startswith("Free:"):
            free_line = s
    return malloc_line, free_line, malloc_val

def _memuse_n_excel(xlsx_path, it, all_dev, available, unavailable, crashed,
                    not_rejoin, ap_bssid, picked, rejoined,
                    m1, m2, m3, ping_rows, retry_rows, arp_fail_ips=None):
    """One compact block per iteration; sheet split every 100 iterations."""
    try:
        import openpyxl
        from openpyxl.styles import PatternFill, Font
    except ImportError:
        print("openpyxl not installed -> Excel skipped (pip install openpyxl)")
        return

    sheet_name = f"Iter_{((it - 1) // 100) * 100 + 1}-{((it - 1) // 100) * 100 + 100}"

    if os.path.exists(xlsx_path):
        wb = openpyxl.load_workbook(xlsx_path)
    else:
        wb = openpyxl.Workbook()
        wb.active.title = sheet_name
    ws = wb[sheet_name] if sheet_name in wb.sheetnames else wb.create_sheet(sheet_name)
    # drop the default empty "Sheet" if present and unused
    if "Sheet" in wb.sheetnames and wb["Sheet"].max_row == 1 and ws.title != "Sheet":
        del wb["Sheet"]

    if ws.max_row and ws.max_row > 1:
        ws.append([])

    picked_ips   = {c["ip"] for c in picked}
    rejoined_ips = {c["ip"] for c in rejoined}
    notrej_ips   = {c["ip"] for c in not_rejoin}

    n_astra = sum(1 for c in all_dev if c["type"] == "ASTRA")
    n_vim3  = sum(1 for c in all_dev if c["type"] == "VIM3")

    ws.append([f"Iteration {it}", time.strftime("%Y-%m-%d %H:%M:%S")])
    block_start = ws.max_row
    ws.append([f"Devices ({len(all_dev)}): ASTRA x{n_astra}, VIM3 x{n_vim3}"])
    ws.append([f"Available: {len(available)}",
               f"Unavailable: {len(unavailable)}",
               f"Device Crash: {len(crashed)}",
               f"Rejoin-not-detected: {len(not_rejoin)}"])
    if unavailable:
        ws.append(["Unavailable this iter:", ", ".join(c["ip"] for c in unavailable)])
    if crashed:
        ws.append(["Device Crash (excluded):", ", ".join(sorted(crashed))])
    if not_rejoin:
        ws.append(["Rejoin not detected:", ", ".join(c["ip"] for c in not_rejoin)])
    ws.append([f"AP_BSSID: {ap_bssid}"])
    ws.append([f"Deauthed ({len(picked)}):", ", ".join(c["ip"] for c in picked)])
    ws.append([f"wl status: {len(rejoined)}/{len(picked)} rejoined"])
    if arp_fail_ips:
        ws.append(["ARP update:", f"FAIL for {', '.join(arp_fail_ips)}"])
    else:
        ws.append(["ARP update:", "done (all rejoined clients)"])
    ws.append([])

    # memuse #1 + #2 (compact: Malloc + Free lines)
    for tag, mtext in (("MEMUSE #1 before deauth", m1),
                       ("MEMUSE #2 after deauth", m2)):
        ml, fl, _ = _parse_memuse(mtext)
        ws.append([tag, ml, fl])

    ws.append([])
    ws.append(["Post-rejoin ping", "Client IP", "Latency (ms)", "Packet summary"])
    for (ip, lat, pkt) in ping_rows:
        ws.append(["", ip, lat, pkt])

    ws.append([])
    ml3, fl3, _ = _parse_memuse(m3)
    ws.append(["MEMUSE #3 after rejoin", ml3, fl3])

    if retry_rows:
        ws.append([])
        ws.append(["Ping RETRY (failed)", "Client IP", "Result", "Latency (ms)", "Packet summary"])
        for (ip, result, lat, pkt) in retry_rows:
            ws.append(["", ip, result, lat, pkt])

    ws.append(["end of block"])
    block_end = ws.max_row

    tint = "FFF2CC" if it % 2 else "DDEBF7"
    fill = PatternFill("solid", fgColor=tint)
    for r in range(block_start, block_end + 1):
        for cc in range(1, 6):
            ws.cell(row=r, column=cc).fill = fill
    ws.cell(row=block_start, column=1).font = Font(bold=True)

    wb.save(xlsx_path)
    print(f"Excel: Iteration {it} -> {sheet_name}")

def opt_memuse_stress_n():
    print("\n--- Memuse stress check for N iterations (deauth + rejoin) ---")
    dut_ip   = SOFTAP_IP
    dut_path = SOFTAP_PATH
    dut = {"ip": dut_ip, "path": dut_path, "data": SOFTAP_DATA}
    print(f"SoftAP (DUT) = {dut_ip} (wlan1 {SOFTAP_DATA}) [fixed]")

    # ---- ask k + N once ----
    all_dev = _all_clients()
    while True:
        try:
            k = int(input(f"How many STAs to deauth per iteration (1-{len(all_dev)}): ").strip())
            if 1 <= k <= len(all_dev):
                break
        except ValueError:
            pass
        print(f"  enter 1..{len(all_dev)}")
    while True:
        try:
            N = int(input("How many iterations: ").strip())
            if N >= 1:
                break
        except ValueError:
            pass
        print("  enter a positive integer")

    # ---- output folder + files (auto-increment RunN, never overwrite) ----
    run = 1
    while os.path.exists(f"memuse_logs_{N}_iterations_{k}STAs_Run{run}"):
        run += 1
    folder = f"memuse_logs_{N}_iterations_{k}STAs_Run{run}"
    os.makedirs(folder)          # no exist_ok -> guaranteed fresh
    print(f"Output folder: {folder}")
    xlsx_path    = os.path.join(folder, "memuse_stress_Niter.xlsx")
    summary_path = os.path.join(folder, f"{N}_Itr_summary.txt")
    with open(summary_path, "w") as f:
        f.write("#" * 60 + "\n")
        f.write(f"MEMUSE STRESS - {N} ITERATIONS   k={k}\n")
        f.write(f"SoftAP: {dut_ip}   start {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("#" * 60 + "\n")
        f.flush()

    crashed = set()          # ip -> permanently excluded (SSH timeout)
    malloc_hits = []         # (iter, malloc_value) where value != 0
    completed = 0

    for it in range(1, N + 1):
        print("\n" + "#" * 60)
        print(f"ITERATION {it}/{N}")
        print("#" * 60)

        logfile = os.path.join(folder, f"memuse_iter{it}.log")
        with open(logfile, "w") as f:
            f.write("#" * 60 + f"\nMEMUSE ITERATION {it}/{N}\n" + "#" * 60 + "\n")
            f.write(f"SoftAP: {dut_ip}   {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

        # ---- SoftAP alive check (abort if dead) ----
        if not _softap_alive():
            print(f"SoftAP {dut_ip} not responding -> ABORT")
            with open(logfile, "a") as f:
                f.write(f"\nABORT: SoftAP {dut_ip} ping failed (device crashed)\n")
            _abort_summary(summary_path, it - 1, completed, malloc_hits,
                           reason=f"SoftAP {dut_ip} crashed at iteration {it}")
            return

        # ---- discovery: associated? crash? (direct SSH, 7s) ----
        available, unavailable = [], []
        for c in all_dev:
            if c["ip"] in crashed:
                continue
            out, crash = _client_cmd(c["ip"], c["path"], "wl -i wlan0 status")
            if crash:
                crashed.add(c["ip"])
                print(f"  DEVICE CRASH (SSH timeout): {c['ip']}")
                continue
            if "BSSID" in out:
                available.append(c)
            else:
                unavailable.append(c)   # temp: responded, not associated

        print(f"available={len(available)} unavailable={len(unavailable)} "
              f"crashed={len(crashed)}")

        # ---- pre-ping (DUT->client ping -c 2); fail => unavailable this iter ----
        still_avail = []
        for c in available:
            if _dut_ping_client(dut_ip, c["data"]):
                still_avail.append(c)
            else:
                unavailable.append(c)
                print(f"  PRE-PING FAIL (unavailable this iter): {c['ip']}")
        available = still_avail

        with open(logfile, "a") as f:
            f.write(f"\nAvailable ({len(available)}): "
                    f"{', '.join(c['ip'] for c in available)}\n")
            f.write(f"Unavailable ({len(unavailable)}): "
                    f"{', '.join(c['ip'] for c in unavailable)}\n")
            f.write(f"Device Crash ({len(crashed)}): {', '.join(sorted(crashed))}\n")

        # ---- ABORT FLOOR: available < k ----
        if len(available) < k:
            print(f"Available {len(available)} < k={k} -> ABORT")
            with open(logfile, "a") as f:
                f.write(f"\nABORT: available {len(available)} < k {k}\n")
            _abort_summary(summary_path, it - 1, completed, malloc_hits,
                           reason=f"available {len(available)} < k {k} at iteration {it}")
            return

        # ---- MEMUSE #1 ----
        m1 = _collect_memuse(dut_ip, dut_path, logfile, "MEMUSE #1 - before deauth")

        # ---- AP_BSSID ----
        ap_bssid = _get_ap_bssid(dut_ip, dut_path)
        if not ap_bssid:
            print("Could not fetch AP_BSSID -> skipping iteration")
            with open(logfile, "a") as f:
                f.write("\nAP_BSSID fetch failed; iteration skipped\n")
            continue
        print(f"AP_BSSID = {ap_bssid}")

        # ---- deauth k random available ----
        picked = random.sample(available, k)
        with open(logfile, "a") as f:
            f.write(f"\nAP_BSSID: {ap_bssid}\nDEAUTH on {k} STA(s):\n")
            for c in picked:
                f.write(f"  {c['ip']}\n")
        print(f"Deauthing {k} STA(s)...")
        for c in picked:
            out, crash = _client_cmd(c["ip"], c["path"],
                                     f"wl -i wlan0 deauthenticate {ap_bssid}")
            if crash:
                crashed.add(c["ip"])
                print(f"  DEVICE CRASH on deauth: {c['ip']}")
            else:
                print(f"  deauthed: {c['ip']}")

        # ---- MEMUSE #2 ----
        m2 = _collect_memuse(dut_ip, dut_path, logfile, "MEMUSE #2 - after deauth")

        # ---- rejoin wait: 15s per STA; BSSID=rejoined, timeout=crash,
        #      responds-no-BSSID after 15s = rejoin-not-detected (temp) ----
        print("Waiting for rejoin (wl -i wlan0 status, BSSID, 15s cap)...")
        rejoined, not_rejoin = [], []
        for c in picked:
            if c["ip"] in crashed:
                continue
            t0 = time.time()
            done = False
            while time.time() - t0 < MEMUSE_REJOIN_TIMEOUT:
                out, crash = _client_cmd(c["ip"], c["path"], "wl -i wlan0 status")
                if crash:
                    crashed.add(c["ip"])
                    print(f"  DEVICE CRASH during rejoin: {c['ip']}")
                    done = True
                    break
                if "BSSID" in out:
                    rejoined.append(c)
                    print(f"  rejoined: {c['ip']}")
                    done = True
                    break
                time.sleep(2)
            if not done and c["ip"] not in crashed:
                not_rejoin.append(c)   # temp: back next iteration
                print(f"  rejoin NOT detected (15s): {c['ip']}")

        with open(logfile, "a") as f:
            f.write(f"\nRejoined ({len(rejoined)}): "
                    f"{', '.join(c['ip'] for c in rejoined)}\n")
            f.write(f"Rejoin-not-detected ({len(not_rejoin)}): "
                    f"{', '.join(c['ip'] for c in not_rejoin)}\n")

        # ---- ARP update (sequential) on each rejoined client, before post-rejoin ping ----
        arp_fail_ips = []   # data IPs where arp add failed after retry
        if rejoined:
            print("ARP update (arping + ping + verify) on rejoined clients...")
            with open(logfile, "a") as f:
                f.write("\n" + "=" * 60 + "\nARP TABLE UPDATE (SoftAP, sequential)\n" + "=" * 60 + "\n")
            for c in rejoined:
                ok, _ = _arp_update_client(dut_ip, dut_path, c["data"], logfile)
                print(f"  arp {'OK' if ok else 'FAIL'}: {c['ip']} ({c['data']})")
                if not ok:
                    arp_fail_ips.append(c["data"])

        # ---- post-rejoin ping (terminals, parallel) on rejoined only ----
        ping_rows = []
        if rejoined:
            print("Post-rejoin ping (terminals)...")
            start_ping(dut, rejoined, "d2c", "ping_rejoin")
            time.sleep(13)
            fetch_ping(dut, rejoined, "d2c", "ping_rejoin")
            with open(logfile, "a") as f:
                f.write("\n" + "=" * 60 + "\nPOST-REJOIN PING\n" + "=" * 60 + "\n")
            for i, c in enumerate(rejoined):
                try:
                    out = open(f"ping_rejoin_{i}.txt").read()
                except FileNotFoundError:
                    out = ""
                mm = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', out)
                lat = mm.group(1) if mm else "NO DATA"
                pm = re.search(r'(\d+ packets transmitted,.*)', out)
                pkt = pm.group(1).strip() if pm else "NO DATA"
                ping_rows.append((c["data"], lat, pkt))
                with open(logfile, "a") as f:
                    f.write(f"\n--- DUT -> {c['ip']} ({c['data']})  avg={lat} ms ---\n")
                    f.write((out or "  (no output)").strip() + "\n")

        # ---- MEMUSE #3 ----
        # ---- 5s settle, close terminals, then MEMUSE #3 ----
        print("Waiting 5s before final memuse collect...")
        time.sleep(5)
        opt_close_terminals()
        m3 = _collect_memuse(dut_ip, dut_path, logfile, "MEMUSE #3 - after rejoin")

        # ---- retry failed pings (one retry) ----
        failed = [c for (c, (ip, lat, pkt)) in zip(rejoined, ping_rows)
                  if lat == "NO DATA"]
        retry_rows = []
        if failed:
            print(f"Retrying ping for {len(failed)} failed client(s)...")
            start_ping(dut, failed, "d2c", "ping_retry")
            time.sleep(13)
            fetch_ping(dut, failed, "d2c", "ping_retry")
            with open(logfile, "a") as f:
                f.write("\n" + "=" * 60 + "\nPING RETRY\n" + "=" * 60 + "\n")
            for i, c in enumerate(failed):
                try:
                    out = open(f"ping_retry_{i}.txt").read()
                except FileNotFoundError:
                    out = ""
                mm = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', out)
                lat = mm.group(1) if mm else "NO DATA"
                pm = re.search(r'(\d+ packets transmitted,.*)', out)
                pkt = pm.group(1).strip() if pm else "NO DATA"
                result = "PASS" if lat != "NO DATA" else "FAIL"
                retry_rows.append((c["data"], result, lat, pkt))
                print(f"  retry {result}: {c['ip']}")
                with open(logfile, "a") as f:
                    f.write(f"\n--- RETRY {c['ip']} ({c['data']}) {result} avg={lat} ---\n")
                    f.write((out or "  (no output)").strip() + "\n")
                opt_close_terminals()
                

        # ---- count post-rejoin ping fails (after retry) ----
        # a client counts as failed if first ping was NO DATA AND retry didn't pass
        retry_pass_ips = {ip for (ip, r, _, _) in retry_rows if r == "PASS"}
        ping_fail = sum(1 for (ip, lat, pkt) in ping_rows
                        if lat == "NO DATA" and ip not in retry_pass_ips)

        # ---- MEMUSE #3 malloc/free for summary ----
        ml3, fl3, mval3 = _parse_memuse(m3)
        if mval3 is not None and mval3 != 0:
            malloc_hits.append((it, mval3))

        # ---- live summary append+flush ----
        with open(summary_path, "a") as f:
            f.write("=" * 60 + "\n")
            f.write(f"Iteration {it} ({len(available)}/{len(all_dev)} clients)\n")
            if arp_fail_ips:
                f.write(f"  arp add fail for {', '.join(arp_fail_ips)}\n")
            else:
                f.write(f"  arp add done\n")
            f.write(f"  Clients failed to ping (post-rejoin): {ping_fail}\n")
            if ping_fail and arp_fail_ips:
                f.write(f"    note: ping failures may be due to arp add fail "
                        f"({', '.join(arp_fail_ips)})\n")
            f.write(f"  MEMUSE #3: {ml3}\n")
            f.write(f"  MEMUSE #3: {fl3}\n")
            if crashed:
                f.write(f"  Device Crash so far: {', '.join(sorted(crashed))}\n")
            if not_rejoin:
                f.write(f"  Rejoin-not-detected: "
                        f"{', '.join(c['ip'] for c in not_rejoin)}\n")
            f.write("=" * 60 + "\n")
            f.flush()

        # ---- Excel block ----
        _memuse_n_excel(xlsx_path, it, all_dev, available, unavailable, crashed,
                        not_rejoin, ap_bssid, picked, rejoined,
                        m1, m2, m3, ping_rows, retry_rows, arp_fail_ips=arp_fail_ips)

        completed = it

        # # ---- close spawned terminals each iteration ----
        # opt_close_terminals()

    # ---- final summary (all N done) ----
    _abort_summary(summary_path, N, completed, malloc_hits,
                   reason=f"completed all {N} iterations")
    print(f"\nDone. {completed} iterations. Logs -> {folder}/")


def _abort_summary(summary_path, ran, completed, malloc_hits, reason):
    """Write the final/abort tail to the summary file."""
    with open(summary_path, "a") as f:
        f.write("\n" + "#" * 60 + "\nFINAL SUMMARY\n" + "#" * 60 + "\n")
        f.write(f"  Reason        : {reason}\n")
        f.write(f"  Iterations run: {completed}\n")
        if malloc_hits:
            f.write(f"  Malloc failures (count != 0):\n")
            for (it, val) in malloc_hits:
                f.write(f"    ITR{it}_MALLOC: {val}\n")
        else:
            f.write(f"  Malloc failures: none (all 0)\n")
        f.flush()
    print(f"\nSummary -> {summary_path}")
    if malloc_hits:
        print("Malloc failures:")
        for (it, val) in malloc_hits:
            print(f"  ITR{it}_MALLOC: {val}")

#########

def _memuse_excel(dut_ip, ap_bssid, assoc, picked, rejoined, wpa_out,
                  memuse_caps=None, ping_rows=None, retry_rows=None, iteration=None):
    """Write a memuse-stress summary block into wlan_results.xlsx."""
    try:
        import openpyxl
        from openpyxl.styles import PatternFill, Font
    except ImportError:
        print("openpyxl not installed -> Excel skipped (pip install openpyxl)")
        return
    xlsx_path = "wlan_results.xlsx"
    if os.path.exists(xlsx_path):
        wb = openpyxl.load_workbook(xlsx_path)
        ws = wb["Results"] if "Results" in wb.sheetnames else wb.active
    else:
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Results"
    if iteration is None:
        iteration = _next_iteration(xlsx_path)
    if ws.max_row and ws.max_row > 1:
        ws.append([])

    picked_ips   = {c["ip"] for c in picked}
    rejoined_ips = {c["ip"] for c in rejoined}

    ws.append([f"Iteration {iteration} - Memuse Stress Check",
               time.strftime("%Y-%m-%d %H:%M:%S")])
    block_start = ws.max_row
    ws.append([f"DUT SoftAP: {dut_ip} (wlan1)", f"AP_BSSID={ap_bssid}"])
    ws.append([f"Associated={len(assoc)}",
               f"Deauthed={len(picked)}",
               f"Rejoined={len(rejoined)}"])
    ws.append([])

    ws.append(["STA", "IP", "Type", "Deauthed?", "Rejoined?"])
    for i, c in enumerate(assoc, 1):
        deauthed = "YES" if c["ip"] in picked_ips else "-"
        if c["ip"] in picked_ips:
            rej = "YES" if c["ip"] in rejoined_ips else "NO"
        else:
            rej = "-"
        typ = "ASTRA" if c["xx"] in ALL_ASTRA else "VIM3"
        ws.append([f"STA{i}", c["ip"], typ, deauthed, rej])

    if memuse_caps:
            ws.append([])
            ws.append(["MEMUSE OUTPUTS (line by line)"])
            for tag, text in memuse_caps:
                ws.append([f"--- {tag} ---"])
                for line in (text or "(no output)").splitlines():
                    ws.append([line])
                ws.append([])          # blank separator after each memuse block

                # ping table goes after #2 (after deauth), before #3 (after rejoin)
                if ping_rows is not None and "after deauth" in tag:
                    ws.append(["--- ping (SoftAP -> client, after rejoin) ---"])
                    ws.append(["Client IP", "Ping latency (ms)", "Packet summary"])
                    for (ip, lat, pkt) in ping_rows:
                        ws.append([ip, lat, pkt])
                    ws.append([])
    if retry_rows:
        ws.append([])
        ws.append(["--- ping RETRY (failed clients) ---"])
        ws.append(["Client IP", "Retry result", "Ping latency (ms)", "Packet summary"])
        for (ip, result, lat, pkt) in retry_rows:
            ws.append([ip, result, lat, pkt])
        ws.append([])

    ws.append(["end of block"])
    block_end = ws.max_row

    tint = "FFF2CC" if iteration % 2 else "DDEBF7"
    fill = PatternFill("solid", fgColor=tint)
    for r in range(block_start, block_end + 1):
        for cc in range(1, 7):
            ws.cell(row=r, column=cc).fill = fill
    ws.cell(row=block_start, column=1).font = Font(bold=True)

    wb.save(xlsx_path)
    print(f"Excel: Iteration {iteration} - Memuse Stress -> {xlsx_path}")


def opt_memuse_stress():
    print("\n--- Memuse stress check (deauth + rejoin) ---")
    dut_ip   = f"172.16.{MEMUSE_DUT_IP}"
    dut_path = MEMUSE_DUT_PATH
    logfile  = "memuse.log"
    open(logfile, "w").close()   # fresh file each run

    with open(logfile, "a") as f:
        f.write("#" * 60 + "\nMEMUSE STRESS CHECK\n" + "#" * 60 + "\n")
        f.write(f"DUT SoftAP: {dut_ip} (wlan1)   {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    # ---- STEP1: verify associated clients ----
    print("STEP1: verifying associated clients (wl -i wlan0 status)...")
    assoc = []
    for c in _memuse_client_ips():
        if _is_associated(c["ip"], c["path"]):
            assoc.append(c)
            print(f"  associated: {c['ip']}")
    if not assoc:
        print("No associated clients found. Aborting.")
        return
    with open(logfile, "a") as f:
        f.write("\nASSOCIATED CLIENTS (wl -i wlan0 status returned):\n")
        for c in assoc:
            f.write(f"  {c['ip']}\n")

    # ---- pre-check: ping all associated clients from DUT (ping -c 2) ----
    print("Pre-check: pinging associated clients from DUT (ping -c 2)...")
    for c in assoc:
        data_ip = f"192.168.{c['xx']}"
        remote = f"ping -c 2 {data_ip}"
        out, _, _, _ = execute_command(f"ssh {SSH_USER}@{dut_ip} '{remote}'",
                                       remote_host=None)
        if "0 received" in out or " 0 packets received" in out or not out.strip():
            print(f"  PING FAIL: {c['ip']} ({data_ip})")
        else:
            print(f"  ping ok:   {c['ip']} ({data_ip})")

    # ---- STEP2: memuse BEFORE deauth ----
    m1 = _collect_memuse(dut_ip, dut_path, logfile, "MEMUSE #1 - before deauth")

    # ---- STEP3: fetch AP_BSSID + pick k STAs + deauth ----
    ap_bssid = _get_ap_bssid(dut_ip, dut_path)
    if not ap_bssid:
        print("Could not fetch AP_BSSID. Aborting.")
        return
    print(f"AP_BSSID = {ap_bssid}")

    while True:
        try:
            k = int(input(f"How many STAs to deauth (1-{len(assoc)}): ").strip())
            if 1 <= k <= len(assoc):
                break
        except ValueError:
            pass
        print(f"  enter 1..{len(assoc)}")

    picked = random.sample(assoc, k)
    with open(logfile, "a") as f:
        f.write(f"\nAP_BSSID: {ap_bssid}\n")
        f.write(f"DEAUTH ISSUED (wl deauthenticate {ap_bssid}) on {k} STA(s):\n")
        for c in picked:
            f.write(f"  {c['ip']}\n")

    print(f"Deauthing {k} STA(s)...")
    for c in picked:
        cmd = f"cd {c['path']} && wl -i wlan0 deauthenticate {ap_bssid}"
        execute_command(cmd + ", dp", remote_host=c["ip"])
        print(f"  deauthed: {c['ip']}")

    # ---- STEP4: memuse AFTER deauth ----
    m2 = _collect_memuse(dut_ip, dut_path, logfile, "MEMUSE #2 - after deauth")

    # ---- STEP5: wait for all deauthed STAs to auto-rejoin (no timeout) ----
    print("Waiting for all deauthed STAs to rejoin (wl -i wlan0 status, BSSID)...")
    pending = list(picked)
    rejoined = []
    wpa_out = {}   # ip -> wpa_cli status output at rejoin
    while pending:
        still = []
        for c in pending:
            ok, out = _wpa_status(c["ip"], c["path"])
            if ok:
                print(f"  rejoined: {c['ip']}")
                rejoined.append(c)
                wpa_out[c["ip"]] = out
            else:
                still.append(c)
        pending = still
        if pending:
            time.sleep(3)
    with open(logfile, "a") as f:
        f.write("\nALL DEAUTHED STAs REJOINED (wl -i wlan0 status, BSSID confirmed):\n")
        for c in rejoined:
            f.write(f"  {c['ip']}\n")
        f.write("\n" + "=" * 60 + "\nWL STATUS PER STA (after rejoin)\n" + "=" * 60 + "\n")
        for c in rejoined:
            f.write(f"\n--- {c['ip']} ---\n")
            f.write(wpa_out.get(c["ip"], "  (no output)").strip() + "\n")

    # ---- STEP6: parallel ping rejoined clients from DUT (terminals) ----
    print("Pinging all rejoined clients from DUT in parallel (terminals)...")

    # start_ping/fetch_ping need full dicts: dut + 'data' key on each client
    dut = {"ip": dut_ip, "path": dut_path, "data": SOFTAP_DATA}
    for c in rejoined:
        c["data"] = f"192.168.{c['xx']}"

    # open one terminal per client, all ping in parallel (d2c = DUT -> client)
    start_ping(dut, rejoined, "d2c", "ping_rejoin")
    time.sleep(13)                      # wait for ping -c 10 (~10s) + buffer
    fetch_ping(dut, rejoined, "d2c", "ping_rejoin")

    # parse each fetched log: latency + packet summary line
    with open(logfile, "a") as f:
        f.write("\n" + "=" * 60 + "\nPING REJOINED CLIENTS (from SoftAP, data-plane, parallel)\n" + "=" * 60 + "\n")
    ping_rows = []   # (client_ip, latency_ms, pkt_summary_line)
    for i, c in enumerate(rejoined):
        fname = f"ping_rejoin_{i}.txt"
        try:
            out = open(fname).read()
        except FileNotFoundError:
            out = ""
        m = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', out)
        lat = m.group(1) if m else "NO DATA"
        pm = re.search(r'(\d+ packets transmitted,.*)', out)
        pkt = pm.group(1).strip() if pm else "NO DATA"
        ping_rows.append((c["data"], lat, pkt))
        with open(logfile, "a") as f:
            f.write(f"\n--- DUT -> {c['ip']} ({c['data']})  avg={lat} ms ---\n")
            f.write((out or "  (no output)").strip() + "\n")

    print("Waiting 5s before final memuse collect...")
    time.sleep(5)
    m3 = _collect_memuse(dut_ip, dut_path, logfile, "MEMUSE #3 - after rejoin")

    # ---- STEP7: retry ping for failed clients (one retry) ----
    failed = [c for (c, (ip, lat, pkt)) in zip(rejoined, ping_rows) if lat == "NO DATA"]
    retry_rows = []   # (client_ip, result, latency_ms, pkt_summary_line)
    if failed:
        print(f"Retrying ping for {len(failed)} failed client(s)...")
        with open(logfile, "a") as f:
            f.write("\n" + "=" * 60 + "\nPING RETRY (failed clients, from SoftAP)\n" + "=" * 60 + "\n")
        start_ping(dut, failed, "d2c", "ping_retry")
        time.sleep(13)
        fetch_ping(dut, failed, "d2c", "ping_retry")
        for i, c in enumerate(failed):
            try:
                out = open(f"ping_retry_{i}.txt").read()
            except FileNotFoundError:
                out = ""
            m = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', out)
            lat = m.group(1) if m else "NO DATA"
            pm = re.search(r'(\d+ packets transmitted,.*)', out)
            pkt = pm.group(1).strip() if pm else "NO DATA"
            result = "PASS" if lat != "NO DATA" else "FAIL"
            retry_rows.append((c["data"], result, lat, pkt))
            print(f"  retry {result}: {c['ip']} ({c['data']})  avg={lat} ms")
            with open(logfile, "a") as f:
                f.write(f"\n--- RETRY DUT -> {c['ip']} ({c['data']})  {result}  avg={lat} ms ---\n")
                f.write((out or "  (no output)").strip() + "\n")
    else:
        print("No failed pings; skipping retry.")

    # ---- SUMMARY at end ----
    with open(logfile, "a") as f:
        f.write("\n" + "#" * 60 + "\nFLOW SUMMARY\n" + "#" * 60 + "\n")
        f.write(f"  Associated clients found : {len(assoc)}\n")
        f.write(f"  AP_BSSID                 : {ap_bssid}\n")
        f.write(f"  STAs deauthed            : {k}  ({', '.join(c['ip'] for c in picked)})\n")
        f.write(f"  STAs rejoined            : {len(rejoined)}  ({', '.join(c['ip'] for c in rejoined)})\n")
        f.write(f"  memuse captures          : #1 before deauth, #2 after deauth, #3 after rejoin\n")
        if retry_rows:
            passed = sum(1 for (_, r, _, _) in retry_rows if r == "PASS")
            f.write(f"  ping retry               : {len(retry_rows)} failed, {passed} passed on retry\n")
        else:
            f.write(f"  ping retry               : none needed\n")
    print(f"\nMemuse stress check done -> {logfile}")

    _memuse_excel(dut_ip, ap_bssid, assoc, picked, rejoined, wpa_out,
                  memuse_caps=[("#1 before deauth", m1),
                               ("#2 after deauth", m2),
                               ("#3 after rejoin", m3)],
                  ping_rows=ping_rows, retry_rows=retry_rows)

# ======================================================================
# Option 12 : Auto assign IPs to hardcoded clients (SoftAP 1.4 untouched)
# ======================================================================
def opt_assign_ips():
    print("\n--- Auto assign IPs (hardcoded devices) ---")
    print(f"SoftAP (DUT) = {SOFTAP_IP} (wlan1 {SOFTAP_DATA}) [fixed]")

    # assign SoftAP wlan1 IP first
    cmd = f"ifconfig wlan1 {SOFTAP_DATA}"
    execute_command(cmd, remote_host=SOFTAP_IP)
    print(f"  {SOFTAP_IP} -> wlan1 {SOFTAP_DATA}")

    # all hardcoded clients, excluding SoftAP 1.4
    clients = []
    for xx in ALL_ASTRA + ALL_VIM3:
        if xx == SOFTAP_XX:
            continue
        path = ASTRA_PATH if xx in ALL_ASTRA else VIM3_PATH
        clients.append({"xx": xx, "ip": f"172.16.{xx}",
                        "path": path, "data": f"192.168.{xx}"})

    print(f"Assigning wlan0 IPs to {len(clients)} client(s)...")
    for c in clients:
        cmd = f"ifconfig wlan0 {c['data']}"
        execute_command(cmd, remote_host=c["ip"])
        print(f"  {c['ip']} -> wlan0 {c['data']}")

    print("\n--- Verify (read back ifconfig wlan0) ---")

    print("\n--- Verify ---")
    results = []
    for c in clients:
        out, _, _, _ = execute_command(f"ifconfig wlan0" + ", dp", remote_host=c["ip"])
        got = re.search(r'inet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)', out or "")
        got_ip = got.group(1) if got else None
        ok = (got_ip == c["data"])
        results.append((c["ip"], c["data"], got_ip, ok))
        print(f"  {c['ip']}: want {c['data']}  got {got_ip or 'NONE'}  {'OK' if ok else 'FAIL'}")

    n = len(results)
    passed = sum(1 for (*_, ok) in results if ok)
    fail = [ip for (ip, _, _, ok) in results if not ok]
    print("\n" + "=" * 50)
    print(f"IP ASSIGN: {passed}/{n} OK")
    if fail:
        print(f"FAILED: {', '.join(fail)}")
    else:
        print("ALL ASSIGNED")

# ======================================================================
# Main menu
# ======================================================================
def main():
    actions = {
        "1": ("Load driver on all DUTs        (Code A)", opt_load_all),
        "2": ("Broadcast a command + collect  (Code B)", opt_broadcast),
        "3": ("Ping test (DUT <-> clients)", opt_ping),
        "4": ("TX traffic test  (DUT SoftAP -> clients)", opt_tx),
        "5": ("RX traffic test  (clients -> DUT SoftAP)", opt_rx),
        "6": ("Bidirectional traffic (DUT <-> clients)", opt_bd),
        "7": ("Combo: Ping + TX + RX + BD (one iteration)", opt_combo),
        "8": ("Memuse stress check (deauth + rejoin)", opt_memuse_stress),
        "9": ("Memuse stress check for N iterations (deauth + rejoin)", opt_memuse_stress_n),
        "10": ("VI+VO+BE+BK simultaneous traffic (DUT -> clients)", opt_vi_vo_be_bk),
        "11": ("Edit a dependency file + scp to devices", opt_edit_deps),
        "12": ("Close all spawned terminals (keep this one)", opt_close_terminals),
        "13": ("Push a custom file to all/selected devices", opt_push_custom),
        "14": ("Auto assign IPs to hardcoded devices", opt_assign_ips),
    }
    while True:
        print("\n==================== WLAN TEST SUITE ====================")
        for k in actions:
            print(f"  {k}) {actions[k][0]}")
        print("  0) Exit")
        choice = input("Select: ").strip()
        if choice == "0":
            print("Bye.")
            break
        act = actions.get(choice)
        if not act:
            print("Invalid choice.")
            continue
        try:
            act[1]()
        except KeyboardInterrupt:
            print("\nInterrupted -> back to menu.")
        except Exception as e:
            print(f"ERROR: {e}")




if __name__ == "__main__":
    main()
