#!/bin/bash
[ $UID -eq 0 ] || 
{ echo "This script needs to be run with sudo or by root."; exit 1; }

# Enable strict error checking
set -o errexit
set -o nounset
set -o pipefail

check_iptables() {
	echo -e "STATUS IPTABLES:\n"
	iptables -L
}

clear_iptables() {
# Set default policies for INPUT and OUTPUT chains
	iptables -P INPUT ACCEPT
	iptables -P OUTPUT ACCEPT
	
	# Clear all rules
	iptables -F
	# Clear all user-defined chains
	iptables -X
	# Clear all byte counters
	iptables -Z
	
	# Flush and destroy all IP sets
	ipset flush
	ipset destroy
}
