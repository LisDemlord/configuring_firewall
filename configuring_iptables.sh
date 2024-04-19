#!/bin/bash
[ $UID -eq 0 ] || 
{ echo "This script needs to be run with sudo or by root."; exit 1; }

# Включение строгой проверки на наличие ошибок
set -o errexit
set -o nounset
set -o pipefail

# Проверка наличия необходимых утилит
check_dependencies() {
    local dependencies='iptables osqueryi jq awk tr wc'
    for dep in $dependencies; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            echo "Error: $dep is not installed or not in PATH"
            exit 1
        fi
    done
}

check_iptables() {
	echo -e "STATUS IPTABLES:\n"
	iptables -L
}

clear_iptables() {
# Установка политики по умолчанию для цепочек ВВОДА и ВЫВОДА
	iptables -P INPUT ACCEPT
	iptables -P OUTPUT ACCEPT
	
	# Очистка всех правил
	iptables -F
	# Очистка всех пользовательских цепочек
	iptables -X
	# Сброс счетсичков пакетов и байтов
	iptables -Z
	
	# Очистка и уничтожение всех наборов IP-адресов
	ipset flush
	ipset destroy
}

initial_setup_iptables() {
	iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	iptables -A INPUT -i lo -j ACCEPT
	iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
	iptables -A INPUT -p icmp -j ACCEPT
}

change_default_policy() {
    read -r -p "Enter default policy (ACCEPT or DROP): " user_policy
    case "$user_policy" in
        "ACCEPT" | "DROP")
            iptables -P INPUT "$user_policy"
            ;;
        *)
            echo "Invalid policy. Please enter either ACCEPT or DROP."
            exit 1 ;;
    esac
}

data_collection() {
	local ip_data_osquery
	ip_data_osquery=$(echo 'SELECT (
			  CASE family 
			  WHEN 2 THEN "IP4" 
			  ELSE family END
			) AS family, (
			  CASE protocol 
			  WHEN 6 THEN "TCP" 
			  WHEN 17 THEN "UDP" 
			  ELSE protocol END
			) AS protocol, local_address, local_port, 
			  remote_address
			FROM process_open_sockets 
			WHERE family IN (2) 
			AND protocol IN (6, 17) 
			LIMIT 4;' | osqueryi --json)
	
	echo "$ip_data_osquery"
}

formatting_data() {
    local field="$1"
    local formatted_data
    formatted_data=$(data_collection | jq -r ".[] | .$field")
    echo "$formatted_data"
}

main() {
	check_dependencies
	check_iptables
	clear_iptables
	initial_setup_iptables
	change_default_policy
	formatting_data family
	formatting_data local_address
	formatting_data local_port
	formatting_data protocol
	formatting_data remote_address
}

main
