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

change_base_policy() {
	iptables -P INPUT DROP
}

main() {
	check_dependencies
	check_iptables
	clear_iptables
	initial_setup_iptables
	change_base_policy
}

main
