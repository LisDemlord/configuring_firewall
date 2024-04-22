#!/bin/bash
[ $UID -eq 0 ] || 
{ echo "This script needs to be run with sudo or by root."; exit 1; }

# Включение строгой проверки на наличие ошибок
set -o errexit
set -o nounset
set -o pipefail

rules_file_path="/etc/iptables.rules"
restore_iptables_file_path="/etc/restore-iptables.sh"
service_name="restore-iptables.service"

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
	echo -e "\nSTATUS IPTABLES:"
	iptables -L -vn
}

clear_iptables() {
    # Установка политики по умолчанию для цепочек ВВОДА и ВЫВОДА
    iptables -P INPUT ACCEPT || { echo "Failed to set INPUT policy"; exit 1; }
    iptables -P OUTPUT ACCEPT || { echo "Failed to set OUTPUT policy"; exit 1; }
    
    # Очистка всех правил
    iptables -F || { echo "Failed to flush rules"; exit 1; }
    # Очистка всех пользовательских цепочек
    iptables -X || { echo "Failed to flush custom chains"; exit 1; }
    # Сброс счетсичков пакетов и байтов
    iptables -Z || { echo "Failed to zero counters"; exit 1; }
    
    # Очистка и уничтожение всех наборов IP-адресов
    ipset flush || { echo "Failed to flush ipset"; exit 1; }
    ipset destroy || { echo "Failed to destroy ipset"; exit 1; }
}

initial_setup_iptables() {
    # Добавление правил iptables
    iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || { echo "Failed to add RELATED,ESTABLISHED rule"; exit 1; }
    iptables -A INPUT -i lo -j ACCEPT || { echo "Failed to add loopback rule"; exit 1; }
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP || { echo "Failed to add INVALID rule"; exit 1; }
    iptables -A INPUT -p icmp -j ACCEPT || { echo "Failed to add ICMP rule"; exit 1; }
}

change_default_policy() {
	echo -e "\n"
    read -r -p "Enter default policy (ACCEPT or DROP): " user_policy
    case "$user_policy" in
        "ACCEPT" | "DROP")
            iptables -P INPUT "$user_policy" || { echo "Failed to set default policy"; exit 1; }
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
            LIMIT 4;' | osqueryi --json) || { echo "Failed to collect data"; exit 1; }

    echo "$ip_data_osquery"
}

formatting_data() {
    local field="$1"
    local formatted_data
    formatted_data=$(data_collection | jq -r ".[] | .$field") || { echo "Failed to format data"; exit 1; }

    echo "$formatted_data"
}


formation_of_rules() {
    local net_family net_local_address net_local_port net_protocol net_remote_address
    net_family=$(formatting_data family)
    net_local_address=$(formatting_data local_address)
    net_local_port=$(formatting_data local_port)
    net_protocol=$(formatting_data protocol)
    net_remote_address=$(formatting_data remote_address)

    if [ "$(wc -w <<< "$net_family")" -ne "$(wc -w <<< "$net_local_address")" ] ||
       [ "$(wc -w <<< "$net_family")" -ne "$(wc -w <<< "$net_local_port")" ] ||
       [ "$(wc -w <<< "$net_family")" -ne "$(wc -w <<< "$net_protocol")" ] ||
       [ "$(wc -w <<< "$net_family")" -ne "$(wc -w <<< "$net_remote_address")" ]; then
        echo "Error: different number of items in the connection table"
        exit 1
    fi

    local number_of_connections
    number_of_connections=$(echo "$net_family" | wc -l)

    for ((i = 1; i <= number_of_connections; i++)); do
        family=$(echo "$net_family" | awk "NR==$i")
        local_address=$(echo "$net_local_address" | awk "NR==$i")
        local_port=$(echo "$net_local_port" | awk "NR==$i")
        protocol=$(echo "$net_protocol" | awk "NR==$i")
        remote_address=$(echo "$net_remote_address" | awk "NR==$i")

        # Создание правил iptables на основе данных
        echo -e "\nCreating iptables rules for connection $i:"
        echo "Family: $family"
        echo "Local Address: $local_address"
        echo "Local Port: $local_port"
        echo "Protocol: $protocol"
        echo -e "Remote Address: $remote_address\n"
        
        iptables -A INPUT -p "$protocol" --dport "$local_port" -s "$remote_address" -d "$local_address" -j ACCEPT
    done
}

save_iptables_rules() {
    iptables-save > "$rules_file_path"
    echo -e "\niptables rules are saved in $rules_file_path\n"
}

create_restore_iptables() {
    echo '#!/bin/bash' > "$restore_iptables_file_path"
    echo "iptables-restore < '$rules_file_path'" >> "$restore_iptables_file_path"
    echo 'exit 0' >> "$restore_iptables_file_path"
}

сreate_systemd_service() {
    cat <<EOF | sudo tee "/etc/systemd/system/$service_name" >/dev/null
	[Unit]
	Description=My Script Service
	After=network.target
	[Service]
	Type=simple
	ExecStart=$restore_iptables_file_path
	[Install]
	WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable "$service_name"
    sudo systemctl start "$service_name"
}

main() {
    check_dependencies
    check_iptables
    clear_iptables
    initial_setup_iptables
    change_default_policy
    formation_of_rules
    check_iptables
    save_iptables_rules
    create_restore_iptables
    сreate_systemd_service
}

main