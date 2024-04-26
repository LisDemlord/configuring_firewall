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
    local missing_dependencies=""
    
    for dep in $dependencies; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing_dependencies+=" $dep"
        fi
    done
    
    if [ -n "$missing_dependencies" ]; then
        echo "Error: The following dependencies are missing or not in PATH:$missing_dependencies"
        exit 1
    fi
}


check_iptables() {
	echo -e "\nSTATUS IPTABLES:"
	iptables -L -vn
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
    # Добавление правил iptables
    iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    iptables -A INPUT -p icmp -j ACCEPT
}

change_default_policy() {
    # Функция для изменения политики по умолчанию для правил iptables
    echo -e "\nEnter the default policy (ACCEPT or DROP):"
    read -r user_policy
    case "$user_policy" in
        "ACCEPT" | "DROP")
            # Если пользователь ввел ACCEPT или DROP, устанавливаем соответствующую политику
            iptables -P INPUT "$user_policy"
            ;;
        *)
            # Если введена некорректная политика, выводим сообщение об ошибке и завершаем выполнение
            echo "ERROR! Incorrect policy. Please enter ACCEPT or DROP..."
            exit 1 ;;
    esac
}

data_collection() {
    # Функция для сбора данных
    local ip_data_osquery
    # Выполняем запрос к osquery для сбора данных об открытых сокетах
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
    
    # Выводим собранные данные
    echo "$ip_data_osquery"
}

formatting_data() {
    # Функция для форматирования данных
    local field="$1"
    local formatted_data
    # Получаем данные с помощью функции data_collection и обрабатываем их с помощью jq
    formatted_data=$(data_collection | jq -r ".[] | .$field")
    
    # Выводим отформатированные данные
    echo "$formatted_data"
}

formation_of_rules() {
    # Функция для формирования правил iptables на основе собранных данных
    local net_family net_local_address net_local_port net_protocol net_remote_address
    # Получаем данные о сетевых соединениях с помощью функции formatting_data
    net_family=$(formatting_data family)
    net_local_address=$(formatting_data local_address)
    net_local_port=$(formatting_data local_port)
    net_protocol=$(formatting_data protocol)
    net_remote_address=$(formatting_data remote_address)

    # Проверяем, чтобы количество элементов в каждом поле было одинаковым
    if [ "$(wc -w <<< "$net_family")" -ne "$(wc -w <<< "$net_local_address")" ] ||
       [ "$(wc -w <<< "$net_family")" -ne "$(wc -w <<< "$net_local_port")" ] ||
       [ "$(wc -w <<< "$net_family")" -ne "$(wc -w <<< "$net_protocol")" ] ||
       [ "$(wc -w <<< "$net_family")" -ne "$(wc -w <<< "$net_remote_address")" ]; then
        echo "ERROR! Different number of items in the connection table..."
        exit 1
    fi

    local number_of_connections
    # Получаем общее количество соединений
    number_of_connections=$(echo "$net_family" | wc -l)

    # Проходим по каждому соединению и создаем соответствующее правило iptables
    for ((i = 1; i <= number_of_connections; i++)); do
        family=$(echo "$net_family" | awk "NR==$i")
        local_address=$(echo "$net_local_address" | awk "NR==$i")
        local_port=$(echo "$net_local_port" | awk "NR==$i")
        protocol=$(echo "$net_protocol" | awk "NR==$i")
        remote_address=$(echo "$net_remote_address" | awk "NR==$i")

        echo -e "\nCreating iptables rules for a connection $i:"
        echo "Family: $family"
        echo "Local address: $local_address"
        echo "Local port: $local_port"
        echo "Protocol: $protocol"
        echo -e "Remote address: $remote_address\n"
        
        # Создаем правило iptables для данного соединения
        iptables -A INPUT -p "$protocol" --dport "$local_port" -s "$remote_address" -d "$local_address" -j ACCEPT
    done
}

save_iptables_rules() {
    # Функция для сохранения правил iptables
    echo -e "\nDo you want to save the current iptables rules? (y/n)"
    read -r choice
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        # Сохраните правила iptables в указанном пути к файлу
        iptables-save > "$rules_file_path"
        echo -e "\niptables rules are saved in $rules_file_path\n"
    else
        # Если пользователь решит не сохранять, отобразите сообщение
        echo -e "\nWARNING: iptables rules are not saved..."
    fi
}

create_restore_iptables() {
    # Функция для создания скрипта восстановления правил iptables
    echo "Do you want to create the iptables rules restoration script? (y/n)"
    read -r choice
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        echo '#!/bin/bash' > "$restore_iptables_file_path"
        echo "iptables-restore < '$rules_file_path'" >> "$restore_iptables_file_path"
        echo 'exit 0' >> "$restore_iptables_file_path"
        echo -e "\nThe iptables rules restoration script has been created: $restore_iptables_file_path\n"
    else
        echo -e "\nThe iptables rules restoration script has not been created..."
    fi
}

create_systemd_service() {
    # Функция для создания systemd-службы
    echo "Do you want to create a systemd service for iptables? (y/n)"
    read -r choice
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        cat <<EOF | tee "/etc/systemd/system/$service_name" > /dev/null
			[Unit]
			Description=iptables rules service
			After=network.target

			[Service]
			Type=simple
			ExecStart=$restore_iptables_file_path

			[Install]
			WantedBy=multi-user.target
EOF

        # Перезагружаем конфигурацию systemd
        systemctl daemon-reload
        if systemctl is-enabled "$service_name" > /dev/null; then
            echo -e "\nWARNING: The service is already enabled...\n"
        else
            # Включаем созданную службу
            systemctl enable "$service_name"
        fi

        # Запускаем службу
        systemctl start "$service_name"
    else
        echo "Creation of systemd service for iptables is cancelled."
    fi
}

main() {
    check_dependencies || { echo "ERROR: dependencies not satisfied..."; exit 1; }
    check_iptables || { echo "ERROR: iptables check failed..."; exit 1; }
    clear_iptables || { echo "ERROR: iptables clearing failed..."; exit 1; }
    initial_setup_iptables || { echo "ERROR: initial iptables setup failed..."; exit 1; }
    change_default_policy || { echo "ERROR: changing default policy failed..."; exit 1; }
    formation_of_rules || { echo "ERROR: formation of rules failed..."; exit 1; }
    check_iptables || { echo "ERROR: iptables recheck failed..."; exit 1; }
    save_iptables_rules || { echo "ERROR: saving iptables rules failed..."; exit 1; }
    create_restore_iptables || { echo "ERROR: creating iptables restore script failed..."; exit 1; }
    create_systemd_service || { echo "ERROR: creating systemd service failed..."; exit 1; }
}

main