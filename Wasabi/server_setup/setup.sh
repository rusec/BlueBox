NODE_NAME="node-1"
readonly logfile="/var/log/wazuh-install.log"
debug=">> ${logfile} 2>&1"


function common_logger() {

    now=$(date +'%d/%m/%Y %H:%M:%S')
    mtype="INFO:"
    debugLogger=
    nolog=
    if [ -n "${1}" ]; then
        while [ -n "${1}" ]; do
            case ${1} in
                "-e")
                    mtype="ERROR:"
                    shift 1
                    ;;
                "-w")
                    mtype="WARNING:"
                    shift 1
                    ;;
                "-d")
                    debugLogger=1
                    mtype="DEBUG:"
                    shift 1
                    ;;
                "-nl")
                    nolog=1
                    shift 1
                    ;;
                *)
                    message="${1}"
                    shift 1
                    ;;
            esac
        done
    fi

    if [ -z "${debugLogger}" ] || { [ -n "${debugLogger}" ] && [ -n "${debugEnabled}" ]; }; then
        if [ "$EUID" -eq 0 ] && [ -z "${nolog}" ]; then
            printf "%s\n" "${now} ${mtype} ${message}" | tee -a ${logfile}
        else
            printf "%b\n" "${now} ${mtype} ${message}"
        fi
    fi

}

function check(){
    DIR="./wazuh-certificates"
    if [ -d "$DIR" ]; then
        # Take action if $DIR exists. #
        echo "Cert check complete in ${DIR}..."
    fi

    DIR="./wazuh"
    if [ -d "$DIR" ]; then
        # Take action if $DIR exists. #
        echo "Decompiled check complete in ${DIR}..."
    fi
    DIR="./comfig.yml"
    if [ -d "$DIR" ]; then
        # Take action if $DIR exists. #
        echo "config check in ${DIR}..."
    fi
}
function installCommon_rollBack(){

    common_logger "UNABLE TO START SERVICE"


}

function installCommon_startService() {

    if [ "$#" -ne 1 ]; then
        common_logger -e "installCommon_startService must be called with 1 argument."
        exit 1
    fi

    common_logger "Starting service ${1}."

    if [[ -d /run/systemd/system ]]; then
        eval "systemctl daemon-reload ${debug}"
        eval "systemctl enable ${1}.service ${debug}"
        eval "systemctl start ${1}.service ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            installCommon_rollBack
            exit 1
        else
            common_logger "${1} service started."
        fi
    elif ps -p 1 -o comm= | grep "init"; then
        eval "chkconfig ${1} on ${debug}"
        eval "service ${1} start ${debug}"
        eval "/etc/init.d/${1} start ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            installCommon_rollBack
            exit 1
        else
            common_logger "${1} service started."
        fi
    elif [ -x "/etc/rc.d/init.d/${1}" ] ; then
        eval "/etc/rc.d/init.d/${1} start ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            installCommon_rollBack
            exit 1
        else
            common_logger "${1} service started."
        fi
    else
        common_logger -e "${1} could not start. No service manager found on the system."
        exit 1
    fi

}


function install_indexer(){

    eval "dpkg -i ./wazuh-offline/wazuh-packages/wazuh-indexer*.deb"
    install_result="${PIPESTATUS[0]}"
    
    indexer_installed=$(dpkg --get-selections 2>/dev/null | grep wazuh-indexer)

    if [  "$install_result" != 0  ] || [ -z "${indexer_installed}" ]; then
        common_logger -e "Wazuh indexer installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh indexer installation finished."
    fi

}

function update_yaml(){
    local yaml_file=$1
    local property=$2
    local new_value=$3

    # Check if the YAML file exists
    if [ ! -f "$yaml_file" ]; then
        echo "Error: YAML file not found at $yaml_file"
        exit 1
    fi

    # Use awk to find and replace the property value
    awk -v prop="$property" -v new_val="$new_value" '{
        if ($1 == prop ":") {
            sub(/".*"/, "\"" new_val "\"");
        }
        print;
    }' "$yaml_file" > temp.yml && mv temp.yml "$yaml_file"

    echo "Property '$property' in '$yaml_file' has been updated to '$new_value'"

}
function update_json_property() {
       if [ "$#" -ne 3 ]; then
        echo "Usage: update_json_property <json_file_path> <property_path> <new_value>"
        return 1
    fi

    json_file="$1"
    property_path="$2"
    new_value="$3"

    if [ ! -f "$json_file" ]; then
        echo "Error: JSON file not found at '$json_file'"
        return 1
    fi

    # Read the JSON file into a variable
    json_content=$(cat "$json_file")

    # Use awk to update the JSON property
    updated_json=$(echo "$json_content" | awk -v path="$property_path" -v value="$new_value" '
        BEGIN {
            FS = OFS = "\"";
            RS = ORS = "\n";
            path_found = 0;
        }

        {
            for (i = 1; i <= NF; i += 2) {
                if ($i == path) {
                    path_found = 1;
                }

                if (path_found && $i == "") {
                    $0 = "\"" value "\"";
                    path_found = 0;
                }
            }
            print $0;
        }
    ')

    # Write the updated JSON back to the file
    echo "$updated_json" > "$json_file"

    echo "Property '$property_path' in '$json_file' updated to '$new_value'"

}

function config_indexer(){

    common_logger "installing certs"

    eval "mkdir /etc/wazuh-indexer/certs"
    eval "cp -n wazuh-certificates/${NODE_NAME}.pem /etc/wazuh-indexer/certs/indexer.pem"
    eval "cp -n wazuh-certificates/${NODE_NAME}-key.pem /etc/wazuh-indexer/certs/indexer-key.pem"
    eval "cp wazuh-certificates/admin-key.pem /etc/wazuh-indexer/certs/"
    eval "cp wazuh-certificates/admin.pem /etc/wazuh-indexer/certs/"
    eval "cp wazuh-certificates/root-ca.pem /etc/wazuh-indexer/certs/"
    eval "chmod 500 /etc/wazuh-indexer/certs"
    eval "chmod 400 /etc/wazuh-indexer/certs/*"
    eval "chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs"

    eval "ls -l /etc/wazuh-indexer/certs"

    common_logger "Updating yml file"

    update_yaml "/etc/wazuh-indexer/opensearch.yml" "network.host"  "127.0.0.1"

}
function manager_install(){
    
    common_logger "Starting the Wazuh manager installation."

    eval "dpkg -i ./lsb-release*.deb"
    eval "dpkg -i ./wazuh-offline/wazuh-packages/wazuh-manager*.deb"
    install_result="${PIPESTATUS[0]}"


    wazuh_installed=$(dpkg --get-selections 2>/dev/null | grep wazuh-manager)

    if [  "$install_result" != 0  ] || [ -z "${wazuh_installed}" ]; then
        common_logger -e "Wazuh installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh manager installation finished."
    fi


}
function install_filebeats(){
    common_logger "Starting the File Beats installation."

    eval "dpkg -i ./wazuh-offline/wazuh-packages/filebeat*.deb"
    install_result="${PIPESTATUS[0]}"

    filebeat_installed=$(dpkg --get-selections 2>/dev/null | grep filebeat)

    if [  "$install_result" != 0  ] || [ -z "${filebeat_installed}" ]; then
        common_logger -e "Filebeat installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Filebeat installation finished."
    fi

}

function filebeat_config(){
    common_logger "configuring filebeats"


    eval "cp ./wazuh-offline/wazuh-files/filebeat.yml /etc/filebeat/ &&\
cp ./wazuh-offline/wazuh-files/wazuh-template.json /etc/filebeat/ &&\
chmod go+r /etc/filebeat/wazuh-template.json"


    common_logger "Updating filebeats configs"

    update_json_property "/etc/filebeat/wazuh-template.json" "index.number_of_shards" "1"

    update_yaml "/etc/filebeat/filebeat.yml" "hosts" "127.0.0.1:9200"

    filebeat keystore create

    echo admin | filebeat keystore add username --stdin --force
    echo admin | filebeat keystore add password --stdin --force


    common_logger "Added wazuh module"

    tar -xzf ./wazuh-offline/wazuh-files/wazuh-filebeat-0.3.tar.gz -C /usr/share/filebeat/module

    common_logger "Configuring certs"

    eval "mkdir /etc/filebeat/certs"
    eval "cp -n wazuh-certificates/$NODE_NAME.pem /etc/filebeat/certs/filebeat.pem"
    eval "cp -n wazuh-certificates/$NODE_NAME-key.pem /etc/filebeat/certs/filebeat-key.pem"
    eval "cp wazuh-certificates/root-ca.pem /etc/filebeat/certs/"
    eval "chmod 500 /etc/filebeat/certs"
    eval "chmod 400 /etc/filebeat/certs/*"
    eval "chown -R root:root /etc/filebeat/certs"


}
function dashboard_install() {

    common_logger "Starting Wazuh dashboard installation."


    eval "dpkg -i ./wazuh-offline/wazuh-packages/wazuh-dashboard*.deb"
    install_result="${PIPESTATUS[0]}"
    dashboard_installed=$(dpkg --get-selections 2>/dev/null | grep wazuh-dashboard)


    
    if [  "$install_result" != 0  ] || [ -z "${dashboard_installed}" ]; then
        common_logger -e "Wazuh dashboard installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh dashboard installation finished."
    fi

}
function dashboard_configure() {

    eval "mkdir /etc/wazuh-dashboard/certs"
    eval "cp -n wazuh-certificates/${NODE_NAME}.pem /etc/wazuh-dashboard/certs/dashboard.pem"
    eval "cp -n wazuh-certificates/${NODE_NAME}-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem"
    eval "cp wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/"
    eval "chmod 500 /etc/wazuh-dashboard/certs"
    eval "chmod 400 /etc/wazuh-dashboard/certs/*"
    eval "chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs"


    update_yaml "/etc/wazuh-dashboard/opensearch_dashboards.yml" "server.host" "0.0.0.0"

    update_yaml "/etc/wazuh-dashboard/opensearch_dashboards.yml" "opensearch.hosts" "https://127.0.0.1:9200"

   
    common_logger "Wazuh dashboard post-install configuration finished."

}

function installCommon_changePasswords() {

    common_logger -d "Setting Wazuh indexer cluster passwords."
    eval "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh --change-all --admin-user wazuh --admin-password wazuh"

}

function dashboard_initializeAIO() {

    u_pass="admin"
    http_port='443'

    common_logger "Initializing Wazuh dashboard web application."
    installCommon_getPass "admin"
    http_code=$(curl -XGET https://localhost:"${http_port}"/status -uadmin:"${u_pass}" -k -w %"{http_code}" -s -o /dev/null)
    retries=0
    max_dashboard_initialize_retries=20
    while [ "${http_code}" -ne "200" ] && [ "${retries}" -lt "${max_dashboard_initialize_retries}" ]
    do
        http_code=$(curl -XGET https://localhost:"${http_port}"/status -uadmin:"${u_pass}" -k -w %"{http_code}" -s -o /dev/null)
        common_logger "Wazuh dashboard web application not yet initialized. Waiting..."
        retries=$((retries+1))
        sleep 15
    done
    if [ "${http_code}" -eq "200" ]; then
        common_logger "Wazuh dashboard web application initialized."
        common_logger -nl "--- Summary ---"
        common_logger -nl "You can access the web interface https://<wazuh-dashboard-ip>:${http_port}\n    User: admin\n    Password: ${u_pass}"
    else
        common_logger -e "Wazuh dashboard installation failed."
        installCommon_rollBack
        exit 1
    fi
}
function indexer_post_config(){
    eval "/usr/share/wazuh-indexer/bin/indexer-security-init.sh"


    eval "curl -XGET https://localhost:9200 -u admin:admin -k"

}

function filebeat_check(){
    eval "filebeat test output"


    eval "curl -k -u admin:admin \"https://localhost:9200/_template/wazuh?pretty&filter_path=wazuh.settings.index.number_of_shards\""


}


function main(){

    check

    common_logger "Depacking wazuh" 

    cat ./wazuh/* > wazuh-offline.tar.gz
    tar xf wazuh-offline.tar.gz

    common_logger "Depacking Complete, installing indexer" 
    
    common_logger "--- Wazuh indexer ---"

    install_indexer

    common_logger "Indexer Installed, configuring"
    
    config_indexer

    common_logger "Starting Indexer"


    installCommon_startService "wazuh-indexer"

    indexer_post_config


    common_logger "--- Wazuh server ---"

    manager_install

    installCommon_startService "wazuh-manager"


    common_logger "Installing filebeats"

    install_filebeats
    filebeat_config

    installCommon_startService "filebeat"
    

    filebeat_check

    common_logger "--- Wazuh dashboard ---"

    dashboard_install
    dashboard_configure

    installCommon_startService "wazuh-dashboard"

    installCommon_changePasswords
    dashboard_initializeAIO
}

main