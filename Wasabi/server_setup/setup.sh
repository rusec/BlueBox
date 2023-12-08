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

    if [  "$install_result" != 0  ] || [ -z "${indexer_installed}" ]; then
        common_logger -e "Wazuh indexer installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh indexer installation finished."
    fi

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

    yaml_file="/etc/wazuh-indexer/opensearch.yml"

    # Define the property to be changed
    property="network.host"

    # Define the new value for the property
    new_value=$(hostname)

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


function main(){

    check

    common_logger "Depacking wazuh" 

    cat ./wazuh/* > wazuh-offline.tar.gz
    tar xf wazuh-offline.tar.gz

    common_logger "Depacking Complete, installing indexer" 

    install_indexer

    common_logger "Indexer Installed, configuring"
    
    config_indexer

    common_logger "Starting Indexer"

    installCommon_startService "wazuh-indexer"


}

main