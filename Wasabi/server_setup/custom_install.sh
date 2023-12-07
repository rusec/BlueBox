#!/bin/bash

# Wazuh installer
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

readonly repogpg="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
readonly repobaseurl="https://packages.wazuh.com/4.x"
readonly reporelease="stable"
readonly filebeat_wazuh_module="${repobaseurl}/filebeat/wazuh-filebeat-0.3.tar.gz"
readonly bucket="packages.wazuh.com"
readonly repository="4.x"

adminpem="/etc/wazuh-indexer/certs/admin.pem"
adminkey="/etc/wazuh-indexer/certs/admin-key.pem"
readonly wazuh_major="4.7"
readonly wazuh_version="4.7.0"
readonly filebeat_version="7.10.2"
readonly wazuh_install_vesion="0.1"
readonly source_branch="v${wazuh_version}"
readonly resources="https://${bucket}/${wazuh_major}"
readonly base_url="https://${bucket}/${repository}"
base_path="$(dirname "$(readlink -f "$0")")"
readonly base_path
config_file="${base_path}/config.yml"
readonly tar_file_name="wazuh-install-files.tar"
tar_file="${base_path}/${tar_file_name}"
readonly filebeat_wazuh_template="https://raw.githubusercontent.com/wazuh/wazuh/${source_branch}/extensions/elasticsearch/7.x/wazuh-template.json"
readonly dashboard_cert_path="/etc/wazuh-dashboard/certs"
readonly filebeat_cert_path="/etc/filebeat/certs"
readonly indexer_cert_path="/etc/wazuh-indexer/certs"
readonly logfile="/var/log/wazuh-install.log"
debug=">> ${logfile} 2>&1"
readonly base_dest_folder="wazuh-offline"
readonly manager_deb_base_url="${base_url}/apt/pool/main/w/wazuh-manager"
readonly filebeat_deb_base_url="${base_url}/apt/pool/main/f/filebeat"
readonly filebeat_deb_package="filebeat-oss-${filebeat_version}-amd64.deb"
readonly indexer_deb_base_url="${base_url}/apt/pool/main/w/wazuh-indexer"
readonly dashboard_deb_base_url="${base_url}/apt/pool/main/w/wazuh-dashboard"
readonly manager_rpm_base_url="${base_url}/yum"
readonly filebeat_rpm_base_url="${base_url}/yum"
readonly filebeat_rpm_package="filebeat-oss-${filebeat_version}-x86_64.rpm"
readonly indexer_rpm_base_url="${base_url}/yum"
readonly dashboard_rpm_base_url="${base_url}/yum"
readonly wazuh_gpg_key="https://${bucket}/key/GPG-KEY-WAZUH"
readonly filebeat_config_file="${resources}/tpl/wazuh/filebeat/filebeat.yml"
adminUser="wazuh"
adminPassword="wazuh"
http_port=443
wazuh_aio_ports=( 9200 9300 1514 1515 1516 55000 "${http_port}")
readonly wazuh_indexer_ports=( 9200 9300 )
readonly wazuh_manager_ports=( 1514 1515 1516 55000 )
wazuh_dashboard_port="${http_port}"
NODE_NAME="node-1"

config_file_certificate_config="nodes:
  # Wazuh indexer nodes
  indexer:
    - name: indexer-1
      ip: \"<indexer-node-ip>\"
    - name: indexer-2
      ip: \"<indexer-node-ip>\"
    - name: indexer-3
      ip: \"<indexer-node-ip>\"
  server:
    - name: server-1
      ip: \"<server-node-ip>\"
      node_type: master
    - name: server-2
      ip: \"<server-node-ip>\"
      node_type: worker
    - name: server-3
      ip: \"<server-node-ip>\"
      node_type: worker
  dashboard:
    - name: dashboard-1
      ip: \"<dashboard-node-ip>\"
    - name: dashboard-2
      ip: \"<dashboard-node-ip>\"
    - name: dashboard-3
      ip: \"<dashboard-node-ip>\""

config_file_certificate_config_aio="nodes:
  indexer:
    - name: wazuh-indexer
      ip: 127.0.0.1
  server:
    - name: wazuh-server
      ip: 127.0.0.1
  dashboard:
    - name: wazuh-dashboard
      ip: 127.0.0.1"

config_file_dashboard_dashboard="server.host: \"<kibana-ip>\"
opensearch.hosts: https://<elasticsearch-ip>:9200
server.port: 443
opensearch.ssl.verificationMode: certificate
# opensearch.username: kibanaserver
# opensearch.password: kibanaserver
opensearch.requestHeadersAllowlist: [\"securitytenant\",\"Authorization\"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: [\"kibana_read_only\"]
server.ssl.enabled: true
server.ssl.key: \"/etc/wazuh-dashboard/certs/kibana-key.pem\"
server.ssl.certificate: \"/etc/wazuh-dashboard/certs/kibana.pem\"
opensearch.ssl.certificateAuthorities: [\"/etc/wazuh-dashboard/certs/root-ca.pem\"]
server.defaultRoute: /app/wazuh
opensearch_security.cookie.secure: true"

config_file_dashboard_dashboard_all_in_one="server.host: 0.0.0.0
server.port: 443
opensearch.hosts: https://localhost:9200
opensearch.ssl.verificationMode: certificate
# opensearch.username: kibanaserver
# opensearch.password: kibanaserver
opensearch.requestHeadersAllowlist: [\"securitytenant\",\"Authorization\"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: [\"kibana_read_only\"]
server.ssl.enabled: true
server.ssl.key: \"/etc/wazuh-dashboard/certs/kibana-key.pem\"
server.ssl.certificate: \"/etc/wazuh-dashboard/certs/kibana.pem\"
opensearch.ssl.certificateAuthorities: [\"/etc/wazuh-dashboard/certs/root-ca.pem\"]
uiSettings.overrides.defaultRoute: /app/wazuh
opensearch_security.cookie.secure: true"

config_file_dashboard_dashboard_unattended="server.host: 0.0.0.0
opensearch.hosts: https://127.0.0.1:9200
server.port: 443
opensearch.ssl.verificationMode: certificate
# opensearch.username: kibanaserver
# opensearch.password: kibanaserver
opensearch.requestHeadersAllowlist: [\"securitytenant\",\"Authorization\"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: [\"kibana_read_only\"]
server.ssl.enabled: true
server.ssl.key: \"/etc/wazuh-dashboard/certs/dashboard-key.pem\"
server.ssl.certificate: \"/etc/wazuh-dashboard/certs/dashboard.pem\"
opensearch.ssl.certificateAuthorities: [\"/etc/wazuh-dashboard/certs/root-ca.pem\"]
uiSettings.overrides.defaultRoute: /app/wazuh
opensearch_security.cookie.secure: true"

config_file_dashboard_dashboard_unattended_distributed="server.port: 443
opensearch.ssl.verificationMode: certificate
# opensearch.username: kibanaserver
# opensearch.password: kibanaserver
opensearch.requestHeadersAllowlist: [\"securitytenant\",\"Authorization\"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: [\"kibana_read_only\"]
server.ssl.enabled: true
server.ssl.key: \"/etc/wazuh-dashboard/certs/dashboard-key.pem\"
server.ssl.certificate: \"/etc/wazuh-dashboard/certs/dashboard.pem\"
opensearch.ssl.certificateAuthorities: [\"/etc/wazuh-dashboard/certs/root-ca.pem\"]
uiSettings.overrides.defaultRoute: /app/wazuh
opensearch_security.cookie.secure: true"

config_file_filebeat_filebeat="# Wazuh - Filebeat configuration file
output.elasticsearch:
  hosts: [\"<elasticsearch_ip>:9200\"]
  protocol: https
  username: \${username}
  password: \${password}
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: \"/etc/filebeat/certs/filebeat.pem\"
  ssl.key: \"/etc/filebeat/certs/filebeat-key.pem\"
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.overwrite: true
setup.ilm.enabled: false

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

logging.metrics.enabled: false

seccomp:
  default_action: allow
  syscalls:
  - action: allow
    names:
    - rseq"

config_file_filebeat_filebeat_all_in_one="# Wazuh - Filebeat configuration file
output.elasticsearch:
  hosts: [\"127.0.0.1:9200\"]
  protocol: https
  username: \${username}
  password: \${password}
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: \"/etc/filebeat/certs/filebeat.pem\"
  ssl.key: \"/etc/filebeat/certs/filebeat-key.pem\"
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.overwrite: true
setup.ilm.enabled: false

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

logging.metrics.enabled: false

seccomp:
  default_action: allow
  syscalls:
  - action: allow
    names:
    - rseq"

config_file_filebeat_filebeat_distributed="# Wazuh - Filebeat configuration file
output.elasticsearch:
  protocol: https
  username: \${username}
  password: \${password}
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: \"/etc/filebeat/certs/filebeat.pem\"
  ssl.key: \"/etc/filebeat/certs/filebeat-key.pem\"
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.overwrite: true
setup.ilm.enabled: false

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644

logging.metrics.enabled: false

seccomp:
  default_action: allow
  syscalls:
  - action: allow
    names:
    - rseq"

config_file_filebeat_filebeat_elastic_cluster="# Wazuh - Filebeat configuration file
output.elasticsearch:
  hosts: [\"<elasticsearch_ip_node_1>:9200\", \"<elasticsearch_ip_node_2>:9200\", \"<elasticsearch_ip_node_3>:9200\"]
  protocol: https
  username: \${username}
  password: \${password}
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: \"/etc/filebeat/certs/filebeat.pem\"
  ssl.key: \"/etc/filebeat/certs/filebeat-key.pem\"
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.overwrite: true
setup.ilm.enabled: false

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

logging.metrics.enabled: false

seccomp:
  default_action: allow
  syscalls:
  - action: allow
    names:
    - rseq"

config_file_filebeat_filebeat_unattended="# Wazuh - Filebeat configuration file
output.elasticsearch.hosts:
        - 127.0.0.1:9200
#        - <elasticsearch_ip_node_2>:9200 
#        - <elasticsearch_ip_node_3>:9200

output.elasticsearch:
  protocol: https
  username: \${username}
  password: \${password}
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: \"/etc/filebeat/certs/filebeat.pem\"
  ssl.key: \"/etc/filebeat/certs/filebeat-key.pem\"
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.overwrite: true
setup.ilm.enabled: false

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644

logging.metrics.enabled: false

seccomp:
  default_action: allow
  syscalls:
  - action: allow
    names:
    - rseq"

config_file_indexer_indexer="network.host: 0.0.0.0
node.name: node-1
cluster.initial_master_nodes: node-1

plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled_ciphers:
  - \"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\"
  - \"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\"
  - \"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\"
  - \"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\"
plugins.security.ssl.http.enabled_protocols:
  - \"TLSv1.2\"
plugins.security.nodes_dn:
- CN=node-1,OU=Wazuh,O=Wazuh,L=California,C=US
plugins.security.authcz.admin_dn:
- CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US

plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: [\"all_access\", \"security_rest_api_access\"]
cluster.routing.allocation.disk.threshold_enabled: false
node.max_local_storage_nodes: 3

path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

### Option to allow Filebeat-oss 7.10.2 to work ###
compatibility.override_main_response_version: true"

config_file_indexer_indexer_all_in_one="network.host: \"127.0.0.1\"
node.name: \"node-1\"
cluster.initial_master_nodes:
- \"node-1\"
cluster.name: \"wazuh-cluster\"

node.max_local_storage_nodes: \"3\"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false
plugins.security.ssl.http.enabled_ciphers:
  - \"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\"
  - \"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\"
  - \"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\"
  - \"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\"
plugins.security.ssl.http.enabled_protocols:
  - \"TLSv1.2\"
plugins.security.authcz.admin_dn:
- \"CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US\"
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.nodes_dn:
- \"CN=indexer,OU=Wazuh,O=Wazuh,L=California,C=US\"
plugins.security.restapi.roles_enabled:
- \"all_access\"
- \"security_rest_api_access\"

plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [\".opendistro-alerting-config\", \".opendistro-alerting-alert*\", \".opendistro-anomaly-results*\", \".opendistro-anomaly-detector*\", \".opendistro-anomaly-checkpoints\", \".opendistro-anomaly-detection-state\", \".opendistro-reports-*\", \".opendistro-notifications-*\", \".opendistro-notebooks\", \".opensearch-observability\", \".opendistro-asynchronous-search-response*\", \".replication-metadata-store\"]

### Option to allow Filebeat-oss 7.10.2 to work ###
compatibility.override_main_response_version: true"

config_file_indexer_indexer_unattended_distributed="node.master: true
node.data: true
node.ingest: true

cluster.name: wazuh-indexer-cluster
cluster.routing.allocation.disk.threshold_enabled: false

node.max_local_storage_nodes: \"3\"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer


plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false
plugins.security.ssl.http.enabled_ciphers:
  - \"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\"
  - \"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\"
  - \"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\"
  - \"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\"
plugins.security.ssl.http.enabled_protocols:
  - \"TLSv1.2\"
plugins.security.authcz.admin_dn:
- \"CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US\"
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.restapi.roles_enabled:
- \"all_access\"
- \"security_rest_api_access\"

plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [\".opendistro-alerting-config\", \".opendistro-alerting-alert*\", \".opendistro-anomaly-results*\", \".opendistro-anomaly-detector*\", \".opendistro-anomaly-checkpoints\", \".opendistro-anomaly-detection-state\", \".opendistro-reports-*\", \".opendistro-notifications-*\", \".opendistro-notebooks\", \".opensearch-observability\", \".opendistro-asynchronous-search-response*\", \".replication-metadata-store\"]

### Option to allow Filebeat-oss 7.10.2 to work ###
compatibility.override_main_response_version: true"

config_file_indexer_roles_internal_users="---
# This is the internal user database
# The hash value is a bcrypt hash and can be generated with plugin/tools/hash.sh

_meta:
  type: \"internalusers\"
  config_version: 2

# Define your internal users here

## Demo users

admin:
  hash: \"\$2a\$12\$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG\"
  reserved: true
  backend_roles:
  - \"admin\"
  description: \"Demo admin user\"

kibanaserver:
  hash: \"\$2a\$12\$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H.\"
  reserved: true
  description: \"Demo kibanaserver user\"

kibanaro:
  hash: \"\$2a\$12\$JJSXNfTowz7Uu5ttXfeYpeYE0arACvcwlPBStB1F.MI7f0U9Z4DGC\"
  reserved: false
  backend_roles:
  - \"kibanauser\"
  - \"readall\"
  attributes:
    attribute1: \"value1\"
    attribute2: \"value2\"
    attribute3: \"value3\"
  description: \"Demo kibanaro user\"

logstash:
  hash: \"\$2a\$12\$u1ShR4l4uBS3Uv59Pa2y5.1uQuZBrZtmNfqB3iM/.jL0XoV9sghS2\"
  reserved: false
  backend_roles:
  - \"logstash\"
  description: \"Demo logstash user\"

readall:
  hash: \"\$2a\$12\$ae4ycwzwvLtZxwZ82RmiEunBbIPiAmGZduBAjKN0TXdwQFtCwARz2\"
  reserved: false
  backend_roles:
  - \"readall\"
  description: \"Demo readall user\"

snapshotrestore:
  hash: \"\$2y\$12\$DpwmetHKwgYnorbgdvORCenv4NAK8cPUg8AI6pxLCuWf/ALc0.v7W\"
  reserved: false
  backend_roles:
  - \"snapshotrestore\"
  description: \"Demo snapshotrestore user\""

config_file_indexer_roles_roles="_meta:
  type: \"roles\"
  config_version: 2

# Restrict users so they can only view visualization and dashboard on kibana
kibana_read_only:
  reserved: true

# The security REST API access role is used to assign specific users access to change the security settings through the REST API.
security_rest_api_access:
  reserved: true

# Allows users to view monitors, destinations and alerts
alerting_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/alerting/alerts/get'
    - 'cluster:admin/opendistro/alerting/destination/get'
    - 'cluster:admin/opendistro/alerting/monitor/get'
    - 'cluster:admin/opendistro/alerting/monitor/search'

# Allows users to view and acknowledge alerts
alerting_ack_alerts:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/alerting/alerts/*'

# Allows users to use all alerting functionality
alerting_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster_monitor'
    - 'cluster:admin/opendistro/alerting/*'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices_monitor'
        - 'indices:admin/aliases/get'
        - 'indices:admin/mappings/get'

# Allow users to read Anomaly Detection detectors and results
anomaly_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/ad/detector/info'
    - 'cluster:admin/opendistro/ad/detector/search'
    - 'cluster:admin/opendistro/ad/detectors/get'
    - 'cluster:admin/opendistro/ad/result/search'
    - 'cluster:admin/opendistro/ad/tasks/search'

# Allows users to use all Anomaly Detection functionality
anomaly_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster_monitor'
    - 'cluster:admin/opendistro/ad/*'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices_monitor'
        - 'indices:admin/aliases/get'
        - 'indices:admin/mappings/get'

# Allows users to read Notebooks
notebooks_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/notebooks/list'
    - 'cluster:admin/opendistro/notebooks/get'

# Allows users to all Notebooks functionality
notebooks_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/notebooks/create'
    - 'cluster:admin/opendistro/notebooks/update'
    - 'cluster:admin/opendistro/notebooks/delete'
    - 'cluster:admin/opendistro/notebooks/get'
    - 'cluster:admin/opendistro/notebooks/list'

# Allows users to read and download Reports
reports_instances_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/reports/instance/list'
    - 'cluster:admin/opendistro/reports/instance/get'
    - 'cluster:admin/opendistro/reports/menu/download'

# Allows users to read and download Reports and Report-definitions
reports_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/reports/definition/get'
    - 'cluster:admin/opendistro/reports/definition/list'
    - 'cluster:admin/opendistro/reports/instance/list'
    - 'cluster:admin/opendistro/reports/instance/get'
    - 'cluster:admin/opendistro/reports/menu/download'

# Allows users to all Reports functionality
reports_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/reports/definition/create'
    - 'cluster:admin/opendistro/reports/definition/update'
    - 'cluster:admin/opendistro/reports/definition/on_demand'
    - 'cluster:admin/opendistro/reports/definition/delete'
    - 'cluster:admin/opendistro/reports/definition/get'
    - 'cluster:admin/opendistro/reports/definition/list'
    - 'cluster:admin/opendistro/reports/instance/list'
    - 'cluster:admin/opendistro/reports/instance/get'
    - 'cluster:admin/opendistro/reports/menu/download'

# Allows users to use all asynchronous-search functionality
asynchronous_search_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/asynchronous_search/*'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices:data/read/search*'

# Allows users to read stored asynchronous-search results
asynchronous_search_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/asynchronous_search/get'

# Wazuh monitoring and statistics index permissions
manage_wazuh_index:
  reserved: true
  hidden: false
  cluster_permissions: []
  index_permissions:
  - index_patterns:
    - \"wazuh-*\"
    dls: \"\"
    fls: []
    masked_fields: []
    allowed_actions:
    - \"read\"
    - \"delete\"
    - \"manage\"
    - \"index\"
  tenant_permissions: []
  static: false"

config_file_indexer_roles_roles_mapping="---
# In this file users, backendroles and hosts can be mapped to Open Distro Security roles.
# Permissions for Opendistro roles are configured in roles.yml

_meta:
  type: \"rolesmapping\"
  config_version: 2

# Define your roles mapping here

## Default roles mapping

all_access:
  reserved: true
  hidden: false
  backend_roles:
  - \"admin\"
  hosts: []
  users: []
  and_backend_roles: []
  description: \"Maps admin to all_access\"

own_index:
  reserved: false
  hidden: false
  backend_roles: []
  hosts: []
  users:
  - \"*\"
  and_backend_roles: []
  description: \"Allow full access to an index named like the username\"

logstash:
  reserved: false
  hidden: false
  backend_roles:
  - \"logstash\"
  hosts: []
  users: []
  and_backend_roles: []

readall:
  reserved: true
  hidden: false
  backend_roles:
  - \"readall\"
  hosts: []
  users: []
  and_backend_roles: []

manage_snapshots:
  reserved: true
  hidden: false
  backend_roles:
  - \"snapshotrestore\"
  hosts: []
  users: []
  and_backend_roles: []

kibana_server:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
  - \"kibanaserver\"
  and_backend_roles: []

kibana_user:
  reserved: false
  hidden: false
  backend_roles:
  - \"kibanauser\"
  hosts: []
  users: []
  and_backend_roles: []
  description: \"Maps kibanauser to kibana_user\"

  # Wazuh monitoring and statistics index permissions
manage_wazuh_index:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
  - \"kibanaserver\"
  and_backend_roles: []"

trap installCommon_cleanExit SIGINT
export JAVA_HOME="/usr/share/wazuh-indexer/jdk/"

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
function dashboard_changePort() {

    chosen_port="$1"
    http_port="${chosen_port}" 
    wazuh_dashboard_ports=( "${http_port}" )
    wazuh_aio_ports=(9200 9300 1514 1515 1516 55000 "${http_port}")

    sed -i 's/server\.port: [0-9]\+$/server.port: '"${chosen_port}"'/' "$0"
    common_logger "Wazuh web interface port will be ${chosen_port}."
}
function common_curl() {

    if [ -n "${curl_has_connrefused}" ]; then
        eval "curl $@ --retry-connrefused"
        e_code="${PIPESTATUS[0]}"
    else
        retries=0
        eval "curl $@"
        e_code="${PIPESTATUS[0]}"
        while [ "${e_code}" -eq 7 ] && [ "${retries}" -ne 12 ]; do
            retries=$((retries+1))
            sleep 5
            eval "curl $@"
            e_code="${PIPESTATUS[0]}"
        done
    fi
    return "${e_code}"

}
function installCommon_rollBack() {

    if [ -z "${uninstall}" ]; then
        common_logger "--- Removing existing Wazuh installation ---"
    fi

    if [ -f "/etc/yum.repos.d/wazuh.repo" ]; then
        eval "rm /etc/yum.repos.d/wazuh.repo"
    elif [ -f "/etc/zypp/repos.d/wazuh.repo" ]; then
        eval "rm /etc/zypp/repos.d/wazuh.repo"
    elif [ -f "/etc/apt/sources.list.d/wazuh.list" ]; then
        eval "rm /etc/apt/sources.list.d/wazuh.list"
    fi



    if [[ -n "${wazuh_installed}" && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]];then
        common_logger "Removing Wazuh manager."
        eval "dpkg --remove wazuh-manager"
        common_logger "Wazuh manager removed."
    fi

    if [[ ( -n "${wazuh_remaining_files}"  || -n "${wazuh_installed}" ) && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/ossec/ ${debug}"
    fi

    if [[ -n "${indexer_installed}" && ( -n "${indexer}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        common_logger "Removing Wazuh indexer."

        eval "dpkg --remove wazuh-indexer"

        common_logger "Wazuh indexer removed."
    fi

    if [[ ( -n "${indexer_remaining_files}" || -n "${indexer_installed}" ) && ( -n "${indexer}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/lib/wazuh-indexer/ ${debug}"
        eval "rm -rf /usr/share/wazuh-indexer/ ${debug}"
        eval "rm -rf /etc/wazuh-indexer/ ${debug}"
    fi

    if [[ -n "${filebeat_installed}" && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        common_logger "Removing Filebeat."
        
        eval "dpkg --remove filebeat"

        common_logger "Filebeat removed."
    fi

    if [[ ( -n "${filebeat_remaining_files}" || -n "${filebeat_installed}" ) && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/lib/filebeat/ ${debug}"
        eval "rm -rf /usr/share/filebeat/ ${debug}"
        eval "rm -rf /etc/filebeat/ ${debug}"
    fi

    if [[ -n "${dashboard_installed}" && ( -n "${dashboard}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        common_logger "Removing Wazuh dashboard."
        
        eval "dpkg --remove wazuh-dashboard"

        common_logger "Wazuh dashboard removed."
    fi

    if [[ ( -n "${dashboard_remaining_files}" || -n "${dashboard_installed}" ) && ( -n "${dashboard}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/lib/wazuh-dashboard/ ${debug}"
        eval "rm -rf /usr/share/wazuh-dashboard/ ${debug}"
        eval "rm -rf /etc/wazuh-dashboard/ ${debug}"
        eval "rm -rf /run/wazuh-dashboard/ ${debug}"
    fi

    elements_to_remove=(    "/var/log/wazuh-indexer/"
                            "/var/log/filebeat/"
                            "/etc/systemd/system/opensearch.service.wants/"
                            "/securityadmin_demo.sh"
                            "/etc/systemd/system/multi-user.target.wants/wazuh-manager.service"
                            "/etc/systemd/system/multi-user.target.wants/filebeat.service"
                            "/etc/systemd/system/multi-user.target.wants/opensearch.service"
                            "/etc/systemd/system/multi-user.target.wants/wazuh-dashboard.service"
                            "/etc/systemd/system/wazuh-dashboard.service"
                            "/lib/firewalld/services/dashboard.xml"
                            "/lib/firewalld/services/opensearch.xml" )

    eval "rm -rf ${elements_to_remove[*]}"


    eval "systemctl daemon-reload ${debug}"

    if [ -z "${uninstall}" ]; then
        if [ -n "${rollback_conf}" ] || [ -n "${overwrite}" ]; then
            common_logger "Installation cleaned."
        else
            common_logger "Installation cleaned. Check the ${logfile} file to learn more about the issue."
        fi
    fi

}

function common_checkInstalled() {

    wazuh_installed=""
    indexer_installed=""
    filebeat_installed=""
    dashboard_installed=""

    wazuh_installed=$(dpkg --get-selections 2>/dev/null | grep wazuh-manager)
    indexer_installed=$(dpkg --get-selections 2>/dev/null | grep wazuh-indexer)
    filebeat_installed=$(dpkg --get-selections 2>/dev/null | grep filebeat)
    dashboard_installed=$(dpkg --get-selections 2>/dev/null | grep wazuh-dashboard)


    # if [ "${sys_type}" == "yum" ]; then
    #     wazuh_installed=$(yum list installed 2>/dev/null | grep wazuh-manager)
    # elif [ "${sys_type}" == "apt-get" ]; then
    #     wazuh_installed=$(apt list --installed  2>/dev/null | grep wazuh-manager)
    # fi

    if [ -d "/var/ossec" ]; then
        wazuh_remaining_files=1
    fi

    # if [ "${sys_type}" == "yum" ]; then
    #     indexer_installed=$(yum list installed 2>/dev/null | grep wazuh-indexer)
    # elif [ "${sys_type}" == "apt-get" ]; then
    #     indexer_installed=$(apt list --installed 2>/dev/null | grep wazuh-indexer)
    # fi

    if [ -d "/var/lib/wazuh-indexer/" ] || [ -d "/usr/share/wazuh-indexer" ] || [ -d "/etc/wazuh-indexer" ] || [ -f "${base_path}/search-guard-tlstool*" ]; then
        indexer_remaining_files=1
    fi

    # if [ "${sys_type}" == "yum" ]; then
    #     filebeat_installed=$(yum list installed 2>/dev/null | grep filebeat)
    # elif [ "${sys_type}" == "apt-get" ]; then
    #     filebeat_installed=$(apt list --installed  2>/dev/null | grep filebeat)
    # fi

    if [ -d "/var/lib/filebeat/" ] || [ -d "/usr/share/filebeat" ] || [ -d "/etc/filebeat" ]; then
        filebeat_remaining_files=1
    fi

    # if [ "${sys_type}" == "yum" ]; then
    #     dashboard_installed=$(yum list installed 2>/dev/null | grep wazuh-dashboard)
    # elif [ "${sys_type}" == "apt-get" ]; then
    #     dashboard_installed=$(apt list --installed  2>/dev/null | grep wazuh-dashboard)
    # fi

    if [ -d "/var/lib/wazuh-dashboard/" ] || [ -d "/usr/share/wazuh-dashboard" ] || [ -d "/etc/wazuh-dashboard" ] || [ -d "/run/wazuh-dashboard/" ]; then
        dashboard_remaining_files=1
    fi

}

function indexer_install() {

    common_logger "Starting Wazuh indexer installation."

    # if [ "${sys_type}" == "yum" ]; then
    #     eval "yum install wazuh-indexer-${wazuh_version} -y ${debug}"
    #     install_result="${PIPESTATUS[0]}"
    # elif [ "${sys_type}" == "apt-get" ]; then
    #     installCommon_aptInstall "wazuh-indexer" "${wazuh_version}-*"
    # fi

    eval "dpkg -i ./wazuh-offline/wazuh-packages/wazuh-indexer*.deb"
    install_result="${PIPESTATUS[0]}"
    common_checkInstalled
    if [  "$install_result" != 0  ] || [ -z "${indexer_installed}" ]; then
        common_logger -e "Wazuh indexer installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh indexer installation finished."
    fi

    eval "sysctl -q -w vm.max_map_count=262144 ${debug}"

}
function indexer_copyCertificates() {

    eval "rm -f ${indexer_cert_path}/* ${debug}"
    name=${indexer_node_names[pos]}

    if [ -f "${tar_file}" ]; then
        if ! tar -tvf "${tar_file}" | grep -q "${name}" ; then
            common_logger -e "Tar file does not contain certificate for the node ${name}."
            installCommon_rollBack
            exit 1;
        fi
        eval "mkdir ${indexer_cert_path} ${debug}"
        eval "sed -i s/indexer.pem/${name}.pem/ /etc/wazuh-indexer/opensearch.yml ${debug}"
        eval "sed -i s/indexer-key.pem/${name}-key.pem/ /etc/wazuh-indexer/opensearch.yml ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/${name}.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/${name}-key.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/root-ca.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/admin.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/admin-key.pem --strip-components 1 ${debug}"
        eval "rm -rf ${indexer_cert_path}/wazuh-install-files/"
        eval "chown -R wazuh-indexer:wazuh-indexer ${indexer_cert_path} ${debug}"
        eval "chmod 500 ${indexer_cert_path} ${debug}"
        eval "chmod 400 ${indexer_cert_path}/* ${debug}"
    else
        common_logger -e "No certificates found. Could not initialize Wazuh indexer"
        installCommon_rollBack
        exit 1;
    fi

}
function installCommon_getConfig() {

    if [ "$#" -ne 2 ]; then
        common_logger -e "installCommon_getConfig should be called with two arguments"
        exit 1
    fi

    config_name="config_file_$(eval "echo ${1} | sed 's|/|_|g;s|.yml||'")"
    if [ -z "$(eval "echo \${${config_name}}")" ]; then
        common_logger -e "Unable to find configuration file ${1}. Exiting."
        installCommon_rollBack
        exit 1
    fi
    eval "echo \"\${${config_name}}\"" > "${2}"
}
function installCommon_getPass() {

    for i in "${!users[@]}"; do
        if [ "${users[i]}" == "${1}" ]; then
            u_pass=${passwords[i]}
        fi
    done
}
# ------------ indexer.sh ------------ 
function indexer_configure() {

    common_logger -d "Configuring Wazuh indexer."
    eval "export JAVA_HOME=/usr/share/wazuh-indexer/jdk/"

    # Configure JVM options for Wazuh indexer
    ram_mb=$(free -m | awk '/^Mem:/{print $2}')
    ram="$(( ram_mb / 2 ))"

    if [ "${ram}" -eq "0" ]; then
        ram=1024;
    fi
    eval "sed -i "s/-Xmx1g/-Xmx${ram}m/" /etc/wazuh-indexer/jvm.options ${debug}"
    eval "sed -i "s/-Xmx1g/-Xmx${ram}m/" /etc/wazuh-indexer/jvm.options ${debug}"


    # eval "installCommon_getConfig indexer/indexer_all_in_one.yml /etc/wazuh-indexer/opensearch.yml ${debug}"

    # if [ -n "${AIO}" ]; then
    #     eval "installCommon_getConfig indexer/indexer_all_in_one.yml /etc/wazuh-indexer/opensearch.yml ${debug}"
    # else
    #     eval "installCommon_getConfig indexer/indexer_unattended_distributed.yml /etc/wazuh-indexer/opensearch.yml ${debug}"
    #     if [ "${#indexer_node_names[@]}" -eq 1 ]; then
    #         pos=0
    #         {
    #         echo "node.name: ${indxname}"
    #         echo "network.host: ${indexer_node_ips[0]}"
    #         echo "cluster.initial_master_nodes: ${indxname}"
    #         echo "plugins.security.nodes_dn:"
    #         echo '        - CN='"${indxname}"',OU=Wazuh,O=Wazuh,L=California,C=US'
    #         } >> /etc/wazuh-indexer/opensearch.yml
    #     else
    #         echo "node.name: ${indxname}" >> /etc/wazuh-indexer/opensearch.yml
    #         echo "cluster.initial_master_nodes:" >> /etc/wazuh-indexer/opensearch.yml
    #         for i in "${indexer_node_names[@]}"; do
    #             echo "        - ${i}" >> /etc/wazuh-indexer/opensearch.yml
    #         done

    #         echo "discovery.seed_hosts:" >> /etc/wazuh-indexer/opensearch.yml
    #         for i in "${indexer_node_ips[@]}"; do
    #             echo "        - ${i}" >> /etc/wazuh-indexer/opensearch.yml
    #         done

    #         for i in "${!indexer_node_names[@]}"; do
    #             if [[ "${indexer_node_names[i]}" == "${indxname}" ]]; then
    #                 pos="${i}";
    #             fi
    #         done

    #         echo "network.host: ${indexer_node_ips[pos]}" >> /etc/wazuh-indexer/opensearch.yml

    #         echo "plugins.security.nodes_dn:" >> /etc/wazuh-indexer/opensearch.yml
    #         for i in "${indexer_node_names[@]}"; do
    #                 echo "        - CN=${i},OU=Wazuh,O=Wazuh,L=California,C=US" >> /etc/wazuh-indexer/opensearch.yml
    #         done
    #     fi
    # fi

    # indexer_copyCertificates


    common_logger "Moving certs"

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

    # jv=$(java -version 2>&1 | grep -o -m1 '1.8.0' )
    # if [ "$jv" == "1.8.0" ]; then
    #     {
    #     echo "wazuh-indexer hard nproc 4096"
    #     echo "wazuh-indexer soft nproc 4096"
    #     echo "wazuh-indexer hard nproc 4096"
    #     echo "wazuh-indexer soft nproc 4096"
    #     } >> /etc/security/limits.conf
    #     echo -ne "\nbootstrap.system_call_filter: false" >> /etc/wazuh-indexer/opensearch.yml
    # fi

    common_logger "Wazuh indexer post-install configuration finished."
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
function manager_install() {

    common_logger "Starting the Wazuh manager installation."
    # if [ "${sys_type}" == "yum" ]; then
    #     eval "${sys_type} install wazuh-manager${sep}${wazuh_version} -y ${debug}"
    #     install_result="${PIPESTATUS[0]}"
    # elif [ "${sys_type}" == "apt-get" ]; then
    #     installCommon_aptInstall "wazuh-manager" "${wazuh_version}-*"
    # fi

    # eval "dpkg -i ./wazuh-offline/wazuh-packages/wazuh-manager*.deb"

    cd 'wazuh-4.7.0'

    . "./install.sh"
    install_result="${PIPESTATUS[0]}"
    cd '..'

    common_checkInstalled
    if [  "$install_result" != 0  ] || [ -z "${wazuh_installed}" ]; then
        common_logger -e "Wazuh installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh manager installation finished."
    fi
}
function common_checkSystem() {

    if [ -n "$(command -v dpkg)" ]; then
        sys_type="dpkg"
        sep="-"
    else
        common_logger -e "Couldn't find type of system"
        exit 1
    fi

}


function indexer_initialize() {

    common_logger "Initializing Wazuh indexer cluster security settings."
    eval "common_curl -XGET https://localhost:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null"
    e_code="${PIPESTATUS[0]}"

    if [ "${e_code}" -ne "0" ]; then
        common_logger -e "Cannot initialize Wazuh indexer cluster."
        installCommon_rollBack
        exit 1
    fi

    if [ -n "${AIO}" ]; then
        eval "sudo -u wazuh-indexer JAVA_HOME=/usr/share/wazuh-indexer/jdk/ OPENSEARCH_CONF_DIR=/etc/wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /etc/wazuh-indexer/opensearch-security -icl -p 9200 -nhnv -cacert ${indexer_cert_path}/root-ca.pem -cert ${indexer_cert_path}/admin.pem -key ${indexer_cert_path}/admin-key.pem -h 127.0.0.1 ${debug}"
    fi


    common_logger "Wazuh indexer cluster initialized."

}
function filebeat_install() {

    common_logger "Starting Filebeat installation."
    # if [ "${sys_type}" == "yum" ]; then
    #     eval "yum install filebeat${sep}${filebeat_version} -y -q  ${debug}"
    #     install_result="${PIPESTATUS[0]}"
    # elif [ "${sys_type}" == "apt-get" ]; then
    #     installCommon_aptInstall "filebeat" "${filebeat_version}"
    # fi
    eval "dpkg -i ./wazuh-offline/wazuh-packages/filebeat*.deb"
    install_result="${PIPESTATUS[0]}"
    common_checkInstalled
    if [  "$install_result" != 0  ] || [ -z "${filebeat_installed}" ]; then
        common_logger -e "Filebeat installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Filebeat installation finished."
    fi

}

function filebeat_configure(){

    # eval "common_curl -so /etc/filebeat/wazuh-template.json ${filebeat_wazuh_template} --max-time 300 --retry 5 --retry-delay 5 --fail ${debug}"
    # if [ ! -f "/etc/filebeat/wazuh-template.json" ]; then
    #     common_logger -e "Error downloading wazuh-template.json file."
    #     installCommon_rollBack
    #     exit 1
    # fi

    # eval "chmod go+r /etc/filebeat/wazuh-template.json ${debug}"
    # eval "common_curl -s ${filebeat_wazuh_module} --max-time 300 --retry 5 --retry-delay 5 --fail | tar -xvz -C /usr/share/filebeat/module ${debug}"
    # if [ ! -d "/usr/share/filebeat/module" ]; then
    #     common_logger -e "Error downloading wazuh filebeat module."
    #     installCommon_rollBack
    #     exit 1
    # fi

    # if [ -n "${AIO}" ]; then
    #     eval "installCommon_getConfig /wazuh-offline/wazuh-files/filebeat.yml /etc/filebeat/filebeat.yml ${debug}"
    # else
    #     eval "installCommon_getConfig filebeat/filebeat_distributed.yml /etc/filebeat/filebeat.yml ${debug}"
    #     if [ ${#indexer_node_names[@]} -eq 1 ]; then
    #         echo -e "\noutput.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
    #         echo "  - ${indexer_node_ips[0]}:9200" >> /etc/filebeat/filebeat.yml
    #     else
    #         echo -e "\noutput.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
    #         for i in "${indexer_node_ips[@]}"; do
    #             echo "  - ${i}:9200" >> /etc/filebeat/filebeat.yml
    #         done
    #     fi
    # fi


    eval "cp ./wazuh-offline/wazuh-files/filebeat.yml /etc/filebeat/ &&\
cp ./wazuh-offline/wazuh-files/wazuh-template.json /etc/filebeat/ &&\
chmod go+r /etc/filebeat/wazuh-template.json"

    # filebeat_copyCertificates

    eval "filebeat keystore create ${debug}"
    eval "echo admin | filebeat keystore add username --force --stdin ${debug}"
    eval "echo admin | filebeat keystore add password --force --stdin ${debug}"


    eval "tar -xzf ./wazuh-offline/wazuh-files/wazuh-filebeat-0.3.tar.gz -C /usr/share/filebeat/module"

    eval "mkdir /etc/filebeat/certs"
    eval "mv -n wazuh-certificates/${NODE_NAME}.pem /etc/filebeat/certs/filebeat.pem"
    eval "mv -n wazuh-certificates/${NODE_NAME}-key.pem /etc/filebeat/certs/filebeat-key.pem"
    eval "cp wazuh-certificates/root-ca.pem /etc/filebeat/certs/"
    eval "chmod 500 /etc/filebeat/certs"
    eval "chmod 400 /etc/filebeat/certs/*"
    eval "chown -R root:root /etc/filebeat/certs"

    common_logger "Filebeat post-install configuration finished."
}

function dashboard_install() {

    common_logger "Starting Wazuh dashboard installation."
    # if [ "${sys_type}" == "yum" ]; then
    #     eval "yum install wazuh-dashboard${sep}${wazuh_version} -y ${debug}"
    #     install_result="${PIPESTATUS[0]}"
    # elif [ "${sys_type}" == "apt-get" ]; then
    #     installCommon_aptInstall "wazuh-dashboard" "${wazuh_version}-*"
    # fi

    eval "dpkg -i ./wazuh-offline/wazuh-packages/wazuh-dashboard*.deb"
    install_result="${PIPESTATUS[0]}"
    

    common_checkInstalled
    if [  "$install_result" != 0  ] || [ -z "${dashboard_installed}" ]; then
        common_logger -e "Wazuh dashboard installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh dashboard installation finished."
    fi

}
function dashboard_configure() {

    # if [ -n "${AIO}" ]; then
    #     eval "installCommon_getConfig dashboard/dashboard_unattended.yml /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"
    #     dashboard_copyCertificates
    # else
    #     eval "installCommon_getConfig dashboard/dashboard_unattended_distributed.yml /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"
    #     dashboard_copyCertificates
    #     if [ "${#dashboard_node_names[@]}" -eq 1 ]; then
    #         pos=0
    #         ip=${dashboard_node_ips[0]}
    #     else
    #         for i in "${!dashboard_node_names[@]}"; do
    #             if [[ "${dashboard_node_names[i]}" == "${dashname}" ]]; then
    #                 pos="${i}";
    #             fi
    #         done
    #         ip=${dashboard_node_ips[pos]}
    #     fi

    #     if [[ "${ip}" != "127.0.0.1" ]]; then
    #         echo "server.host: ${ip}" >> /etc/wazuh-dashboard/opensearch_dashboards.yml
    #     else
    #         echo 'server.host: '0.0.0.0'' >> /etc/wazuh-dashboard/opensearch_dashboards.yml
    #     fi

    #     if [ "${#indexer_node_names[@]}" -eq 1 ]; then
    #         echo "opensearch.hosts: https://${indexer_node_ips[0]}:9200" >> /etc/wazuh-dashboard/opensearch_dashboards.yml
    #     else
    #         echo "opensearch.hosts:" >> /etc/wazuh-dashboard/opensearch_dashboards.yml
    #         for i in "${indexer_node_ips[@]}"; do
    #                 echo "  - https://${i}:9200" >> /etc/wazuh-dashboard/opensearch_dashboards.yml
    #         done
    #     fi
    # fi
    eval "mkdir /etc/wazuh-dashboard/certs"
    eval "mv -n wazuh-certificates/${NODE_NAME}.pem /etc/wazuh-dashboard/certs/dashboard.pem"
    eval "mv -n wazuh-certificates/${NODE_NAME}-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem"
    eval "cp wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/"
    eval "chmod 500 /etc/wazuh-dashboard/certs"
    eval "chmod 400 /etc/wazuh-dashboard/certs/*"
    eval "chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs"



    sed -i 's/server\.port: [0-9]\+$/server.port: '"${chosen_port}"'/' /etc/wazuh-dashboard/opensearch_dashboards.yml

    common_logger "Wazuh dashboard post-install configuration finished."

}

function installCommon_changePasswords() {

    common_logger -d "Setting Wazuh indexer cluster passwords."
    eval "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh --change-all --admin-user wazuh --admin-password wazuh"

}

function checks_ports() {

    used_port=0
    ports=("$@")

    checks_firewall "${ports[@]}"

    if command -v lsof > /dev/null; then
        port_command="lsof -sTCP:LISTEN  -i:"
    else
        common_logger -w "Cannot find lsof. Port checking will be skipped."
        return 1
    fi

    for i in "${!ports[@]}"; do
        if eval "${port_command}""${ports[i]}" > /dev/null; then
            used_port=1
            common_logger -e "Port ${ports[i]} is being used by another process. Please, check it before installing Wazuh."
        fi
    done

    if [ "${used_port}" -eq 1 ]; then
        common_logger "The installation can not continue due to port usage by other processes."
        installCommon_rollBack
        exit 1
    fi

}
function dashboard_initializeAIO() {

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
# function cert_convertCRLFtoLF() {
#     if [[ ! -d "/tmp/wazuh-install-files" ]]; then
#         mkdir "/tmp/wazuh-install-files"
#     fi
#     eval "chmod -R 755 /tmp/wazuh-install-files ${debug}"
#     eval "tr -d '\015' < $1 > /tmp/wazuh-install-files/new_config.yml"
#     eval "mv /tmp/wazuh-install-files/new_config.yml $1"
# }
# function cert_parseYaml() {

#     local prefix=$2
#     local separator=${3:-_}
#     local indexfix
#     # Detect awk flavor
#     if awk --version 2>&1 | grep -q "GNU Awk" ; then
#     # GNU Awk detected
#     indexfix=-1
#     elif awk -Wv 2>&1 | grep -q "mawk" ; then
#     # mawk detected
#     indexfix=0
#     fi

#     local s='[[:space:]]*' sm='[ \t]*' w='[a-zA-Z0-9_]*' fs=${fs:-$(echo @|tr @ '\034')} i=${i:-  }
#     cat $1 2>/dev/null | \
#     awk -F$fs "{multi=0; 
#         if(match(\$0,/$sm\|$sm$/)){multi=1; sub(/$sm\|$sm$/,\"\");}
#         if(match(\$0,/$sm>$sm$/)){multi=2; sub(/$sm>$sm$/,\"\");}
#         while(multi>0){
#             str=\$0; gsub(/^$sm/,\"\", str);
#             indent=index(\$0,str);
#             indentstr=substr(\$0, 0, indent+$indexfix) \"$i\";
#             obuf=\$0;
#             getline;
#             while(index(\$0,indentstr)){
#                 obuf=obuf substr(\$0, length(indentstr)+1);
#                 if (multi==1){obuf=obuf \"\\\\n\";}
#                 if (multi==2){
#                     if(match(\$0,/^$sm$/))
#                         obuf=obuf \"\\\\n\";
#                         else obuf=obuf \" \";
#                 }
#                 getline;
#             }
#             sub(/$sm$/,\"\",obuf);
#             print obuf;
#             multi=0;
#             if(match(\$0,/$sm\|$sm$/)){multi=1; sub(/$sm\|$sm$/,\"\");}
#             if(match(\$0,/$sm>$sm$/)){multi=2; sub(/$sm>$sm$/,\"\");}
#         }
#     print}" | \
#     sed  -e "s|^\($s\)?|\1-|" \
#         -ne "s|^$s#.*||;s|$s#[^\"']*$||;s|^\([^\"'#]*\)#.*|\1|;t1;t;:1;s|^$s\$||;t2;p;:2;d" | \
#     sed -ne "s|,$s\]$s\$|]|" \
#         -e ":1;s|^\($s\)\($w\)$s:$s\(&$w\)\?$s\[$s\(.*\)$s,$s\(.*\)$s\]|\1\2: \3[\4]\n\1$i- \5|;t1" \
#         -e "s|^\($s\)\($w\)$s:$s\(&$w\)\?$s\[$s\(.*\)$s\]|\1\2: \3\n\1$i- \4|;" \
#         -e ":2;s|^\($s\)-$s\[$s\(.*\)$s,$s\(.*\)$s\]|\1- [\2]\n\1$i- \3|;t2" \
#         -e "s|^\($s\)-$s\[$s\(.*\)$s\]|\1-\n\1$i- \2|;p" | \
#     sed -ne "s|,$s}$s\$|}|" \
#         -e ":1;s|^\($s\)-$s{$s\(.*\)$s,$s\($w\)$s:$s\(.*\)$s}|\1- {\2}\n\1$i\3: \4|;t1" \
#         -e "s|^\($s\)-$s{$s\(.*\)$s}|\1-\n\1$i\2|;" \
#         -e ":2;s|^\($s\)\($w\)$s:$s\(&$w\)\?$s{$s\(.*\)$s,$s\($w\)$s:$s\(.*\)$s}|\1\2: \3 {\4}\n\1$i\5: \6|;t2" \
#         -e "s|^\($s\)\($w\)$s:$s\(&$w\)\?$s{$s\(.*\)$s}|\1\2: \3\n\1$i\4|;p" | \
#     sed  -e "s|^\($s\)\($w\)$s:$s\(&$w\)\(.*\)|\1\2:\4\n\3|" \
#         -e "s|^\($s\)-$s\(&$w\)\(.*\)|\1- \3\n\2|" | \
#     sed -ne "s|^\($s\):|\1|" \
#         -e "s|^\($s\)\(---\)\($s\)||" \
#         -e "s|^\($s\)\(\.\.\.\)\($s\)||" \
#         -e "s|^\($s\)-$s[\"']\(.*\)[\"']$s\$|\1$fs$fs\2|p;t" \
#         -e "s|^\($s\)\($w\)$s:$s[\"']\(.*\)[\"']$s\$|\1$fs\2$fs\3|p;t" \
#         -e "s|^\($s\)-$s\(.*\)$s\$|\1$fs$fs\2|" \
#         -e "s|^\($s\)\($w\)$s:$s[\"']\?\(.*\)$s\$|\1$fs\2$fs\3|" \
#         -e "s|^\($s\)[\"']\?\([^&][^$fs]\+\)[\"']$s\$|\1$fs$fs$fs\2|" \
#         -e "s|^\($s\)[\"']\?\([^&][^$fs]\+\)$s\$|\1$fs$fs$fs\2|" \
#         -e "s|$s\$||p" | \
#     awk -F$fs "{
#         gsub(/\t/,\"        \",\$1);
#         gsub(\"name: \", \"\");
#         if(NF>3){if(value!=\"\"){value = value \" \";}value = value  \$4;}
#         else {
#         if(match(\$1,/^&/)){anchor[substr(\$1,2)]=full_vn;getline};
#         indent = length(\$1)/length(\"$i\");
#         vname[indent] = \$2;
#         value= \$3;
#         for (i in vname) {if (i > indent) {delete vname[i]; idx[i]=0}}
#         if(length(\$2)== 0){  vname[indent]= ++idx[indent] };
#         vn=\"\"; for (i=0; i<indent; i++) { vn=(vn)(vname[i])(\"$separator\")}
#         vn=\"$prefix\" vn;
#         full_vn=vn vname[indent];
#         if(vn==\"$prefix\")vn=\"$prefix$separator\";
#         if(vn==\"_\")vn=\"__\";
#         }
#         assignment[full_vn]=value;
#         if(!match(assignment[vn], full_vn))assignment[vn]=assignment[vn] \" \" full_vn;
#         if(match(value,/^\*/)){
#             ref=anchor[substr(value,2)];
#             if(length(ref)==0){
#             printf(\"%s=\\\"%s\\\"\n\", full_vn, value);
#             } else {
#             for(val in assignment){
#                 if((length(ref)>0)&&index(val, ref)==1){
#                     tmpval=assignment[val];
#                     sub(ref,full_vn,val);
#                 if(match(val,\"$separator\$\")){
#                     gsub(ref,full_vn,tmpval);
#                 } else if (length(tmpval) > 0) {
#                     printf(\"%s=\\\"%s\\\"\n\", val, tmpval);
#                 }
#                 assignment[val]=tmpval;
#                 }
#             }
#         }
#     } else if (length(value) > 0) {
#         printf(\"%s=\\\"%s\\\"\n\", full_vn, value);
#     }
#     }END{
#         for(val in assignment){
#             if(match(val,\"$separator\$\"))
#                 printf(\"%s=\\\"%s\\\"\n\", val, assignment[val]);
#         }
#     }"

# }
# function cert_readConfig() {

#     if [ -f "${config_file}" ]; then
#         if [ ! -s "${config_file}" ]; then
#             common_logger -e "File ${config_file} is empty"
#             exit 1
#         fi
#         eval "$(cert_convertCRLFtoLF "${config_file}")"

#         eval "indexer_node_names=( $(cert_parseYaml "${config_file}" | grep -E "nodes[_]+indexer[_]+[0-9]+=" | cut -d = -f 2 ) )"
#         eval "server_node_names=( $(cert_parseYaml "${config_file}"  | grep -E "nodes[_]+server[_]+[0-9]+=" | cut -d = -f 2 ) )"
#         eval "dashboard_node_names=( $(cert_parseYaml "${config_file}" | grep -E "nodes[_]+dashboard[_]+[0-9]+=" | cut -d = -f 2) )"
#         eval "indexer_node_ips=( $(cert_parseYaml "${config_file}" | grep -E "nodes[_]+indexer[_]+[0-9]+[_]+ip=" | cut -d = -f 2) )"
#         eval "server_node_ips=( $(cert_parseYaml "${config_file}"  | grep -E "nodes[_]+server[_]+[0-9]+[_]+ip=" | cut -d = -f 2) )"
#         eval "dashboard_node_ips=( $(cert_parseYaml "${config_file}"  | grep -E "nodes[_]+dashboard[_]+[0-9]+[_]+ip=" | cut -d = -f 2 ) )"
#         eval "server_node_types=( $(cert_parseYaml "${config_file}"  | grep -E "nodes[_]+server[_]+[0-9]+[_]+node_type=" | cut -d = -f 2 ) )"
#         eval "number_server_ips=( $(cert_parseYaml "${config_file}" | grep -o -E 'nodes[_]+server[_]+[0-9]+[_]+ip' | sort -u | wc -l) )"

#         for i in $(seq 1 "${number_server_ips}"); do
#             nodes_server="nodes[_]+server[_]+${i}[_]+ip"
#             eval "server_node_ip_$i=( $( cert_parseYaml "${config_file}" | grep -E "${nodes_server}" | sed '/\./!d' | cut -d = -f 2 | sed -r 's/\s+//g') )"
#         done

#         unique_names=($(echo "${indexer_node_names[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
#         if [ "${#unique_names[@]}" -ne "${#indexer_node_names[@]}" ]; then 
#             common_logger -e "Duplicated indexer node names."
#             exit 1
#         fi

#         unique_ips=($(echo "${indexer_node_ips[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
#         if [ "${#unique_ips[@]}" -ne "${#indexer_node_ips[@]}" ]; then 
#             common_logger -e "Duplicated indexer node ips."
#             exit 1
#         fi

#         unique_names=($(echo "${server_node_names[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
#         if [ "${#unique_names[@]}" -ne "${#server_node_names[@]}" ]; then 
#             common_logger -e "Duplicated Wazuh server node names."
#             exit 1
#         fi

#         unique_ips=($(echo "${server_node_ips[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
#         if [ "${#unique_ips[@]}" -ne "${#server_node_ips[@]}" ]; then 
#             common_logger -e "Duplicated Wazuh server node ips."
#             exit 1
#         fi

#         unique_names=($(echo "${dashboard_node_names[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
#         if [ "${#unique_names[@]}" -ne "${#dashboard_node_names[@]}" ]; then
#             common_logger -e "Duplicated dashboard node names."
#             exit 1
#         fi

#         unique_ips=($(echo "${dashboard_node_ips[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
#         if [ "${#unique_ips[@]}" -ne "${#dashboard_node_ips[@]}" ]; then
#             common_logger -e "Duplicated dashboard node ips."
#             exit 1
#         fi

#         for i in "${server_node_types[@]}"; do
#             if ! echo "$i" | grep -ioq master && ! echo "$i" | grep -ioq worker; then
#                 common_logger -e "Incorrect node_type $i must be master or worker"
#                 exit 1
#             fi
#         done

#         if [ "${#server_node_names[@]}" -le 1 ]; then
#             if [ "${#server_node_types[@]}" -ne 0 ]; then
#                 common_logger -e "The tag node_type can only be used with more than one Wazuh server."
#                 exit 1
#             fi
#         elif [ "${#server_node_names[@]}" -gt "${#server_node_types[@]}" ]; then
#             common_logger -e "The tag node_type needs to be specified for all Wazuh server nodes."
#             exit 1
#         elif [ "${#server_node_names[@]}" -lt "${#server_node_types[@]}" ]; then
#             common_logger -e "Found extra node_type tags."
#             exit 1
#         elif [ "$(grep -io master <<< "${server_node_types[*]}" | wc -l)" -ne 1 ]; then
#             common_logger -e "Wazuh cluster needs a single master node."
#             exit 1
#         elif [ "$(grep -io worker <<< "${server_node_types[*]}" | wc -l)" -ne $(( ${#server_node_types[@]} - 1 )) ]; then
#             common_logger -e "Incorrect number of workers."
#             exit 1
#         fi

#         if [ "${#dashboard_node_names[@]}" -ne "${#dashboard_node_ips[@]}" ]; then
#             common_logger -e "Different number of dashboard node names and IPs."
#             exit 1
#         fi

#     else
#         common_logger -e "No configuration file found."
#         exit 1
#     fi

# }

function main(){

    umask 177

    AIO=1

    cat /dev/null > "${logfile}"


    common_logger "Starting Wazuh installation assistant. Wazuh version: ${wazuh_version}"
    common_logger "Verbose logging redirected to ${logfile}"
    common_logger "Wazuh version: ${wazuh_version}"
    common_logger "Filebeat version: ${filebeat_version}"
    common_logger "Wazuh installation assistant version: ${wazuh_install_vesion}"
    common_checkSystem

    dashboard_changePort "${http_port}"

    checks_ports "${wazuh_aio_ports[@]}"

    common_logger "--- Wazuh indexer ---"
    indexer_install
    indexer_configure
    installCommon_startService "wazuh-indexer"
    indexer_initialize
    common_logger "--- Wazuh server ---"
    manager_install
    installCommon_startService "wazuh-manager"
    filebeat_install
    filebeat_configure
    installCommon_startService "filebeat"
    common_logger "--- Wazuh dashboard ---"
    dashboard_install
    dashboard_configure
    installCommon_startService "wazuh-dashboard"
    installCommon_changePasswords
    dashboard_initializeAIO

    




}


main "$@"
