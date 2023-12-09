## Install 

1. **Run step to install wazuh from package**

    ```sh
        chmod 700 ./setup.sh
        ./setup.sh
    ```
    The custom script should config adjust configs to be all in one. 



2. **Run wazuh update password tool to secure wazuh**

    ```sh
    /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh --change-all --admin-user wazuh --admin-password wazuh
    ```





After running the custom_install script if config fails

1. **Edit /etc/wazuh-indexer/opensearch.yml and replace the following values:**
    network.host: Sets the address of this node for both HTTP and transport traffic. The node will bind to this address and will also use it as its publish address. Accepts an IP address or a hostname.

    Use the same node address set in config.yml to create the SSL certificates.

    node.name: Name of the Wazuh indexer node as defined in the config.yml file. For example, node-1.

    cluster.initial_master_nodes: List of the names of the master-eligible nodes. These names are defined in the config.yml file. 


    cluster.initial_master_nodes:
    - "node-1"
    
    plugins.security.nodes_dn: List of the Distinguished Names of the certificates of all the Wazuh indexer cluster nodes. Uncomment the lines for node-2 and node-3 and change the common names (CN) and values according to your settings and your config.yml definitions.


    plugins.security.nodes_dn:
    - "CN=node-1,OU=Wazuh,O=Wazuh,L=California,C=US"

    ```sh
        systemctl daemon-reload
        systemctl enable wazuh-indexer
        systemctl start wazuh-indexer
    ```

    run this to reload the new certs 
    ```sh
        /usr/share/wazuh-indexer/bin/indexer-security-init.sh
    ```

    Test to make sure it works
    ```sh
        curl -XGET https://localhost:9200 -u admin:admin -k
    ```

2. **Edit the /etc/filebeat/filebeat.yml configuration file and replace the following value:**

    hosts: The list of Wazuh indexer nodes to connect to. You can use either IP addresses or hostnames. By default, the host is set to localhost hosts: ["127.0.0.1:9200"]. Replace it with your Wazuh indexer address accordingly.

    If you have more than one Wazuh indexer node, you can separate the addresses using commas. For example, hosts: ["10.0.0.1:9200", "10.0.0.2:9200", "10.0.0.3:9200"]


     # Wazuh - Filebeat configuration file
     output.elasticsearch:
     hosts: ["10.0.0.1:9200"]
     protocol: https
     username: ${username}
     password: ${password}

    restart filebeats
    ```sh
        systemctl daemon-reload
        systemctl enable filebeat
        systemctl start filebeat
    ```

    test filebeats installed
     ```sh
        filebeat test output
     ```

    check wazuh index integration 
    ```sh
        curl -k -u admin:admin "https://localhost:9200/_template/wazuh?pretty&filter_path=wazuh.settings.index.number_of_shards"
    ```
3. **Edit the /etc/wazuh-dashboard/opensearch_dashboards.yml file and replace the following values**

    server.host: This setting specifies the host of the back end server. To allow remote users to connect, set the value to the IP address or DNS name of the Wazuh dashboard. The value 0.0.0.0 will accept all the available IP addresses of the host.

    opensearch.hosts: The URLs of the Wazuh indexer instances to use for all your queries. The Wazuh dashboard can be configured to connect to multiple Wazuh indexer nodes in the same cluster. The addresses of the nodes can be separated by commas. For example, ["https://10.0.0.2:9200", "https://10.0.0.3:9200","https://10.0.0.4:9200"]


       server.host: 0.0.0.0
       server.port: 443
       opensearch.hosts: https://localhost:9200
       opensearch.ssl.verificationMode: certificate

    ```sh
        systemctl daemon-reload
        systemctl enable wazuh-dashboard
        systemctl start wazuh-dashboard
    ```

4. **Access the web**
    Access the web interface.

    URL: https://<wazuh_server_ip>

    Username: admin

    Password: admin