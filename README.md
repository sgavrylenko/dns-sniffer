## Description
`dns-sniffer` witching DNS requests on interface via pcap lib and logging theme in Elasticsearch

## Arguments
 - `-i` - Listening on interface ("eth0")
 - `-e` - Hostname of Elastic service ("127.0.0.1")
 - `-u` - Elastic username ("logstash")
 - `-p` - Elastic password ("logastash")
 - `-s` - Elastic index name ("dns_index")
 - `-t` - Elastic document type ("syslog")
 - `-x` - Set destination network ("0.0.0.0/0")
 - `-v` - Show dumped requests in console ("false")