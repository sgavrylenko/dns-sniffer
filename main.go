package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	devName       string
	esIndex       string
	esDocType     string
	esServer      string
	esUser        string
	esPassword    string
	destNet       string
	verbosity     bool
	err           error
	handle        *pcap.Handle
	SrcIP         string
	DstIP         string
	httpTransport *http.Transport
)

type DnsMsg struct {
	Timestamp       string
	SourceIP        string
	DestinationIP   string
	DnsQuery        string
	DnsAnswer       []string
	DnsAnswerTTL    []string
	NumberOfAnswers string
	DnsResponseCode string
	DnsOpCode       string
}

func sendToElastic(dnsMsg DnsMsg, wg *sync.WaitGroup) {
	defer wg.Done()

	var jsonMsg, jsonErr = json.Marshal(dnsMsg)
	if jsonErr != nil {
		panic(jsonErr)
	}

	// getting ready for elasticsearch
	request, reqErr := http.NewRequest("POST", "https://"+esServer+":9200/"+esIndex+"/"+esDocType,
		bytes.NewBuffer(jsonMsg))
	if reqErr != nil {
		panic(reqErr)
	}

	request.SetBasicAuth(esUser, esPassword)
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Timeout:   60 * time.Second,
		Transport: httpTransport,
	}
	resp, elErr := client.Do(request)

	if elErr != nil {
		panic(elErr)
	}

	defer resp.Body.Close()
}

func main() {

	flag.StringVar(&devName, "i", "eth0", "Listening on interface")
	flag.StringVar(&esServer, "e", "127.0.0.1", "Hostname of Elastic service")
	flag.StringVar(&esUser, "u", "logstash", "Elastic username")
	flag.StringVar(&esPassword, "p", "logstash", "Elastic user password")
	flag.StringVar(&esIndex, "s", "dns_index", "Elastic index name")
	flag.StringVar(&esDocType, "t", "syslog", "Elastic document type")
	flag.StringVar(&destNet, "x", "0.0.0.0/0", "Set destination network")
	flag.BoolVar(&verbosity, "v", false, "Show requests in console")

	flag.Parse()

	httpTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var dns layers.DNS

	var payload gopacket.Payload

	wg := new(sync.WaitGroup)

	// Open device
	handle, err = pcap.OpenLive(devName, 1600, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var filter = fmt.Sprintf("udp and port 53 and dst net %s", destNet)
	fmt.Println("    Filter: ", filter)
	err := handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload)

	decodedLayers := make([]gopacket.LayerType, 0, 10)
	for {
		data, _, err := handle.ReadPacketData()
		if err != nil {
			fmt.Println("Error reading packet data: ", err)
			continue
		}

		err = parser.DecodeLayers(data, &decodedLayers)
		for _, typ := range decodedLayers {
			switch typ {
			case layers.LayerTypeIPv4:
				SrcIP = ip4.SrcIP.String()
				DstIP = ip4.DstIP.String()
			case layers.LayerTypeIPv6:
				SrcIP = ip6.SrcIP.String()
				DstIP = ip6.DstIP.String()
			case layers.LayerTypeDNS:
				dnsOpCode := int(dns.OpCode)
				dnsResponseCode := int(dns.ResponseCode)
				dnsANCount := int(dns.ANCount)

				if (dnsANCount == 0 && dnsResponseCode > 0) || (dnsANCount > 0) {
					if verbosity {
						fmt.Println("------------------------")
						fmt.Println("    DNS Record Detected")
					}
					for _, dnsQuestion := range dns.Questions {

						t := time.Now()
						timestamp := t.Format(time.RFC3339)

						// Add a document to the index
						d := DnsMsg{
							Timestamp:       timestamp,
							SourceIP:        SrcIP,
							DestinationIP:   DstIP,
							DnsQuery:        string(dnsQuestion.Name),
							DnsOpCode:       strconv.Itoa(dnsOpCode),
							DnsResponseCode: strconv.Itoa(dnsResponseCode),
							NumberOfAnswers: strconv.Itoa(dnsANCount),
						}

						if verbosity {
							fmt.Println("    DNS OpCode: ", strconv.Itoa(int(dns.OpCode)))
							fmt.Println("    DNS ResponseCode: ", dns.ResponseCode.String())
							fmt.Println("    DNS # Answers: ", strconv.Itoa(dnsANCount))
							fmt.Println("    DNS Question: ", string(dnsQuestion.Name))
							fmt.Println("    DNS Endpoints: ", SrcIP, DstIP)
						}
						if dnsANCount > 0 {

							for _, dnsAnswer := range dns.Answers {
								d.DnsAnswerTTL = append(d.DnsAnswerTTL, fmt.Sprint(dnsAnswer.TTL))
								if dnsAnswer.IP.String() != "<nil>" {
									if verbosity {
										fmt.Println("    DNS Answer: ", dnsAnswer.IP.String())
									}
									d.DnsAnswer = append(d.DnsAnswer, dnsAnswer.IP.String())
								}
							}

						}

						wg.Add(1)
						sendToElastic(d, wg)

					}
				}

			}
		}

		if err != nil {
			fmt.Println("  Error encountered:", err)
		}
	}
}
