#ifndef NET_H
#define NET_H

#include <iostream>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <map>
#include <net/if.h>
#include <sys/time.h>
using namespace std;

#define ETHERNET 1
#define ARP_REQ 1
#define ARP_REPLY 2
#define ETH_HDR_LEN 14
#define IPV4_HDR_LEN 20
#define ARP_HDR_LEN 28
#define TCP_HDR_LEN 20

#define BUF_SIZE 256
#define ARP_SPOOFING_PERIOD 1000
#define ANSWER_SIZE 4096
#define UDP_HDR_LEN 8

typedef struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} __attribute__((packed)) udphdr;

typedef struct dns_hdr{
    ether_header eth_hdr;
    iphdr ip_hdr;
    udphdr udp_hdr;
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed)) dns_hdr_t;

struct Arp {
    ether_header eth_hdr;
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_length;
    uint8_t protocol_length;
    uint16_t operation;
    uint8_t sender_hardware_addr[ETHER_ADDR_LEN];
    uint32_t sender_protocol_addr;
    uint8_t target_hardware_addr[ETHER_ADDR_LEN];
    uint32_t target_protocol_addr;
    uint8_t padding[18] = {0}; // Padding to 64 byte
} __attribute__((packed));

struct tcp_packet {
    ether_header eth_hdr;
    iphdr ip_hdr;
    tcphdr tcp_hdr;
    char data[ETH_FRAME_LEN - ETH_HDR_LEN - IPV4_HDR_LEN - TCP_HDR_LEN];
} __attribute__((packed));

const uint8_t broadcast_mac[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

class Net {
    public:
        Net();
        Net(string if_name);
        ~Net();
        void print_net_mac();
        void arp_spoofing();
        void forward_ipv4(tcp_packet* buf, int len);
        void get_net_mac(); // Get all other devices' IP/MAC in the network
        uint32_t get_gateway() { return gateway; } // Get the IP of default gateway
        int get_forward_sock() { return forward_sock; }
    private:
        void get_net_info(string if_name); // Get IP, netmask and all other devices' IP/MAC in the network
        void set_socket();
        void get_gateway_ip();
        map<uint32_t, uint8_t*> arp_table;
        uint32_t ip, gateway, mask;
        uint8_t mac[ETHER_ADDR_LEN];
        string if_name;
        int arp_sock, forward_sock;
        sockaddr_ll arp_addr;
        timeval arp_timeout{ .tv_sec = 0, .tv_usec = 3};
};

#endif