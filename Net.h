#ifndef NET_H
#define NET_H

#include <iostream>
#include <netdb.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <map>
#include <sys/time.h>
using namespace std;

#define ETHERNET 1
#define ARP_REQ 1
#define ARP_REPLY 2
#define ETH_HDR_LEN 14
#define IPV4_HDR_LEN 20
#define ARP_HDR_LEN 28

struct Arp {
    ether_header eth_hdr;
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_length;
    uint8_t protocol_length;
    uint16_t operation;
    uint8_t sender_hardware_addr[6];
    uint32_t sender_protocol_addr;
    uint8_t target_hardware_addr[6];
    uint32_t target_protocol_addr;
    uint8_t padding[18] = {0};
} __attribute__((packed));

const uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

class Net {
    public:
        Net();
        Net(string if_name);
        void print_net_mac();
        void arp_spoofing();
        void forward();
        void get_net_mac(); // Get all other devices' IP/MAC in the network
    private:
        void get_netinfo(string if_name); // Get IP, netmask and all other devices' IP/MAC in the network
        void set_arp_socket();
        map<uint32_t, uint8_t*> arp_table;
        uint32_t ip;
        uint32_t mask;
        uint8_t mac[6];
        string if_name;
        int sock, arp_sock;
        sockaddr_ll arp_addr;
        timeval recv_timeout{ .tv_sec = 0, .tv_usec = 3};
};

#endif