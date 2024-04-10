#include "Net.h"
#include <cstdlib>
#include <pthread.h>
#include <unistd.h>

using namespace std;

void* arp_spoofing(void*);
Net* net;

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
            if (false/*TODO*/) {
                /* TODO: Not to forward the packet*/
            }
            else net->forward_ipv4(&buf, len); 
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