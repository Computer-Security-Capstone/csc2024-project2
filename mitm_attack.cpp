#include "Net.h"
using namespace std;

int main(int argc, char** argv){
    Net* net = new Net((argc < 2) ? "" : argv[1]);
    net->get_net_mac();
    net->print_net_mac();
    net->arp_spoofing();
    while (true) {


        break;
        // periodically get using ip and do arp spoofing (must be done frequently enough or the gateway entry will be update)
        net->get_net_mac();
        net->arp_spoofing();
    }
    return 0;
}