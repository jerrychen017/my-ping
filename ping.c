#include "ping.h"

/**
 * A ping program that is a clone to the ping program on MacOs 
 */
int main(int argc, char *argv[]) {
    // display help menu
    if (argv != 2) {
        
        return 0; 
    }
    // host name or ip address
    const char * host = argv[1];  

    int ret; 
    int host_num;
    struct hostent h_ent, *p_h_ent;

    struct sockaddr_in addr;

    p_h_ent = gethostbyname2(host, AF_INET);
    if (p_h_ent == NULL) {
        p_h_ent = gethostbyaddr(host , 4, AF_INET);
    }
    // second argument is neither a hostname or an ip address 
    if (p_h_ent == NULL) {
        printf("ping: cannot resolve %s: Unknown host");
        return 1;
    }

    
    return 0; 
}
