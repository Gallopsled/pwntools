#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/param.h>

#ifdef __BYTE_ORDER
# if __BYTE_ORDER == __LITTLE_ENDIAN
inline uint32_t make_big(uint32_t n) {
    return ((n & 0xff000000) >> 24) |
           ((n & 0x00ff0000) >> 8) |
           ((n & 0x0000ff00) << 8) |
           ((n & 0x000000ff) << 24);
}
# else
#  if __BYTE_ORDER == __BIG_ENDIAN
inline uint32_t make_big(uint32_t n) {
    return n;
}
#  else
#   error "Unknown byte order"
#  endif
# endif
#else
# error "Unknown byte order"
#endif

int main(int argc, char **argv) {

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(1337);

    uint32_t ip;

    for(ip = 0; ip != 0xffffffff; ip++) {
        if((ip & 0x00ffffff) == 0) {
            if(((ip >> 24) & 0xff) == 0 || ((ip >> 24) & 0xff) == 127) {
                ip += 1 << 24;
            } else if(((ip >> 24) & 0xff) == 224) {
                ip = 240 << 24;
            }
            printf("%d.0.0.0 reached\n", ((ip >> 24) & 0xff));
        }

        serv_addr.sin_addr.s_addr = make_big(ip);

        if(bind(sock, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1) {
            if(errno != EADDRNOTAVAIL) {
                printf("%d.%d.%d.%d:\t%d\n", ((ip >> 24) & 0xff), ((ip >> 16) & 0xff), ((ip >> 8) & 0xff), (ip & 0xff), errno);
            }
        } else {
            printf("%d.%d.%d.%d ok\n", ((ip >> 24) & 0xff), ((ip >> 16) & 0xff), ((ip >> 8) & 0xff), (ip & 0xff));
            close(sock);
            sock = socket(AF_INET, SOCK_STREAM, 0);
        }
    }

    return 0;
}

