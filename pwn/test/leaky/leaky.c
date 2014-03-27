 /**
  * gcc -pie -fPIC -Xlinker --hash-style=sysv -o leaker_sysv_64 leaky.c
  * gcc -pie -fPIC -Xlinker --hash-style=gnu -o leaker_gnu_64 leaky.c
  * gcc -pie -fPIC -m32 -Xlinker --hash-style=sysv -o leaker_sysv_32 leaky.c
  * gcc -pie -fPIC -m32 -Xlinker --hash-style=gnu -o leaker_gnu_32 leaky.c
  *
  * Read this: https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections
  */
#include <netinet/in.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>

int find_me();

int main(int argc, char const *argv[]);

static int create_server(unsigned short port) {
    int server;
    int flags;
    struct sockaddr_in addr;

    server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        return -1;
    }

    flags = 1;
    if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags)) < 0) {
        close(server);
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(server, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(server);
        return -1;
    }

    if (listen(server, 10) < 0) {
        close(server);
        return -1;
    }

    return server;
}

void child_died(int sig) {
    wait(&sig);
}

void handle_client(int client) {
    unsigned long main_addr = (unsigned long)main;
    char * ptr = (char*)&main_addr;
    int bytes_read;
    do {
        write(client, ptr, sizeof(char*));
    } while ((bytes_read = read(client, &ptr, sizeof(char *))) == sizeof(char*));
}

int main(int argc, char const *argv[]) {
    int server, client;
    pid_t pid;

    if ((server = create_server(argc > 1 ? atoi(argv[1]) : 9999)) < 0) {
        fprintf(stderr, "Could not create server socket.\n");
        exit(-1);

    } else {
        signal(SIGCHLD, child_died);
        while (1) {
            if ((client = accept(server, NULL, NULL)) < 0) {
                fprintf(stderr, "Could not accept client.\n");
                exit(-1);
            } else {
                pid = fork();
                if (pid) {
                    close(client);
                } else {
                    close(server);
                    handle_client(client);
                    close(client);
                    exit(find_me());
                }
            }
        }
    }
    return 0;
}
