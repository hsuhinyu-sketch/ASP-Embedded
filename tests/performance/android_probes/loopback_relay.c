/* TCP loopback control for matching the two ADB legs of an HTTP workload. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static struct sockaddr_in destination;

static struct sockaddr_in address(const char *port) {
    char *end;
    long value = strtol(port, &end, 10);
    if (*port == '\0' || *end != '\0' || value < 1 || value > 65535) {
        fputs("invalid port\n", stderr);
        exit(2);
    }
    return (struct sockaddr_in){.sin_family = AF_INET, .sin_port = htons(value),
                               .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
}

static int forward(int from, int to) {
    char buffer[16384];
    ssize_t size = read(from, buffer, sizeof(buffer));
    for (ssize_t sent = 0; sent < size;) {
        ssize_t count = write(to, buffer + sent, (size_t)(size - sent));
        if (count <= 0) {
            return -1;
        }
        sent += count;
    }
    return size > 0 ? 0 : -1;
}

static void *relay(void *arg) {
    int client = *(int *)arg;
    free(arg);
    int upstream = socket(AF_INET, SOCK_STREAM, 0);
    if (upstream >= 0 && connect(upstream, (struct sockaddr *)&destination, sizeof(destination)) == 0) {
        int enabled = 1;
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
        setsockopt(upstream, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
        struct pollfd fds[2] = {{client, POLLIN, 0}, {upstream, POLLIN, 0}};
        while (poll(fds, 2, 15000) > 0) {
            if ((fds[0].revents && forward(client, upstream) != 0) ||
                (fds[1].revents && forward(upstream, client) != 0)) {
                break;
            }
        }
    }
    if (upstream >= 0) {
        close(upstream);
    }
    close(client);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    struct sockaddr_in local = address(argv[1]);
    destination = address(argv[2]);
    if (local.sin_port == destination.sin_port) {
        return 2;
    }
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int enabled = 1;
    if (listener < 0 || setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) ||
        bind(listener, (struct sockaddr *)&local, sizeof(local)) || listen(listener, 32)) {
        perror("open loopback relay");
        return 1;
    }
    puts("ready");
    fflush(stdout);
    for (;;) {
        int client = accept(listener, NULL, NULL);
        if (client < 0 && errno == EINTR) {
            continue;
        }
        int *connection = malloc(sizeof(*connection));
        if (client < 0 || connection == NULL) {
            perror("accept loopback connection");
            return 1;
        }
        *connection = client;
        pthread_t thread;
        if (pthread_create(&thread, NULL, relay, connection) != 0) {
            close(client);
            free(connection);
            return 1;
        }
        pthread_detach(thread);
    }
}
