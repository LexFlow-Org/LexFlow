/* Positive control for the LexFlow-only packet capture. Synthetic loopback UDP. */
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int receiver = socket(AF_INET, SOCK_DGRAM, 0);
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in destination = {0};
    destination.sin_family = AF_INET;
    destination.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    destination.sin_port = htons(48761);
    if (receiver < 0 || sender < 0 || bind(receiver, (struct sockaddr *)&destination, sizeof(destination))) {
        perror("probe setup");
        return 1;
    }
    const char payload[] = "LEXFLOW-SYNTHETIC-NETWORK-POSITIVE-CONTROL";
    for (int i = 0; i < 3; i++) {
        if (sendto(sender, payload, sizeof(payload), 0, (struct sockaddr *)&destination, sizeof(destination)) < 0) {
            perror("probe send");
            return 1;
        }
        char buffer[128];
        if (recv(receiver, buffer, sizeof(buffer), 0) != sizeof(payload)) return 1;
        sleep(1);
    }
    close(sender);
    close(receiver);
    puts("Three synthetic loopback packets sent and received.");
    return 0;
}
