#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define PROC_FILE "/proc/xor_key"
#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define BLUE "\033[1;34m"
#define RESET "\033[0m"

void read_xor_key() {
    int fd = open(PROC_FILE, O_RDONLY);
    if (fd < 0) {
        perror(RED "Failed to open proc file" RESET);
        return;
    }
    char buf[4];
    if (read(fd, buf, sizeof(buf) - 1) < 0) {
        perror(RED "Failed to read XOR key" RESET);
        close(fd);
        return;
    }
    close(fd);
    buf[3] = '\0';
    printf(GREEN "[INFO] " RESET "Current XOR Key: " YELLOW "0x%s\n" RESET, buf);
}

void write_xor_key(const char *key) {
    int fd = open(PROC_FILE, O_WRONLY);
    if (fd < 0) {
        perror(RED "Failed to open proc file" RESET);
        return;
    }
    if (write(fd, key, strlen(key)) < 0) {
        perror(RED "Failed to write XOR key" RESET);
    }
    close(fd);
}

void show_banner() {
    printf(BLUE "\n==============================\n" RESET);
    printf(BLUE " XOR Packet Obfuscation Control \n" RESET);
    printf(BLUE "==============================\n\n" RESET);
}

int main(int argc, char *argv[]) {
    show_banner();
    if (argc == 1) {
        read_xor_key();
    } else if (argc == 3 && strcmp(argv[1], "--set-key") == 0) {
        write_xor_key(argv[2]);
        printf(GREEN "[SUCCESS] " RESET "XOR Key set to: " YELLOW "0x%s\n" RESET, argv[2]);
    } else {
        fprintf(stderr, RED "[ERROR] " RESET "Invalid command!\n" BLUE "Usage: %s [--set-key <hex_key>]\n" RESET, argv[0]);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

