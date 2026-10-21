// Fixed: CWE-787 Out-of-bounds Write and CWE-134 Externally-Controlled
// Format String. Copies are now bounded with snprintf, and user-controlled
// strings are always passed as printf arguments rather than as the format
// string itself.
#include <cstdio>
#include <cstring>
#include <cstdlib>

void log_user_action(const char *username, const char *action) {
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%s performed: %s", username, action);

    printf("%s\n", action);
}

void parse_request(const char *raw_request) {
    char parsed[128];
    snprintf(parsed, sizeof(parsed), "REQUEST: %s", raw_request);
    log_user_action("anonymous", parsed);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <request-data>\n", argv[0]);
        return 1;
    }
    parse_request(argv[1]);
    return 0;
}
