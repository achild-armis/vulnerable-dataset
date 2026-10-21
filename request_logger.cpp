// CWE-120 / CWE-787: Buffer Copy without Checking Size of Input (Buffer Overflow)
// CWE-134: Use of Externally-Controlled Format String
// Vulnerable: fixed-size stack buffer copied into with unchecked strcpy,
// and user input passed directly as a printf format string.
#include <cstdio>
#include <cstring>
#include <cstdlib>

void log_user_action(const char *username, const char *action) {
    char buffer[64];
    // FIXED: bounded snprintf replaces the unchecked strcpy/strcat sequence,
    // so the write can never exceed the destination buffer and is always
    // null-terminated.
    snprintf(buffer, sizeof(buffer), "%s performed: %s", username, action);

    // FIXED: 'action' is passed as a data argument rather than the format
    // string, so format specifiers embedded in user input are not interpreted.
    printf("%s", action);
    printf("\n");
}

void parse_request(const char *raw_request) {
    char parsed[128];
    // FIXED: snprintf bounds the write to the destination buffer size.
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
