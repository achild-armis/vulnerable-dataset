// CWE-120 / CWE-787: Buffer Copy without Checking Size of Input (Buffer Overflow)
// CWE-134: Use of Externally-Controlled Format String
// Vulnerable: fixed-size stack buffer copied into with unchecked strcpy,
// and user input passed directly as a printf format string.
#include <cstdio>
#include <cstring>
#include <cstdlib>

void log_user_action(const char *username, const char *action) {
    char buffer[64];
    // VULNERABLE: strcpy does not check destination size; a long username
    // overflows the stack buffer and can corrupt adjacent memory/return address.
    strcpy(buffer, username);
    strcat(buffer, " performed: ");
    strcat(buffer, action);

    // VULNERABLE: 'action' originates from user input and is used directly as
    // the format string. An attacker can supply "%s%s%s%n" to read/write memory.
    printf(action);
    printf("\n");
}

void parse_request(const char *raw_request) {
    char parsed[128];
    // VULNERABLE: no bounds check on the copy length vs. destination size
    sprintf(parsed, "REQUEST: %s", raw_request);
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
