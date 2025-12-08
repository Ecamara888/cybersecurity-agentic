#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define PASSWORD_LENGTH 8

/*
 * Validate whether the provided password matches the pattern L$$555ee:
 *   - Position 0: uppercase letter (A–Z)
 *   - Positions 1–2: literal '$' characters
 *   - Positions 3–5: digits (0–9)
 *   - Positions 6–7: lowercase letters (a–z)
 */
static bool is_compliant(const char *password) {
    if (password == NULL) {
        return false;
    }

    if (strlen(password) != PASSWORD_LENGTH) {
        return false;
    }

    if (!isupper((unsigned char)password[0])) {
        return false;
    }

    if (password[1] != '$' || password[2] != '$') {
        return false;
    }

    for (int i = 3; i <= 5; ++i) {
        if (!isdigit((unsigned char)password[i])) {
            return false;
        }
    }

    if (!islower((unsigned char)password[6]) || !islower((unsigned char)password[7])) {
        return false;
    }

    return true;
}

int main(void) {
    char password[128];

    printf("Enter password to validate (format L$$555ee): ");
    if (scanf("%127s", password) != 1) {
        fprintf(stderr, "Failed to read password input.\n");
        return 1;
    }

    if (is_compliant(password)) {
        printf("Password is compliant.\n");
        return 0;
    }

    printf("Password is NOT compliant.\n");
    return 0;
}
