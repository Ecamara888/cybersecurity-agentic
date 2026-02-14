# Password Compliance Specification

This document describes the requirements for a password that follows the `L$$555ee` pattern, along with pseudocode and a flowchart to implement the validation.

## Format definition (`L$$555ee`)

- Position 0: uppercase letter (A–Z)
- Positions 1–2: the dollar-sign special character `$`
- Positions 3–5: digits (0–9)
- Positions 6–7: lowercase letters (a–z)
- Total length: exactly 8 characters

## Pseudocode

```
FUNCTION is_compliant(password: STRING) RETURNS BOOLEAN
    IF length(password) != 8 THEN
        RETURN FALSE
    END IF

    IF NOT is_uppercase(password[0]) THEN
        RETURN FALSE
    END IF

    IF password[1] != '$' OR password[2] != '$' THEN
        RETURN FALSE
    END IF

    FOR i FROM 3 TO 5 DO
        IF NOT is_digit(password[i]) THEN
            RETURN FALSE
        END IF
    END FOR

    IF NOT is_lowercase(password[6]) OR NOT is_lowercase(password[7]) THEN
        RETURN FALSE
    END IF

    RETURN TRUE
END FUNCTION
```

## Flowchart

```mermaid
flowchart TD
    A([Start]) --> B{Read password}
    B --> C{Length == 8?}
    C -- No --> Z([Reject])
    C -- Yes --> D{password[0] is uppercase?}
    D -- No --> Z
    D -- Yes --> E{password[1] == '$' and password[2] == '$'?}
    E -- No --> Z
    E -- Yes --> F{password[3..5] are digits?}
    F -- No --> Z
    F -- Yes --> G{password[6] and password[7] are lowercase?}
    G -- No --> Z
    G -- Yes --> H([Accept])
```

## Usage

Compile and run the accompanying C program located at `src/password_checker.c` to test passwords against this format.
