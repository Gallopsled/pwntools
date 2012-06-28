#include "ld-override.h"
#include <stdlib.h>


void puts(char *);
char *parse_format(char *);
wchar_t *parse_format_wide(wchar_t *);


void check_format_string(char *s) {
    char *i = s;
    while (*i != '\0') {
        if (*i != '%') {
            i++;
            continue;
        }
        else {
            i++;
//            puts("printf: parsing format string");
            i = parse_format(i);
        }
    }
}

char *parse_format(char *i) {
    // Flags
    while(*i == '#' ||
          *i == '0' ||
          *i == '-' ||
          *i == ' ' ||
          *i == '+' ||
          *i == 'I' ||
          *i == '\'') {
//        puts("printf: parsing flags");
        i++;
    }

    // Field width
    while(*i == '0' ||
          *i == '1' ||
          *i == '2' ||
          *i == '3' ||
          *i == '4' ||
          *i == '5' ||
          *i == '6' ||
          *i == '7' ||
          *i == '8' ||
          *i == '9') {
//        puts("printf: parsing field width");
        i++;
    }

    // Precision modifier
    while(*i == '.' ||
          *i == '*' ||
          *i == '$' ||
          *i == '0' ||
          *i == '1' ||
          *i == '2' ||
          *i == '3' ||
          *i == '4' ||
          *i == '5' ||
          *i == '6' ||
          *i == '7' ||
          *i == '8' ||
          *i == '9') {
//        puts("printf: parsing precision modifier");
        i++;
    }

    // Length modifier
    while(*i == 'h' ||
          *i == 'l' ||
          *i == 'L' ||
          *i == 'q' ||
          *i == 'j' ||
          *i == 'z' ||
          *i == 't') {
//        puts("printf: parsing length modifier");
        i++;
    }

    if(*i == 'n') {
        puts("NU DØR BABY!");
        exit(1337);
    }
    i++;

    return i;
}

void check_format_string_wide(wchar_t *s) {
    wchar_t *i = s;
    while (*i != '\0') {
        if (*i != '%') {
            i++;
            continue;
        }
        else {
            i++;
//            puts("printf: parsing format string");
            i = parse_format_wide(i);
        }
    }
}

wchar_t *parse_format_wide(wchar_t *i) {
    // Flags
    while(*i == '#' ||
          *i == '0' ||
          *i == '-' ||
          *i == ' ' ||
          *i == '+' ||
          *i == 'I' ||
          *i == '\'') {
//        puts("printf: parsing flags");
        i++;
    }

    // Field width
    while(*i == '0' ||
          *i == '1' ||
          *i == '2' ||
          *i == '3' ||
          *i == '4' ||
          *i == '5' ||
          *i == '6' ||
          *i == '7' ||
          *i == '8' ||
          *i == '9') {
//        puts("printf: parsing field width");
        i++;
    }

    // Precision modifier
    while(*i == '.' ||
          *i == '*' ||
          *i == '$' ||
          *i == '0' ||
          *i == '1' ||
          *i == '2' ||
          *i == '3' ||
          *i == '4' ||
          *i == '5' ||
          *i == '6' ||
          *i == '7' ||
          *i == '8' ||
          *i == '9') {
//        puts("printf: parsing precision modifier");
        i++;
    }

    // Length modifier
    while(*i == 'h' ||
          *i == 'l' ||
          *i == 'L' ||
          *i == 'q' ||
          *i == 'j' ||
          *i == 'z' ||
          *i == 't') {
//        puts("printf: parsing length modifier");
        i++;
    }

    if(*i == 'n') {
        puts("NU DØR BABY!");
        exit(1337);
    }
    i++;

    return i;
}

void printf_wrapper(char *s) {
    check_format_string(s);
}

void dprintf_wrapper(int ignore, char *s) {
    check_format_string(s);
}

void asprintf_wrapper(int ignore, char *s) {
    check_format_string(s);
}

void vasprintf_wrapper(int ignore, char *s) {
    check_format_string(s);
}

void vdprintf_wrapper(int ignore, char *s) {
    check_format_string(s);
}

void fprintf_wrapper(int ignore, char *s) {
    check_format_string(s);
}

void sprintf_wrapper(int ignore, char *s) {
    check_format_string(s);
}

void snprintf_wrapper(int ignore, int ignore2, char *s) {
    check_format_string(s);
}

void vprintf_wrapper(char *s) {
    check_format_string(s);
}

void vfprintf_wrapper(int ignore, char *s) {
    check_format_string(s);
}

void vsprintf_wrapper(int ignore, char *s) {
    check_format_string(s);
}

void vsnprintf_wrapper(int ignore, int ignore2, char *s) {
    check_format_string(s);
}


// Wide chars
void wprintf_wrapper(wchar_t *s) {
    check_format_string_wide(s);
}
void fwprintf_wrapper(int ignore, wchar_t *s) {
    check_format_string_wide(s);
}
void swprintf_wrapper(int ignore, int ignore2, wchar_t *s) {
    check_format_string_wide(s);
}
void vwprintf_wrapper(wchar_t *s) {
    check_format_string_wide(s);
}

void vfwprintf_wrapper(int ignore, wchar_t *s) {
    check_format_string_wide(s);
}

void vswprintf_wrapper(int ignore, int ignore2, wchar_t *s) {
    check_format_string_wide(s);
}
WRAP(printf);
WRAP(asprintf);
WRAP(vasprintf);
WRAP(dprintf);
WRAP(vdprintf);
WRAP(fprintf);
WRAP(sprintf);
WRAP(snprintf);
WRAP(vprintf);
WRAP(vfprintf);
WRAP(vsprintf);
WRAP(vsnprintf);

// Wide
WRAP(wprintf);
WRAP(fwprintf);
WRAP(swprintf);
WRAP(vwprintf);
WRAP(vfwprintf);
WRAP(vswprintf);
