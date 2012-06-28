#include "ld-override.h"
#include <stdlib.h>


void puts(char *);
char *parse_format(char *);

void printf_wrapper(char *s) {
    char *i = s;
    while (*i != '\0') {
        if (*i != '%') {
            i++;
            continue;
        }
        else {
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
        puts("Parsing flags\n");
        i++;
        continue;
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
        puts("Parsing field width\n");
        i++;
        continue;
    }

    // Precision modifier
    while(*i == '.' ||
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
        puts("Parsing precision modifier\n");
        i++;
        continue;
    }

    // Length modifier
    while(*i == 'h' ||
          *i == 'l' ||
          *i == 'L' ||
          *i == 'q' ||
          *i == 'j' ||
          *i == 'z' ||
          *i == 't') {
        puts("Parsing length modifier\n");
        i++;
        continue;
    }

    if(*i == 'n') {
        puts("NU DØR BABY!");
    }
    return i;
}

WRAP(printf);
