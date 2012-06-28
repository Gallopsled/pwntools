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

WRAP(printf);
