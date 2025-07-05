#ifndef KEYS_H
#define KEYS_H

#include <stdlib.h>
#include <string.h>

#define KEYS_SIZE 142

typedef struct Entry {
    char *key;
    int value;
    struct Entry *next;
} Entry;

typedef struct Keys {
    Entry **entries;
} Keys;

Keys* createTable();
void freeTable(Keys *table);
void insert(Keys *table, const char *key, const int value);
int search(Keys *table, const char *key);

#endif
