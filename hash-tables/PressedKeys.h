#ifndef PRESSED_KEYS_H
#define PRESSED_KEYS_H

#include <stdlib.h>
#include <string.h>

#define PRESSED_KEYS_SIZE 142

typedef struct PressedEntry {
    char *key;
    int value;
    struct PressedEntry *next;
} PressedEntry;

typedef struct PressedKeys {
    PressedEntry **entries;
} PressedKeys;

PressedKeys* createTablePK();
void freeTablePK(PressedKeys *table);
void insertPK(PressedKeys *table, const char *key, const int value);
int searchPK(PressedKeys *table, const char *key);
void deletePK(PressedKeys *table, const char *key);

#endif 
