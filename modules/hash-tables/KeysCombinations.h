#ifndef KEYS_COMBINATIONS_H
#define KEYS_COMBINATIONS_H

#include <stdlib.h>
#include <string.h>

#define COMBINATIONS_KEYS_SIZE 21

typedef struct CombinationEntry {
    char *key;
    char value;
    struct CombinationEntry *next;
} CombinationEntry;

typedef struct KeysCombinations {
    CombinationEntry **entries;
} KeysCombinations;

KeysCombinations* createCombinationTable();
void insertCombination(KeysCombinations *table, const char *key, const char value);
char searchCombination(KeysCombinations *table, const char *key);

#endif
