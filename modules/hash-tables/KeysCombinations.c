#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash-tables/KeysCombinations.h"
#include "utils/common/utils.h"


KeysCombinations* createCombinationTable() {
    KeysCombinations *table = malloc(sizeof(KeysCombinations));
    if (table == NULL) {
        return NULL;    
    }
    table->entries = calloc(COMBINATIONS_KEYS_SIZE, sizeof(CombinationEntry*));
    if (table->entries == NULL) {
        free(table);
        return NULL;
    }
    return table;
}

void insertCombination(KeysCombinations *table, const char *key, const char value) {
    unsigned int slot = hash(key, COMBINATIONS_KEYS_SIZE);
    CombinationEntry *entry = table->entries[slot];

    if (entry == NULL) {
        entry = malloc(sizeof(CombinationEntry));
        entry->key = strdup(key);
        entry->value = value;
        entry->next = NULL;
        table->entries[slot] = entry;
    } else {
        CombinationEntry *prev;
        while (entry != NULL) {
            if (strcmp(entry->key, key) == 0) {
                entry->value = value;
                return;
            }
            prev = entry;
            entry = entry->next;
        }
        entry = malloc(sizeof(CombinationEntry));
        entry->key = strdup(key);
        entry->value = value;
        entry->next = NULL;
        prev->next = entry;
    }
}

char searchCombination(KeysCombinations *table, const char *key) {
    unsigned int slot = hash(key, COMBINATIONS_KEYS_SIZE);
    CombinationEntry *entry = table->entries[slot];
    while (entry != NULL) {
        if (strcmp(entry->key, key) == 0) {
            return entry->value;
        }
        entry = entry->next;
    }
    return '\0';
}

void freeCombinations(KeysCombinations *table) {
    for (int i = 0; i < COMBINATIONS_KEYS_SIZE; i++) {
        CombinationEntry *entry = table->entries[i];
        table->entries[i] = NULL;
        
        while (entry != NULL) {
            CombinationEntry *temp = entry;
            entry = entry->next;
            free(temp->key);
            free(temp);
        }
    }
    free(table->entries);
    free(table);
}
