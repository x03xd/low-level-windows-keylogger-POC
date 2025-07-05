#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash-tables/PressedKeys.h"
#include "utils/common/utils.h"


PressedKeys* createTablePK() {
    PressedKeys *table = malloc(sizeof(PressedKeys));
    if (table == NULL) {
        return NULL;
    }
    table->entries = calloc(PRESSED_KEYS_SIZE, sizeof(PressedEntry*));
    if (table->entries == NULL) {
        free(table);
        return NULL;
    }
    return table;
}

void freeTablePK(PressedKeys *table) {
    for (int i = 0; i < PRESSED_KEYS_SIZE; i++) {
        PressedEntry *entry = table->entries[i];
        table->entries[i] = NULL;

        while (entry != NULL) {
            PressedEntry *temp = entry;
            entry = entry->next;
            free(temp->key);
            free(temp);
        }
    }
    free(table->entries);
    free(table);
}

void insertPK(PressedKeys *table, const char *key, const int value) {
    unsigned int slot = hash(key, PRESSED_KEYS_SIZE);
    PressedEntry *entry = table->entries[slot];

    if (entry == NULL) {
        entry = malloc(sizeof(PressedEntry));
        entry->key = strdup(key);
        entry->value = value;
        entry->next = NULL;
        table->entries[slot] = entry;
    } else {
        PressedEntry *prev;
        while (entry != NULL) {
            if (strcmp(entry->key, key) == 0) {
                entry->value = value;
                return;
            }
            prev = entry;
            entry = entry->next;
        }
        entry = malloc(sizeof(PressedEntry));
        entry->key = strdup(key);
        entry->value = value;
        entry->next = NULL;
        prev->next = entry;
    }
}

int searchPK(PressedKeys *table, const char *key) {
    unsigned int slot = hash(key, PRESSED_KEYS_SIZE);
    PressedEntry *entry = table->entries[slot];
    
    while (entry != NULL) {
        if (strcmp(entry->key, key) == 0) {
            return entry->value;
        }
        entry = entry->next;
    }
    return -1;
}

void deletePK(PressedKeys *table, const char *key) {
    unsigned int slot = hash(key, PRESSED_KEYS_SIZE);
    PressedEntry *entry = table->entries[slot];
    PressedEntry *prev = NULL;

    while (entry != NULL && strcmp(entry->key, key) != 0) {
        prev = entry;
        entry = entry->next;
    }

    if (entry == NULL) {
        return;
    }

    if (prev == NULL) {
        table->entries[slot] = entry->next;
    } else {
        prev->next = entry->next;
    }

    free(entry->key);
    free(entry);
}
