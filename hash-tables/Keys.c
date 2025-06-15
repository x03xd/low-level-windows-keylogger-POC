#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Keys.h"
#include "utils.h"


Keys* createTable() {
    Keys *table = malloc(sizeof(Keys));
    if (table == NULL) {
        return NULL;
    }
    table->entries = calloc(KEYS_SIZE, sizeof(Entry*));
    if (table->entries == NULL) {
        free(table);
        return NULL;
    }
    return table;
}

void freeTable(Keys *table) {
    for (int i = 0; i < KEYS_SIZE; i++) {
        Entry *entry = table->entries[i];
        while (entry != NULL) {
            Entry *temp = entry;
            entry = entry->next;
            free(temp->key);
            free(temp);
        }
    }
    free(table->entries);
    free(table);
}

void insert(Keys *table, const char *key, const int value) {
    unsigned int slot = hash(key, KEYS_SIZE);
    Entry *entry = table->entries[slot];

    if (entry == NULL) {
        entry = malloc(sizeof(Entry));
        entry->key = strdup(key);
        entry->value = value;
        entry->next = NULL;
        table->entries[slot] = entry;
    } else {
        Entry *prev;
        while (entry != NULL) {
            if (strcmp(entry->key, key) == 0) {
                entry->value = value;
                return;
            }
            prev = entry;
            entry = entry->next;
        }
        entry = malloc(sizeof(Entry));
        entry->key = strdup(key);
        entry->value = value;
        entry->next = NULL;
        prev->next = entry;
    }
}

int search(Keys *table, const char *key) {
    unsigned int slot = hash(key, KEYS_SIZE);
    Entry *entry = table->entries[slot];

    while (entry != NULL) {
        if (strcmp(entry->key, key) == 0) {
            return entry->value;
        }
        entry = entry->next;
    }
    return -1;
}

void delete(Keys *table, const char *key) {
    unsigned int slot = hash(key, KEYS_SIZE);
    Entry *entry = table->entries[slot];
    Entry *prev = NULL;

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
