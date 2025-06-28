#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "sets/Set.h"
#include "utils/utils.h"


Set* createSet() {
    Set *set = malloc(sizeof(Set));
    if (set == NULL) {
        return NULL;
    }
    set->entries = calloc(SET_SIZE, sizeof(SetEntry*));
    if (set->entries == NULL) {
        free(set);
        return NULL;
    }
    return set;
}

void add(Set *set, const char *key) {
    unsigned int index = hash(key, SET_SIZE);
    SetEntry *entry = set->entries[index];
    if (entry == NULL) {
        entry = malloc(sizeof(SetEntry));
        entry->key = strdup(key);
        entry->next = NULL;
        set->entries[index] = entry;
    } else {
        SetEntry *prev = NULL;
        while (entry != NULL) {
            if (strcmp(entry->key, key) == 0) {
                return;
            }
            prev = entry;
            entry = entry->next;
        }
        entry = malloc(sizeof(SetEntry));
        entry->key = strdup(key);
        entry->next = NULL;
        if (prev != NULL) {
            prev->next = entry;
        } else {
            set->entries[index] = entry;
        }
    }
}

int contains(Set *set, const char *key) {
    unsigned int index = hash(key, SET_SIZE);
    SetEntry *entry = set->entries[index];

    while (entry != NULL) {
        if (strcmp(entry->key, key) == 0) {
            return 1;
        }
        entry = entry->next;
    }
    return 0;
}

void freeSetEntries(Set *set) {
    for (int i = 0; i < SET_SIZE; i++) {
        SetEntry *entry = set->entries[i];
        set->entries[i] = NULL;

        while (entry != NULL) {
            SetEntry *temp = entry;
            entry = entry->next;
            free(temp->key);
            free(temp);
        }
    }
}
