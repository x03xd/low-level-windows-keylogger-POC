// Set.h
#ifndef SET_H
#define SET_H

#define SET_SIZE 142

typedef struct SetEntry {
    char *key;
    struct SetEntry *next;
} SetEntry;

typedef struct Set {
    SetEntry **entries;
} Set;

Set* createSet();
void freeSetEntries(Set *set);
void add(Set *set, const char *key);
int contains(Set *set, const char *key);

/*
+-------------------------+
| Set                     |
+-------------------------+
| entries[0] -> Entry1 -> Entry2 -> ... -> NULL
| entries[1] -> Entry3 -> NULL
| entries[2] -> NULL
| entries[3] -> Entry4 -> Entry5 -> ... -> NULL
| ...       -> ...
+-------------------------+
*/

#endif
