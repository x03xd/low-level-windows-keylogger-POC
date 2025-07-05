#ifndef INITIALIZER_H
#define INITIALIZER_H

#include <windows.h>
#include "hash-tables/Keys.h"
#include "hash-tables/KeysCombinations.h"
#include "hash-tables/PressedKeys.h"
#include "sets/Set.h"

typedef struct {
    KeysCombinations* combinations;
    PressedKeys* pressedKeys;
    Keys* keys;
    Set* set;
} AppContext;


BOOL initStrings(char** resultOut, char** userIdOut);

BOOL initAppContext(AppContext* ctx);

void destroyAppContext(AppContext* ctx);

void initKeysCombinations(KeysCombinations *table);

void initKeys(Keys *table);

#endif
