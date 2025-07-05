#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <tlhelp32.h>
#include "include/shared.h"

/**
 * @brief Checks if the given single-character string matches any of a predefined set of special characters.
 *
 * @param key Pointer to a null-terminated string containing a single character to check.
 *            Must not be NULL.
 * @return int Returns 1 if `key` matches one of the special characters, otherwise returns 0.
 */
int containsChar(const char *key);

/**
 * @brief Generates a UUID-like string and writes it to the provided buffer.
 *
 * @param uuid Pointer to a buffer of at least 37 `wchar_t` elements where the generated UUID will be written.
 *             The string will be null-terminated.
 *             Must not be NULL.
 */
void generateUserId(LPBYTE uuid);

/**
 * @brief Concatenates two null-terminated strings into a newly allocated string.
 *
 * @param pre Pointer to a null-terminated prefix string.
 * @param post Pointer to a null-terminated postfix string.
 * @return char* Pointer to a newly allocated null-terminated string containing the concatenation.
 *               The caller is responsible for freeing the returned buffer.
 */
char* concatenateChars(char *pre, char *post);

/**
 * @brief Computes a hash value for a given string.
 *
 * @param key Pointer to a null-terminated string to be hashed.
 * @param size Size of the hash table (number of buckets).
 * @return unsigned int Computed hash value in the range [0, size-1].
 */
unsigned int hash(const char *key, int size);

/**
 * @brief Initializes a `UNICODE_STRING` structure with the provided wide-character buffer.
 *
 * @param unicodeStr Pointer to the `UNICODE_STRING` structure to initialize.
 *                   Must not be NULL.
 * @param sectionNameBuffer Pointer to a null-terminated wide-character string to use as the buffer.
 *                           Must not be NULL.
 */
void createUnicodeString(PUNICODE_STRING unicodeStr, const wchar_t* sectionNameBuffer);

#endif
