#include <time.h>
#include <string.h>
#include <stdint.h>
#include "utils/common/utils.h"


int containsChar(const char *key) {
    static const char *s[] = {"-", "=", "[", "]", "\\", ";", ",", ".", "/"};
    int num_elements = sizeof(s) / sizeof(s[0]);
    int key_length = strlen(key);
    for (int i = 0; i < num_elements; i++) {
        if (key_length == 1 && key[0] == s[i][0]) {
            return 1;
        }
    }
    return 0;
}

void generateUserId(LPBYTE uuid) {
    srand((unsigned int)time(NULL));
    const wchar_t *hex_chars = L"0123456789abcdef";
    int i;
    
    for (i = 0; i < 36; i++) {
        switch (i) {
            case 8:
            case 13:
            case 18:
            case 23:
                uuid[i] = L'-';
                break;
            case 14:
                uuid[i] = L'4';
                break;
            case 19:
                uuid[i] = hex_chars[(rand() & 0x3) | 0x8];
                break;
            default:
                uuid[i] = hex_chars[rand() % 16];
        }
    }
    uuid[36] = L'\0';
}

char* concatenateChars(char *pre, char *post) {
    char* fullPath = (char*)malloc(sizeof(char) * (1 + strlen(pre) + strlen(post)));
    strcpy(fullPath, pre);
    strcat(fullPath, post);
    return fullPath;
}

unsigned int hash(const char *key, int size) {
    unsigned long int value = 0;
    unsigned int i = 0;
    unsigned int key_len = strlen(key);
    for (; i < key_len; ++i) {
        value = value * 37 + key[i];
    }
    return value % size;
}

void createUnicodeString(PUNICODE_STRING unicodeStr, const wchar_t* sectionNameBuffer) {
    size_t length = wcslen(sectionNameBuffer) * sizeof(wchar_t);
    unicodeStr->Buffer = (PWSTR)sectionNameBuffer;
    unicodeStr->Length = (USHORT)length;
    unicodeStr->MaximumLength = (USHORT)(length + sizeof(wchar_t));
}
