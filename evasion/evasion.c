#include <stdio.h>
#include "evasion.h"


void isDebuggerModeOn() {
    PPEB pPEB = _getPeb();

    if (_checkDebugger() != 0) {
        exit(1);
    }
}