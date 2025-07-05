#ifndef MAIN_H
#define MAIN_H

extern BYTE _checkDebugger(void);

extern char* userId;
extern char* result;

/**
 * @brief Verifies if the program is running in debug mode.
 *
 * @return TRUE if the process is being debugged, otherwise FALSE.
 */
BOOL isDebuggerModeOn();

#endif
