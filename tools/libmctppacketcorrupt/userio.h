#pragma once

#include "apptypes.h"

int userio_read_lib_config(corrupt_config* conf) _EXPORT_HIDDEN;

const char* userio_error_to_str(enum error err) _EXPORT_HIDDEN;

void userio_print_help(void) _EXPORT_HIDDEN;