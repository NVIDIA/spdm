#pragma once
#include "apptypes.h"

//! Initialize random generator
int random_init(void) EXPORT_HIDDEN;
//! Get random value
int random_value(u32* val) EXPORT_HIDDEN;
//! Deinitialize random gen
void random_deinit(void) EXPORT_HIDDEN;

