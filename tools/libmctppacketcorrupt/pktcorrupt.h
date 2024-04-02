#pragma once
#include <stddef.h>
#include <stdbool.h>
#include "apptypes.h"
#include "error.h"

//! Initialize corrupt library
int corrupt_init(void) EXPORT_HIDDEN;
//! Deinitialize corrupt library
int corrupt_deinit(void) EXPORT_HIDDEN;

/**
 * @param[in] buf Buffer data len
 * @param[in] buf_size Buffer maximum size
 * @param[in] recv_size Real recv size
*/
int corrupt_recv_packet(char *buf, size_t buf_size, size_t recv_size) EXPORT_HIDDEN;

