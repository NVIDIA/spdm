#pragma once

#include <stddef.h>
#include <stdbool.h>
#include "apptypes.h"

// Corrupted packet response code
int corrupt_pkt_mod_cmd(char* buf, size_t len) EXPORT_HIDDEN;

// Corrupted packet response code
int corrupt_pkt_mod_len(char* buf, size_t buf_size, size_t recv_size) EXPORT_HIDDEN;

// Corrupt message version
int corrupt_pkt_mod_version(char* buf, size_t len) EXPORT_HIDDEN;

// Corrupt reserved fields settings
int corrupt_pkt_mod_param_and_reserved(char* buf, size_t len, bool* modified) EXPORT_HIDDEN;

// Corrupt Certificate sizes
int corrupt_pkt_mod_cert_sizes(char* buf, size_t len) EXPORT_HIDDEN;

// Corrupt Certificate data
int corrupt_pkt_mod_cert_data(char* buf, size_t len) EXPORT_HIDDEN;

// Corrupt Unsupported algo fields
int corrupt_pkt_mod_unsup_algo(char* buf, size_t len) EXPORT_HIDDEN;

// Corrupt Unsupported capabilities fields
int corrupt_pkt_mod_unsup_capab(char* buf, size_t len) EXPORT_HIDDEN;

// pkt corrupt version reserved
int corrupt_pkt_mod_version_param_reserved(char *buf, size_t len) EXPORT_HIDDEN;

// pkt corrupt capabilities reserved
int corrupt_pkt_mod_capabilities_param_reserved(char *buf, size_t len) EXPORT_HIDDEN;

// pkt corrupt algo reserved
int corrupt_pkt_mod_algo_param_reserved(char *buf, size_t len) EXPORT_HIDDEN;
