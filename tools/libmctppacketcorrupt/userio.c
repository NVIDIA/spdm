/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "userio.h"

#include "apptypes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

// Configuration environment variables
#define CFGENV_MODE "MCTP_CORRUPT_MODE"
#define CFGENV_LVL "MCTP_CORRUPT_LEVEL"

// Convert mode to string
static corrupt_mode modestr_to_enum(const char* str)
{
    if (!strcasecmp(str, "bypass"))
    {
        return corrupt_mode_bypass;
    }
    else if (!strcasecmp(str, "command"))
    {
        return corrupt_mode_cmds;
    }
    else if (!strcasecmp(str, "reserved"))
    {
        return corrupt_mode_reserved;
    }
    else if (!strcasecmp(str, "msglen"))
    {
        return corrupt_mode_msg_len;
    }
    else if (!strcasecmp(str, "zerolen"))
    {
        return corrupt_mode_msg_zero;
    }
    else if (!strcasecmp(str, "version"))
    {
        return corrupt_mode_version;
    }
    else if (!strcasecmp(str, "certlen"))
    {
        return corrupt_mode_cert_len;
    }
    else if (!strcasecmp(str, "certdata"))
    {
        return corrupt_mode_cert_data;
    }
    else if (!strcasecmp(str, "unsupalgo"))
    {
        return corrupt_mode_unsup_algo;
    }
    else if (!strcasecmp(str, "unsupcapab"))
    {
        return corrupt_mode_unsup_capab;
    }
    else if (!strcasecmp(str, "versionfields"))
    {
        return corrupt_mode_version_fields;
    }
    else if (!strcasecmp(str, "capabfields"))
    {
        return corrupt_mode_capab_fields;
    }
    else if (!strcasecmp(str, "digestfields"))
    {
        return corrupt_mode_digest_fields;
    }
    else if (!strcasecmp(str, "certfields"))
    {
        return corrupt_mode_cert_fields;
    }
    else if (!strcasecmp(str, "algofields"))
    {
        return corrupt_mode_algo_fields;
    }
    else if (!strcasecmp(str, "measdata"))
    {
        return corrupt_mode_meas_data;
    }
    return corrupt_mode_invalid;
}

// Read library configuration from the environment variables
int userio_read_lib_config(corrupt_config* conf)
{
    // Parse mode
    const char* const mode_str = getenv(CFGENV_MODE);
    if (!mode_str)
    {
        return error_no_env_var;
    }
    conf->mode = modestr_to_enum(mode_str);
    if (conf->mode == corrupt_mode_invalid)
    {
        return error_no_env_var;
    }
    // Parse corrupt level
    const char* lvl_str = getenv(CFGENV_LVL);
    if (!lvl_str)
    {
        return error_no_env_var;
    }
    char* endptr;
    if (strchr(lvl_str, '%'))
    {
        conf->pkt_manual_list = true;
    }
    if (strchr(lvl_str, '/'))
    {
        if (conf->pkt_manual_list)
            return error_env_parse;
        conf->pkt_manual_list = false;
    }
    if (!conf->pkt_manual_list)
    {
        conf->pkt_corrupted = strtoul(lvl_str, &endptr, 10);
        if (*endptr != '/')
        {
            return error_env_parse;
        }
        else
        {
            lvl_str = endptr + 1;
            endptr = NULL;
        }
        conf->pkt_cycles = strtoul(lvl_str, &endptr, 10);
        if (*endptr != '\0')
        {
            return error_env_parse;
        }
        if (conf->pkt_corrupted > conf->pkt_cycles)
        {
            return error_env_range;
        }
        if (conf->pkt_cycles > CONFIG_MAX_PKT_HISTORY)
        {
            return error_env_range;
        }
    }
    else
    {
        int i = 0;
        const char* start = lvl_str;
        do
        {
            u32 val = strtoul(start, &endptr, 10);
            if (endptr && (*endptr == ',' || *endptr == '%'))
            {
                conf->pkt_mod_num[i++] = val;
                start = endptr + 1;
            }
            else if (endptr && *endptr == '\0')
            {
                conf->pkt_cycles = val;
                start = endptr + 1;
            }
        } while (endptr && (*endptr == ',' || *endptr == '%'));
        conf->pkt_corrupted = i;
        if (conf->pkt_cycles > CONFIG_MAX_PKT_HISTORY)
        {
            return error_env_range;
        }
        if (conf->pkt_cycles < CONFIG_MIN_NUM_CYCLES)
        {
            return error_env_range;
        }
        if (conf->pkt_corrupted > conf->pkt_cycles)
        {
            return error_env_range;
        }
    }
    fprintf(
        stderr,
        "## CorruptLib work mode: %s (%i). %u packets of %u will be corrupted ##\n",
        mode_str, conf->mode, conf->pkt_corrupted, conf->pkt_cycles);
    return error_success;
}

// Convert error to string
const char* userio_error_to_str(enum error err)
{
    switch (err)
    {
        case error_success:
            return "error_success";
        case error_failure:
            return "error_failure";
        case error_no_env_var:
            return "error_no_env_var";
        case error_env_parse:
            return "error_env_parse";
        case error_env_range:
            return "error_env_range";
        case error_invalid_size:
            return "error_invalid_size";
        case error_buf_offs:
            return "error_buf_offs";
    }
    return "error_unknown";
}

// USER IO print helper message
void userio_print_help(void)
{
    fprintf(stderr, "######## libpacketcorrupt help ########\n");
    fprintf(stderr, "Environment variables:\n");
    fprintf(stderr, "%s:\tMCTP Packet corrupt mode\n", CFGENV_MODE);
    fprintf(stderr, "\tbypass:\t\tPacket passthrue\n");
    fprintf(stderr, "\tcommand:\tCorrupt response code in packets\n");
    fprintf(stderr, "\treserved:\tCorrupt reserved fields in packets\n");
    fprintf(stderr, "\tmsglen:\t\tChange message length of the packet\n");
    fprintf(stderr, "\tzerolen:\tSet packet message len to zero\n");
    fprintf(stderr, "\tversion:\tChange message version in the packets\n");
    fprintf(stderr,
            "\tcertlen:\tChange certificate len in certificate reponse\n");
    fprintf(
        stderr,
        "\tcertdata:\tChange certificate data in the certificate response\n");
    fprintf(stderr,
            "\tunsupalgo:\tChange algo field in the algorithm response\n");
    fprintf(
        stderr,
        "\tunsupcapab:\tChange cabability field in the capability response\n");
    fprintf(
        stderr,
        "\tversionfields:\tChange param1, param2, reserved in getVersion\n");
    fprintf(
        stderr,
        "\tcapabfields:\tChange param1, param2, reserved in getCapabilites\n");
    fprintf(stderr,
            "\tdigestfields:\tChange param1, param2, reserved in getDigest\n");
    fprintf(
        stderr,
        "\tcertfields:\tChange param1, param2, reserved in getCertificate\n");
    fprintf(
        stderr,
        "\talgofields:\tChange param1, param2, reserved in getAlgorithms\n");
    fprintf(stderr, "\tmeasdata:\tRandomly corrupt measurements data\n");
    fprintf(stderr, "%s:\tMCTP Packet corrupt probability n/t\n", CFGENV_LVL);
    fprintf(stderr, "\tn:\tNumber of corrupted packet in the sequence\n");
    fprintf(stderr, "\tt:\tSequence length\n");
    fprintf(stderr, "%s:\tMCTP Packet corrupt nums a,b,..%%n\n", CFGENV_LVL);
    fprintf(stderr, "\ta,b,...:\tNumber of corrupted packet in the sequence\n");
    fprintf(stderr, "\tt:\tSequence length\n");
    fprintf(stderr, "%s:\tComma-separated list of EIDs to drop\n",
            "MCTP_CORRUPT_DROP_EIDS");
    fprintf(stderr, "\tExample: 1,2,3 drops packets with EIDs 1, 2, and 3\n");
    fprintf(
        stderr,
        "\tUse ! for negation. Example: !1,2,3 allows EIDs 1, 2, and 3, and drops others\n");
    fprintf(stderr, "%s:\tComma-separated list of command types to drop\n",
            "MCTP_CORRUPT_TYPES");
    fprintf(stderr,
            "\tExample: 1,2,3 drops packets with command types 1, 2, and 3\n");
    fprintf(
        stderr,
        "\tUse ! for negation. Example: !1,2,3 allows types 1, 2, and 3, and drops others\n");
    fprintf(
        stderr,
        "\nNote: Packet dropping only occurs if the file /tmp/corrupt_drop_enable exists.\n");
}
