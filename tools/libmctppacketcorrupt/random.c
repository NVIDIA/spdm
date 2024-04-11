/*
* SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
* SPDX-License-Identifier: Apache-2.0
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

#include "random.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h> /* exit */

static FILE* frand;

//! Initialize random generator
int random_init(void)
{
    frand = fopen("/dev/urandom", "r");
    if(!frand) {
        return -1;
    }
    return 0;
}

//! Get random value
int random_value(u32* val)
{
    if(frand) {
        unsigned ret = fread(val, sizeof(*val), 1, frand);
        if(ret==1) {
            return 0;
        }
        return -1;
    }
    return -1;
}

//! Deinitialize random gen
void random_deinit(void)
{
    if(frand) {
        fclose(frand);
    }
}

