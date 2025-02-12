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

#include "random.h"

#include <stdint.h>
#include <time.h>

// Global PRNG state
static u32 prng_state = 0;

//! Initialize random generator
int random_init(void)
{
    prng_state = (u32)time(NULL);
    if (prng_state == 0)
    {
        prng_state = 2463534242U;
    }
    return 0;
}

//! Get random value
int random_value(u32* val)
{
    // Xorshift32
    uint32_t x = prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    prng_state = x;
    *val = x;
    return 0;
}

//! Deinitialize random gen
void random_deinit(void)
{}

