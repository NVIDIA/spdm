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

#include "config.h"

#include "test_helpers.hpp"

#include <spdmcpp/flag.hpp>
#include <spdmcpp/signature.hpp>

#include <gtest/gtest.h>

using namespace spdmcpp;

class SignatureTest : public ::testing::Test
{};

TEST_F(SignatureTest, ToSignatureEcdsaP256)
{
    EXPECT_EQ(toSignature(BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P256),
              SignatureEnum::TPM_ALG_ECDSA_ECC_NIST_P256);
}

TEST_F(SignatureTest, ToSignatureEcdsaP384)
{
    EXPECT_EQ(toSignature(BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P384),
              SignatureEnum::TPM_ALG_ECDSA_ECC_NIST_P384);
}

TEST_F(SignatureTest, ToSignatureEcdsaP521)
{
    EXPECT_EQ(toSignature(BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P521),
              SignatureEnum::TPM_ALG_ECDSA_ECC_NIST_P521);
}

TEST_F(SignatureTest, ToSignatureRsassa2048)
{
    EXPECT_EQ(toSignature(BaseAsymAlgoFlags::TPM_ALG_RSASSA_2048),
              SignatureEnum::TPM_ALG_RSASSA_2048);
}

TEST_F(SignatureTest, ToSignatureRsapss2048)
{
    EXPECT_EQ(toSignature(BaseAsymAlgoFlags::TPM_ALG_RSAPSS_2048),
              SignatureEnum::TPM_ALG_RSAPSS_2048);
}

TEST_F(SignatureTest, ToSignatureInvalid)
{
    BaseAsymAlgoFlags none = static_cast<BaseAsymAlgoFlags>(0);
    EXPECT_EQ(toSignature(none), SignatureEnum::INVALID);
}
