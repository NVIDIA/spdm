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

#include <spdmcpp/common.hpp>

#include <vector>

#include <gtest/gtest.h>

using namespace spdmcpp;

/** Mock transport for testing TransportClass API (encodePre, encodePost,
 * decode, setupTimeout, clearTimeout) and LayerState without MCTP/linux. */
class MockTransportClass : public TransportClass
{
  public:
    static constexpr size_t kHeaderSize = 4;

    RetStat encodePre(std::vector<uint8_t>& /*buf*/,
                      TransportClass::LayerState& lay) override
    {
        setLayerSize(lay, kHeaderSize);
        return RetStat::OK;
    }

    RetStat encodePost(std::vector<uint8_t>& /*buf*/,
                       TransportClass::LayerState& /*lay*/) override
    {
        return RetStat::OK;
    }

    RetStat decode(std::vector<uint8_t>& /*buf*/,
                   TransportClass::LayerState& lay) override
    {
        setLayerSize(lay, kHeaderSize);
        return RetStat::OK;
    }

    RetStat setupTimeout(timeout_ms_t /*timeout*/) override
    {
        return RetStat::OK;
    }

    bool clearTimeout() override
    {
        return true;
    }
};

class TransportTest : public ::testing::Test
{};

TEST_F(TransportTest, EncodePreSetsLayerSize)
{
    MockTransportClass transport;
    std::vector<uint8_t> buf(64, 0);
    TransportClass::LayerState lay;

    RetStat rs = transport.encodePre(buf, lay);

    ASSERT_EQ(rs, RetStat::OK);
    EXPECT_EQ(lay.getOffset(), 0u);
    EXPECT_EQ(lay.getEndOffset(), MockTransportClass::kHeaderSize);
}

TEST_F(TransportTest, EncodePostReturnsOk)
{
    MockTransportClass transport;
    std::vector<uint8_t> buf(64, 0);
    TransportClass::LayerState lay;

    RetStat rs = transport.encodePost(buf, lay);

    EXPECT_EQ(rs, RetStat::OK);
}

TEST_F(TransportTest, DecodeSetsLayerSize)
{
    MockTransportClass transport;
    std::vector<uint8_t> buf(64, 0);
    TransportClass::LayerState lay;

    RetStat rs = transport.decode(buf, lay);

    ASSERT_EQ(rs, RetStat::OK);
    EXPECT_EQ(lay.getOffset(), 0u);
    EXPECT_EQ(lay.getEndOffset(), MockTransportClass::kHeaderSize);
}

TEST_F(TransportTest, SetupTimeoutReturnsOk)
{
    MockTransportClass transport;
    RetStat rs = transport.setupTimeout(1000);
    EXPECT_EQ(rs, RetStat::OK);
}

TEST_F(TransportTest, ClearTimeoutReturnsTrue)
{
    MockTransportClass transport;
    EXPECT_TRUE(transport.clearTimeout());
}

TEST_F(TransportTest, LayerStateGetOffsetGetEndOffset)
{
    TransportClass::LayerState lay;
    EXPECT_EQ(lay.getOffset(), 0u);
    EXPECT_EQ(lay.getEndOffset(), 0u);
}

TEST_F(TransportTest, DefaultTransportSetupTimeoutReturnsErrorUnknown)
{
    struct DefaultTimeoutTransport : TransportClass
    {
        RetStat encodePre(std::vector<uint8_t>&, LayerState& lay) override
        {
            setLayerSize(lay, 4);
            return RetStat::OK;
        }
        RetStat encodePost(std::vector<uint8_t>&, LayerState&) override
        {
            return RetStat::OK;
        }
        RetStat decode(std::vector<uint8_t>&, LayerState& lay) override
        {
            setLayerSize(lay, 4);
            return RetStat::OK;
        }
    };
    DefaultTimeoutTransport t;
    RetStat rs = t.setupTimeout(1000);
    EXPECT_EQ(rs, RetStat::ERROR_UNKNOWN);
}

TEST_F(TransportTest, DefaultTransportClearTimeoutReturnsFalse)
{
    struct DefaultClearTransport : TransportClass
    {
        RetStat encodePre(std::vector<uint8_t>&, LayerState& lay) override
        {
            setLayerSize(lay, 4);
            return RetStat::OK;
        }
        RetStat encodePost(std::vector<uint8_t>&, LayerState&) override
        {
            return RetStat::OK;
        }
        RetStat decode(std::vector<uint8_t>&, LayerState& lay) override
        {
            setLayerSize(lay, 4);
            return RetStat::OK;
        }
    };
    DefaultClearTransport t;
    EXPECT_FALSE(t.clearTimeout());
}
