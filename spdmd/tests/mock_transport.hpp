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

#pragma once

#include <memory>
#include <string>
#include <vector>

// Forward declaration of message types
enum class SpdmMessageType
{
    INVALID,
    GET_VERSION,
    VERSION,
    GET_CAPABILITIES,
    CAPABILITIES,
    NEGOTIATE_ALGORITHMS,
    ALGORITHMS,
    GET_MEASUREMENTS,
    MEASUREMENTS
};

// Simple SPDM message class for testing
class SpdmMessage
{
  public:
    SpdmMessage() : type_(SpdmMessageType::INVALID)
    {}

    void setType(SpdmMessageType type)
    {
        type_ = type;
    }

    SpdmMessageType getType() const
    {
        return type_;
    }

  private:
    SpdmMessageType type_;
};

// Mock transport class for testing
class MockTransport
{
  public:
    MockTransport() : fail_next_operation_(false), simulate_timeout_(false)
    {}

    void setFailNextOperation(bool fail)
    {
        fail_next_operation_ = fail;
    }

    void simulateTimeout(bool timeout)
    {
        simulate_timeout_ = timeout;
    }

    SpdmMessageType getLastSentMessageType() const
    {
        return last_sent_type_;
    }

    void queueResponseMessage(const SpdmMessage& msg)
    {
        response_queue_.push_back(msg);
    }

    // Make member variables public for testing
    bool fail_next_operation_ = false;
    bool simulate_timeout_ = false;
    SpdmMessageType last_sent_type_ = SpdmMessageType::INVALID;
    std::vector<SpdmMessage> response_queue_;
};

// Connection class error and state enums
enum class ConnectionState
{
    Disconnected,
    Initialized,
    Connected,
    Error
};

enum class ConnectionError
{
    None,
    Timeout,
    TransportError,
    InvalidState
};

// Connection class for testing
class Connection
{
  public:
    Connection(std::shared_ptr<MockTransport> transport) :
        transport_(transport), state_(ConnectionState::Disconnected),
        last_error_(ConnectionError::None)
    {}

    bool initialize()
    {
        if (transport_->getLastSentMessageType() == SpdmMessageType::INVALID)
        {
            if (transport_->fail_next_operation_)
            {
                state_ = ConnectionState::Error;
                last_error_ = ConnectionError::TransportError;
                return false;
            }
            state_ = ConnectionState::Initialized;
            return true;
        }
        return false;
    }

    bool connect()
    {
        if (state_ == ConnectionState::Initialized)
        {
            if (transport_->fail_next_operation_)
            {
                state_ = ConnectionState::Error;
                last_error_ = ConnectionError::TransportError;
                return false;
            }
            state_ = ConnectionState::Connected;
            return true;
        }
        return false;
    }

    bool disconnect()
    {
        if (state_ == ConnectionState::Connected)
        {
            if (transport_->fail_next_operation_)
            {
                return false;
            }
            state_ = ConnectionState::Disconnected;
            return true;
        }
        return false;
    }

    bool reconnect()
    {
        if (state_ == ConnectionState::Error)
        {
            state_ = ConnectionState::Connected;
            return true;
        }
        return false;
    }

    bool sendMessage(const SpdmMessage& message, int timeout_ms = 0)
    {
        (void)message;    // Avoid unused parameter warning
        (void)timeout_ms; // Avoid unused parameter warning

        if (state_ != ConnectionState::Connected)
        {
            last_error_ = ConnectionError::InvalidState;
            return false;
        }

        if (transport_->simulate_timeout_)
        {
            last_error_ = ConnectionError::Timeout;
            return false;
        }

        if (transport_->fail_next_operation_)
        {
            state_ = ConnectionState::Error;
            last_error_ = ConnectionError::TransportError;
            return false;
        }

        return true;
    }

    bool receiveMessage(SpdmMessage& message)
    {
        (void)message; // Avoid unused parameter warning
        return true;
    }

    ConnectionState getState() const
    {
        return state_;
    }

    ConnectionError getLastError() const
    {
        return last_error_;
    }

  private:
    std::shared_ptr<MockTransport> transport_;
    ConnectionState state_;
    ConnectionError last_error_;
};