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

#include "mctp_endpoint_discovery.hpp"
#include "spdmd_app.hpp"

#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgReferee;

namespace spdmd
{

class MockSpdmdApp : public SpdmdApp
{
  public:
    MOCK_METHOD(void, connectMCTP, (const std::string& sockPath));
    MOCK_METHOD(void, discoveryUpdateResponder,
                (const dbus_api::ResponderArgs& args));
    MOCK_METHOD(sdbusplus::asio::connection&, getConn, ());
    MOCK_METHOD(spdmcpp::LogClass&, getLog, ());

    template <typename RetType>
    MOCK_METHOD(std::optional<RetType>, getPropertyByEid,
                (size_t eid, const std::string& propName), ());
};

class MctpDiscoveryTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ioc = std::make_shared<boost::asio::io_context>();
        conn = std::make_shared<sdbusplus::asio::connection>(*ioc);
        ON_CALL(mockApp, getConn()).WillByDefault(Return(*conn));
        ON_CALL(mockApp, getLog()).WillByDefault(Return(log));

        // Setup mock D-Bus server to handle requests
        dbusServer = std::make_unique<sdbusplus::asio::object_server>(*conn);
    }

    void TearDown() override
    {
        dbusServer.reset();
        conn.reset();
        ioc.reset();
    }

    // Helper method to run async operations
    void runContext()
    {
        ioc->run_for(std::chrono::milliseconds(100));
        ioc->restart();
    }

    MockSpdmdApp mockApp;
    spdmcpp::LogClass log{std::cout};
    std::shared_ptr<boost::asio::io_context> ioc;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::unique_ptr<sdbusplus::asio::object_server> dbusServer;
};

// Test CSM status initialization
TEST_F(MctpDiscoveryTest, InitCsmStatus)
{
    // Setup CSM interface
    auto csmInterface = dbusServer->add_interface(
        "/xyz/openbmc_project/state/configurableStateManager/MCTP",
        "xyz.openbmc_project.State.FeatureReady");

    csmInterface->register_property(
        "State",
        std::string("xyz.openbmc_project.State.FeatureReady.States.Enabled"));

    csmInterface->initialize();

    // Create MctpDiscovery with our mocked app
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    // Let the async operations run
    runContext();

    // Verify that setupMCTPServices was called since CSM is ready
    EXPECT_CALL(mockApp, getConn()).Times(::testing::AtLeast(1));

    // Change CSM state and verify the change is detected
    csmInterface->set_property(
        "State",
        std::string("xyz.openbmc_project.State.FeatureReady.States.Disabled"));

    runContext();

    // Set it back to enabled and expect services to be setup
    EXPECT_CALL(mockApp, getConn()).Times(::testing::AtLeast(1));

    csmInterface->set_property(
        "State",
        std::string("xyz.openbmc_project.State.FeatureReady.States.Enabled"));

    runContext();
}

// Test MCTP services discovery
TEST_F(MctpDiscoveryTest, GetMctpServicesAsync)
{
    // Setup object mapper interface
    auto mapperInterface =
        dbusServer->add_interface("/xyz/openbmc_project/object_mapper",
                                  "xyz.openbmc_project.ObjectMapper");

    // Setup mock GetSubTree method to return MCTP service
    std::map<std::string, std::map<std::string, std::vector<std::string>>>
        mockResponse;
    mockResponse["/xyz/openbmc_project/mctp/endpoint/1"]
                ["xyz.openbmc_project.MCTP.Control"] = {
                    "xyz.openbmc_project.MCTP.Endpoint"};

    mapperInterface->register_method(
        "GetSubTree", [mockResponse](const std::string&, int,
                                     const std::vector<std::string>&) {
            return mockResponse;
        });

    mapperInterface->initialize();

    // Create MctpDiscovery with our mocked app
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    // Call getMCTPServicesAsync and verify the callback is called with the
    // expected data
    std::atomic<bool> callbackCalled{false};

    discovery->getMCTPServicesAsync(
        [&callbackCalled](std::unordered_set<std::string> services) {
            EXPECT_EQ(services.size(), 1);
            EXPECT_TRUE(services.contains("xyz.openbmc_project.MCTP.Control"));
            callbackCalled = true;
        });

    runContext();

    EXPECT_TRUE(callbackCalled);
}

// Test MCTP object discovery by UUID
TEST_F(MctpDiscoveryTest, GetMctpObjectByUuid)
{
    // Setup MCTP service interface
    auto mctpObjMgrInterface = dbusServer->add_interface(
        "/xyz/openbmc_project/mctp", "org.freedesktop.DBus.ObjectManager");

    // Setup mock GetManagedObjects response
    dbus::ObjectValueTree mockManagedObjects;

    // Create a test endpoint
    std::string testUuid = "11111111-2222-3333-4444-555555555555";
    dbus::InterfaceMap endpointInterfaces;

    // Add MCTP UUID interface
    std::map<std::string, dbus::Value> uuidProps;
    uuidProps["UUID"] = testUuid;
    endpointInterfaces["xyz.openbmc_project.MCTP.UUID"] = uuidProps;

    // Add MCTP Endpoint interface
    std::map<std::string, dbus::Value> endpointProps;
    endpointProps["EID"] = static_cast<uint32_t>(42);
    std::vector<uint8_t> msgTypes = {5}; // SPDM type
    endpointProps["SupportedMessageTypes"] = msgTypes;
    endpointInterfaces["xyz.openbmc_project.MCTP.Endpoint"] = endpointProps;

    mockManagedObjects["/xyz/openbmc_project/mctp/endpoint/1"] =
        endpointInterfaces;

    mctpObjMgrInterface->register_method(
        "GetManagedObjects",
        [mockManagedObjects]() { return mockManagedObjects; });

    mctpObjMgrInterface->initialize();

    // Create MctpDiscovery with our mocked app
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    // Call getMCTPObjectAsync and verify callback receives the right object
    std::atomic<bool> callbackCalled{false};

    discovery->getMCTPObjectAsync(testUuid, [&callbackCalled, testUuid](
                                                MctpDiscovery::Object obj) {
        EXPECT_TRUE(obj.isValid());
        EXPECT_EQ(obj.path, "/xyz/openbmc_project/mctp/endpoint/1");

        // Verify UUID in returned interfaces
        std::string uuid = "";
        auto uuidIntf = obj.interfaces.find("xyz.openbmc_project.MCTP.UUID");
        if (uuidIntf != obj.interfaces.end())
        {
            auto uuidProp = uuidIntf->second.find("UUID");
            if (uuidProp != uuidIntf->second.end())
            {
                uuid = std::get<std::string>(uuidProp->second);
            }
        }
        EXPECT_EQ(uuid, testUuid);

        callbackCalled = true;
    });

    runContext();

    EXPECT_TRUE(callbackCalled);
}

// Test MCTP Endpoint Signal Handler
TEST_F(MctpDiscoveryTest, MctpNewObjectSignal)
{
    // Create MctpDiscovery with our mocked app
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    // Simulate CSM being ready
    auto csmInterface = dbusServer->add_interface(
        "/xyz/openbmc_project/state/configurableStateManager/MCTP",
        "xyz.openbmc_project.State.FeatureReady");

    csmInterface->register_property(
        "State",
        std::string("xyz.openbmc_project.State.FeatureReady.States.Enabled"));

    csmInterface->initialize();
    runContext();

    // Create a test endpoint object path and interfaces
    sdbusplus::object_path objPath("/xyz/openbmc_project/mctp/endpoint/1");
    dbus::InterfaceMap interfaces;

    // Add MCTP UUID interface
    std::map<std::string, dbus::Value> uuidProps;
    std::string testUuid = "11111111-2222-3333-4444-555555555555";
    uuidProps["UUID"] = testUuid;
    interfaces["xyz.openbmc_project.MCTP.UUID"] = uuidProps;

    // Add MCTP Endpoint interface
    std::map<std::string, dbus::Value> endpointProps;
    endpointProps["EID"] = static_cast<uint32_t>(42);
    std::vector<uint8_t> msgTypes = {5}; // SPDM type
    endpointProps["SupportedMessageTypes"] = msgTypes;
    interfaces["xyz.openbmc_project.MCTP.Endpoint"] = endpointProps;

    // Add binding interface for medium type
    std::map<std::string, dbus::Value> bindingProps;
    bindingProps["BindingType"] =
        std::string("xyz.openbmc_project.MCTP.Binding.Types.PCIe");
    interfaces["xyz.openbmc_project.MCTP.Binding"] = bindingProps;

    // Add transport socket interface
    std::map<std::string, dbus::Value> socketProps;
    std::vector<uint8_t> sockAddr = {'/', 't', 'm', 'p', '/', 'm', 'c',
                                     't', 'p', '.', 's', 'o', 'c', 'k'};
    socketProps["Address"] = sockAddr;
    interfaces["xyz.openbmc_project.Common.UnixSocket"] = socketProps;

    // Expect connectMCTP and discoveryUpdateResponder to be called
    EXPECT_CALL(mockApp, connectMCTP("/tmp/mctp.sock")).Times(1);

    dbus_api::ResponderArgs expectedArgs;
    expectedArgs.eid = 42;
    expectedArgs.uuid = testUuid;
    expectedArgs.medium = "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.PCIe";
    expectedArgs.mctpPath = objPath;

#ifdef DISCOVERY_ONLY_FROM_MCTP_CONTROL
    EXPECT_CALL(mockApp, discoveryUpdateResponder(testing::_))
        .Times(1)
        .WillOnce(testing::SaveArg<0>(&expectedArgs));
#else
    // For non-DISCOVERY_ONLY_FROM_MCTP_CONTROL, need to mock
    // getInventoryPathAsync response Add mapper interface for inventory path
    // lookup
    auto mapperInterface =
        dbusServer->add_interface("/xyz/openbmc_project/object_mapper",
                                  "xyz.openbmc_project.ObjectMapper");

    std::map<std::string, std::map<std::string, std::set<std::string>>>
        mockResponse;
    mockResponse["/xyz/openbmc_project/inventory/system/device"]
                ["xyz.openbmc_project.Inventory"] = {
                    "xyz.openbmc_project.Inventory.Item.SPDMResponder"};

    mapperInterface->register_method(
        "GetSubTree", [mockResponse](const std::string&, int,
                                     const std::vector<std::string>&) {
            return mockResponse;
        });

    mapperInterface->initialize();

    // Mock getPropertyValue to return the UUID
    auto propsInterface = dbusServer->add_interface(
        "/xyz/openbmc_project/inventory/system/device",
        "org.freedesktop.DBus.Properties");

    propsInterface->register_method(
        "Get", [testUuid](const std::string&, const std::string&) {
            return std::variant<std::string>(testUuid);
        });

    propsInterface->initialize();

    EXPECT_CALL(mockApp, discoveryUpdateResponder(testing::_))
        .Times(1)
        .WillOnce(testing::SaveArg<0>(&expectedArgs));
#endif

    // Call mctpNewObjectSignal
    discovery->mctpNewObjectSignal(objPath, interfaces);

    runContext();

    // Verify args passed to discoveryUpdateResponder
    EXPECT_EQ(expectedArgs.eid, 42);
    EXPECT_EQ(expectedArgs.uuid, testUuid);
    EXPECT_EQ(expectedArgs.medium,
              "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.PCIe");
    EXPECT_EQ(expectedArgs.mctpPath, objPath);
}

// Test getInventoryPathAsync
TEST_F(MctpDiscoveryTest, GetInventoryPath)
{
    // Create MctpDiscovery with our mocked app
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    // Setup object mapper interface
    auto mapperInterface =
        dbusServer->add_interface("/xyz/openbmc_project/object_mapper",
                                  "xyz.openbmc_project.ObjectMapper");

    // Setup mock GetSubTree method for inventory path
    std::map<std::string, std::map<std::string, std::set<std::string>>>
        mockResponse;
    mockResponse["/xyz/openbmc_project/inventory/system/device"]
                ["xyz.openbmc_project.Inventory"] = {
                    "xyz.openbmc_project.Inventory.Item.SPDMResponder",
                    "xyz.openbmc_project.Common.UUID"};

    mapperInterface->register_method(
        "GetSubTree", [mockResponse](const std::string&, int,
                                     const std::vector<std::string>&) {
            return mockResponse;
        });

    mapperInterface->initialize();

    // Setup properties interface for UUID lookup
    auto propsInterface = dbusServer->add_interface(
        "/xyz/openbmc_project/inventory/system/device",
        "org.freedesktop.DBus.Properties");

    std::string testUuid = "11111111-2222-3333-4444-555555555555";

    propsInterface->register_method(
        "Get",
        [testUuid](const std::string& interface, const std::string& property) {
            if (interface == "xyz.openbmc_project.Common.UUID" &&
                property == "UUID")
            {
                return std::variant<std::string>(testUuid);
            }
            return std::variant<std::string>("");
        });

    propsInterface->initialize();

    // Test getInventoryPathAsync
    std::atomic<bool> callbackCalled{false};

    discovery->getInventoryPathAsync(
        testUuid, [&callbackCalled](sdbusplus::object_path path) {
            EXPECT_EQ(path.str, "/xyz/openbmc_project/inventory/system/device");
            callbackCalled = true;
        });

    runContext();

    EXPECT_TRUE(callbackCalled);
}

// Test getMediumType() with valid medium type
TEST_F(MctpDiscoveryTest, GetMediumType_ValidPCIe)
{
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    dbus::InterfaceMap interfaces;
    std::map<std::string, dbus::Value> endpointProps;
    endpointProps["MediumType"] =
        std::string("xyz.openbmc_project.MCTP.Endpoint.MediaTypes.PCIe");
    interfaces["xyz.openbmc_project.MCTP.Endpoint"] = endpointProps;

    // Access the private method through a wrapper or make it public for testing
    // For now, we'll test indirectly through mctpNewObjectSignal
    // which calls getMediumType internally
}

// Test getMediumType() with different medium types
TEST_F(MctpDiscoveryTest, GetMediumType_AllTypes)
{
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    // Test all supported medium types
    std::vector<std::string> mediumTypes = {
        "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.PCIe",
        "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.USB",
        "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.SPI",
        "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.I3C",
        "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.KCS",
        "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.Serial",
        "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.SMBus"};

    for (const auto& mediumType : mediumTypes)
    {
        dbus::InterfaceMap interfaces;
        std::map<std::string, dbus::Value> endpointProps;
        endpointProps["MediumType"] = mediumType;
        interfaces["xyz.openbmc_project.MCTP.Endpoint"] = endpointProps;

        // The medium type should be extracted correctly
        // This is tested indirectly through mctpNewObjectSignal
    }
}

// getMediumType: MCTP.Endpoint present but MediumType
TEST_F(MctpDiscoveryTest,
       GetMediumType_MissingMediumTypeProperty_DefaultsToPCIe)
{
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    // Simulate CSM being ready
    auto csmInterface = dbusServer->add_interface(
        "/xyz/openbmc_project/state/configurableStateManager/MCTP",
        "xyz.openbmc_project.State.FeatureReady");

    csmInterface->register_property(
        "State",
        std::string("xyz.openbmc_project.State.FeatureReady.States.Enabled"));

    csmInterface->initialize();
    runContext();

    sdbusplus::object_path objPath("/xyz/openbmc_project/mctp/endpoint/1");
    dbus::InterfaceMap interfaces;

    std::map<std::string, dbus::Value> uuidProps;
    std::string testUuid = "11111111-2222-3333-4444-555555555555";
    uuidProps["UUID"] = testUuid;
    interfaces["xyz.openbmc_project.MCTP.UUID"] = uuidProps;

    std::map<std::string, dbus::Value> endpointProps;
    endpointProps["EID"] = static_cast<uint32_t>(42);
    std::vector<uint8_t> msgTypes = {5};
    endpointProps["SupportedMessageTypes"] = msgTypes;
    interfaces["xyz.openbmc_project.MCTP.Endpoint"] = endpointProps;

    std::map<std::string, dbus::Value> bindingProps;
    bindingProps["BindingType"] =
        std::string("xyz.openbmc_project.MCTP.Binding.Types.PCIe");
    interfaces["xyz.openbmc_project.MCTP.Binding"] = bindingProps;

    std::map<std::string, dbus::Value> socketProps;
    std::vector<uint8_t> sockAddr = {'/', 't', 'm', 'p', '/', 'm', 'c',
                                     't', 'p', '.', 's', 'o', 'c', 'k'};
    socketProps["Address"] = sockAddr;
    interfaces["xyz.openbmc_project.Common.UnixSocket"] = socketProps;

    EXPECT_CALL(mockApp, connectMCTP("/tmp/mctp.sock")).Times(1);

    dbus_api::ResponderArgs capturedArgs{};

#ifdef DISCOVERY_ONLY_FROM_MCTP_CONTROL
    EXPECT_CALL(mockApp, discoveryUpdateResponder(testing::_))
        .Times(1)
        .WillOnce(testing::SaveArg<0>(&capturedArgs));
#else
    auto mapperInterface =
        dbusServer->add_interface("/xyz/openbmc_project/object_mapper",
                                  "xyz.openbmc_project.ObjectMapper");

    std::map<std::string, std::map<std::string, std::set<std::string>>>
        mockResponse;
    mockResponse["/xyz/openbmc_project/inventory/system/device"]
                ["xyz.openbmc_project.Inventory"] = {
                    "xyz.openbmc_project.Inventory.Item.SPDMResponder"};

    mapperInterface->register_method(
        "GetSubTree", [mockResponse](const std::string&, int,
                                     const std::vector<std::string>&) {
            return mockResponse;
        });

    mapperInterface->initialize();

    auto propsInterface = dbusServer->add_interface(
        "/xyz/openbmc_project/inventory/system/device",
        "org.freedesktop.DBus.Properties");

    propsInterface->register_method(
        "Get", [testUuid](const std::string&, const std::string&) {
            return std::variant<std::string>(testUuid);
        });

    propsInterface->initialize();

    EXPECT_CALL(mockApp, discoveryUpdateResponder(testing::_))
        .Times(1)
        .WillOnce(testing::SaveArg<0>(&capturedArgs));
#endif

    discovery->mctpNewObjectSignal(objPath, interfaces);
    runContext();

    EXPECT_EQ(capturedArgs.eid, 42u);
    EXPECT_EQ(capturedArgs.uuid, testUuid);
    EXPECT_EQ(capturedArgs.medium,
              "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.PCIe");
    EXPECT_EQ(capturedArgs.bindingType,
              "xyz.openbmc_project.MCTP.Binding.Types.PCIe");
    EXPECT_EQ(capturedArgs.mctpPath, objPath);
}

// Test getBindingType() with valid binding types
TEST_F(MctpDiscoveryTest, GetBindingType_AllTypes)
{
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    std::vector<std::string> bindingTypes = {
        "xyz.openbmc_project.MCTP.Binding.BindingTypes.PCIe",
        "xyz.openbmc_project.MCTP.Binding.BindingTypes.USB",
        "xyz.openbmc_project.MCTP.Binding.BindingTypes.SPI",
        "xyz.openbmc_project.MCTP.Binding.BindingTypes.I3C",
        "xyz.openbmc_project.MCTP.Binding.BindingTypes.KCS",
        "xyz.openbmc_project.MCTP.Binding.BindingTypes.Serial",
        "xyz.openbmc_project.MCTP.Binding.BindingTypes.SMBus"};

    for (const auto& bindingType : bindingTypes)
    {
        dbus::InterfaceMap interfaces;
        std::map<std::string, dbus::Value> bindingProps;
        bindingProps["BindingType"] = bindingType;
        interfaces["xyz.openbmc_project.MCTP.Binding"] = bindingProps;
    }
}

// Test getBindingType() with missing binding interface
TEST_F(MctpDiscoveryTest, GetBindingType_MissingInterface)
{
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    // Simulate CSM being ready
    auto csmInterface = dbusServer->add_interface(
        "/xyz/openbmc_project/state/configurableStateManager/MCTP",
        "xyz.openbmc_project.State.FeatureReady");

    csmInterface->register_property(
        "State",
        std::string("xyz.openbmc_project.State.FeatureReady.States.Enabled"));

    csmInterface->initialize();
    runContext();

    // Create interfaces without binding interface
    sdbusplus::object_path objPath("/xyz/openbmc_project/mctp/endpoint/1");
    dbus::InterfaceMap interfaces;

    std::map<std::string, dbus::Value> uuidProps;
    std::string testUuid = "11111111-2222-3333-4444-555555555555";
    uuidProps["UUID"] = testUuid;
    interfaces["xyz.openbmc_project.MCTP.UUID"] = uuidProps;

    std::map<std::string, dbus::Value> endpointProps;
    endpointProps["EID"] = static_cast<uint32_t>(42);
    endpointProps["MediumType"] =
        std::string("xyz.openbmc_project.MCTP.Endpoint.MediaTypes.PCIe");
    std::vector<uint8_t> msgTypes = {5};
    endpointProps["SupportedMessageTypes"] = msgTypes;
    interfaces["xyz.openbmc_project.MCTP.Endpoint"] = endpointProps;

    EXPECT_CALL(mockApp, connectMCTP(testing::_)).Times(1);
    EXPECT_CALL(mockApp, discoveryUpdateResponder(testing::_)).Times(0);

    discovery->mctpNewObjectSignal(objPath, interfaces);
    runContext();
}

// Test getBindingType() with missing BindingType property
TEST_F(MctpDiscoveryTest, GetBindingType_MissingProperty)
{
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    // Simulate CSM being ready
    auto csmInterface = dbusServer->add_interface(
        "/xyz/openbmc_project/state/configurableStateManager/MCTP",
        "xyz.openbmc_project.State.FeatureReady");

    csmInterface->register_property(
        "State",
        std::string("xyz.openbmc_project.State.FeatureReady.States.Enabled"));

    csmInterface->initialize();
    runContext();

    sdbusplus::object_path objPath("/xyz/openbmc_project/mctp/endpoint/1");
    dbus::InterfaceMap interfaces;

    std::map<std::string, dbus::Value> uuidProps;
    std::string testUuid = "11111111-2222-3333-4444-555555555555";
    uuidProps["UUID"] = testUuid;
    interfaces["xyz.openbmc_project.MCTP.UUID"] = uuidProps;

    std::map<std::string, dbus::Value> endpointProps;
    endpointProps["EID"] = static_cast<uint32_t>(42);
    endpointProps["MediumType"] =
        std::string("xyz.openbmc_project.MCTP.Endpoint.MediaTypes.PCIe");
    std::vector<uint8_t> msgTypes = {5};
    endpointProps["SupportedMessageTypes"] = msgTypes;
    interfaces["xyz.openbmc_project.MCTP.Endpoint"] = endpointProps;

    // Binding interface exists but without BindingType property
    std::map<std::string, dbus::Value> bindingProps;
    interfaces["xyz.openbmc_project.MCTP.Binding"] = bindingProps;

    EXPECT_CALL(mockApp, connectMCTP(testing::_)).Times(1);
    EXPECT_CALL(mockApp, discoveryUpdateResponder(testing::_)).Times(0);

    // Call should fail due to missing binding type property
    discovery->mctpNewObjectSignal(objPath, interfaces);
    runContext();
}

// Test with complete and valid medium and binding types
TEST_F(MctpDiscoveryTest, GetMediumAndBindingType_ValidComplete)
{
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    // Simulate CSM being ready
    auto csmInterface = dbusServer->add_interface(
        "/xyz/openbmc_project/state/configurableStateManager/MCTP",
        "xyz.openbmc_project.State.FeatureReady");

    csmInterface->register_property(
        "State",
        std::string("xyz.openbmc_project.State.FeatureReady.States.Enabled"));

    csmInterface->initialize();
    runContext();

    sdbusplus::object_path objPath("/xyz/openbmc_project/mctp/endpoint/1");
    dbus::InterfaceMap interfaces;

    std::map<std::string, dbus::Value> uuidProps;
    std::string testUuid = "11111111-2222-3333-4444-555555555555";
    uuidProps["UUID"] = testUuid;
    interfaces["xyz.openbmc_project.MCTP.UUID"] = uuidProps;

    std::map<std::string, dbus::Value> endpointProps;
    endpointProps["EID"] = static_cast<uint32_t>(42);
    endpointProps["MediumType"] =
        std::string("xyz.openbmc_project.MCTP.Endpoint.MediaTypes.USB");
    std::vector<uint8_t> msgTypes = {5};
    endpointProps["SupportedMessageTypes"] = msgTypes;
    interfaces["xyz.openbmc_project.MCTP.Endpoint"] = endpointProps;

    std::map<std::string, dbus::Value> bindingProps;
    bindingProps["BindingType"] =
        std::string("xyz.openbmc_project.MCTP.Binding.BindingTypes.USB");
    interfaces["xyz.openbmc_project.MCTP.Binding"] = bindingProps;

    std::map<std::string, dbus::Value> socketProps;
    std::vector<uint8_t> sockAddr = {'/', 't', 'm', 'p', '/', 'm', 'c',
                                     't', 'p', '.', 's', 'o', 'c', 'k'};
    socketProps["Address"] = sockAddr;
    interfaces["xyz.openbmc_project.Common.UnixSocket"] = socketProps;

    EXPECT_CALL(mockApp, connectMCTP("/tmp/mctp.sock")).Times(1);

    dbus_api::ResponderArgs capturedArgs;
    EXPECT_CALL(mockApp, discoveryUpdateResponder(testing::_))
        .Times(1)
        .WillOnce(testing::SaveArg<0>(&capturedArgs));

    discovery->mctpNewObjectSignal(objPath, interfaces);
    runContext();

    // Verify the captured arguments
    EXPECT_EQ(capturedArgs.medium,
              "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.USB");
    EXPECT_EQ(capturedArgs.bindingType,
              "xyz.openbmc_project.MCTP.Binding.BindingTypes.USB");
}

// Test all medium types through mctpNewObjectSignal
TEST_F(MctpDiscoveryTest, MctpNewObjectSignal_AllMediumTypes)
{
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    // Simulate CSM being ready
    auto csmInterface = dbusServer->add_interface(
        "/xyz/openbmc_project/state/configurableStateManager/MCTP",
        "xyz.openbmc_project.State.FeatureReady");
    csmInterface->register_property(
        "State",
        std::string("xyz.openbmc_project.State.FeatureReady.States.Enabled"));
    csmInterface->initialize();
    runContext();

    std::vector<std::string> allMediumTypes = {
        "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.PCIe",
        "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.USB",
        "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.SPI",
        "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.I3C",
        "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.KCS",
        "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.Serial",
        "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.SMBus"};

    for (const auto& mediumType : allMediumTypes)
    {
        sdbusplus::object_path objPath("/xyz/openbmc_project/mctp/endpoint/1");
        dbus::InterfaceMap interfaces;

        std::map<std::string, dbus::Value> uuidProps;
        uuidProps["UUID"] = std::string("11111111-2222-3333-4444-555555555555");
        interfaces["xyz.openbmc_project.MCTP.UUID"] = uuidProps;

        std::map<std::string, dbus::Value> endpointProps;
        endpointProps["EID"] = static_cast<uint32_t>(42);
        endpointProps["MediumType"] = mediumType;
        std::vector<uint8_t> msgTypes = {5};
        endpointProps["SupportedMessageTypes"] = msgTypes;
        interfaces["xyz.openbmc_project.MCTP.Endpoint"] = endpointProps;

        std::map<std::string, dbus::Value> bindingProps;
        bindingProps["BindingType"] =
            std::string("xyz.openbmc_project.MCTP.Binding.BindingTypes.PCIe");
        interfaces["xyz.openbmc_project.MCTP.Binding"] = bindingProps;

        std::map<std::string, dbus::Value> socketProps;
        std::vector<uint8_t> sockAddr = {'/', 't', 'm', 'p', '/', 'm', 'c',
                                         't', 'p', '.', 's', 'o', 'c', 'k'};
        socketProps["Address"] = sockAddr;
        interfaces["xyz.openbmc_project.Common.UnixSocket"] = socketProps;

        EXPECT_CALL(mockApp, connectMCTP("/tmp/mctp.sock")).Times(1);

        dbus_api::ResponderArgs capturedArgs;
        EXPECT_CALL(mockApp, discoveryUpdateResponder(testing::_))
            .Times(1)
            .WillOnce(testing::SaveArg<0>(&capturedArgs));

        discovery->mctpNewObjectSignal(objPath, interfaces);
        runContext();

        EXPECT_EQ(capturedArgs.medium, mediumType);
    }
}

// Test all binding types through mctpNewObjectSignal
TEST_F(MctpDiscoveryTest, MctpNewObjectSignal_AllBindingTypes)
{
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    // Simulate CSM being ready
    auto csmInterface = dbusServer->add_interface(
        "/xyz/openbmc_project/state/configurableStateManager/MCTP",
        "xyz.openbmc_project.State.FeatureReady");
    csmInterface->register_property(
        "State",
        std::string("xyz.openbmc_project.State.FeatureReady.States.Enabled"));
    csmInterface->initialize();
    runContext();

    std::vector<std::string> allBindingTypes = {
        "xyz.openbmc_project.MCTP.Binding.BindingTypes.PCIe",
        "xyz.openbmc_project.MCTP.Binding.BindingTypes.USB",
        "xyz.openbmc_project.MCTP.Binding.BindingTypes.SPI",
        "xyz.openbmc_project.MCTP.Binding.BindingTypes.I3C",
        "xyz.openbmc_project.MCTP.Binding.BindingTypes.KCS",
        "xyz.openbmc_project.MCTP.Binding.BindingTypes.Serial",
        "xyz.openbmc_project.MCTP.Binding.BindingTypes.SMBus"};

    for (const auto& bindingType : allBindingTypes)
    {
        sdbusplus::object_path objPath("/xyz/openbmc_project/mctp/endpoint/1");
        dbus::InterfaceMap interfaces;

        std::map<std::string, dbus::Value> uuidProps;
        uuidProps["UUID"] = std::string("11111111-2222-3333-4444-555555555555");
        interfaces["xyz.openbmc_project.MCTP.UUID"] = uuidProps;

        std::map<std::string, dbus::Value> endpointProps;
        endpointProps["EID"] = static_cast<uint32_t>(42);
        endpointProps["MediumType"] =
            std::string("xyz.openbmc_project.MCTP.Endpoint.MediaTypes.PCIe");
        std::vector<uint8_t> msgTypes = {5};
        endpointProps["SupportedMessageTypes"] = msgTypes;
        interfaces["xyz.openbmc_project.MCTP.Endpoint"] = endpointProps;

        std::map<std::string, dbus::Value> bindingProps;
        bindingProps["BindingType"] = bindingType;
        interfaces["xyz.openbmc_project.MCTP.Binding"] = bindingProps;

        std::map<std::string, dbus::Value> socketProps;
        std::vector<uint8_t> sockAddr = {'/', 't', 'm', 'p', '/', 'm', 'c',
                                         't', 'p', '.', 's', 'o', 'c', 'k'};
        socketProps["Address"] = sockAddr;
        interfaces["xyz.openbmc_project.Common.UnixSocket"] = socketProps;

        EXPECT_CALL(mockApp, connectMCTP("/tmp/mctp.sock")).Times(1);

        dbus_api::ResponderArgs capturedArgs;
        EXPECT_CALL(mockApp, discoveryUpdateResponder(testing::_))
            .Times(1)
            .WillOnce(testing::SaveArg<0>(&capturedArgs));

        discovery->mctpNewObjectSignal(objPath, interfaces);
        runContext();

        EXPECT_EQ(capturedArgs.bindingType, bindingType);
    }
}

// Test error path when getMediumType returns empty
TEST_F(MctpDiscoveryTest, MctpNewObjectSignal_EmptyMediumType)
{
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    auto csmInterface = dbusServer->add_interface(
        "/xyz/openbmc_project/state/configurableStateManager/MCTP",
        "xyz.openbmc_project.State.FeatureReady");
    csmInterface->register_property(
        "State",
        std::string("xyz.openbmc_project.State.FeatureReady.States.Enabled"));
    csmInterface->initialize();
    runContext();

    sdbusplus::object_path objPath("/xyz/openbmc_project/mctp/endpoint/1");
    dbus::InterfaceMap interfaces;

    std::map<std::string, dbus::Value> uuidProps;
    uuidProps["UUID"] = std::string("11111111-2222-3333-4444-555555555555");
    interfaces["xyz.openbmc_project.MCTP.UUID"] = uuidProps;

    std::map<std::string, dbus::Value> endpointProps;
    endpointProps["EID"] = static_cast<uint32_t>(42);
    // MediumType missing - should cause getMediumType to return empty
    std::vector<uint8_t> msgTypes = {5};
    endpointProps["SupportedMessageTypes"] = msgTypes;
    interfaces["xyz.openbmc_project.MCTP.Endpoint"] = endpointProps;

    std::map<std::string, dbus::Value> bindingProps;
    bindingProps["BindingType"] =
        std::string("xyz.openbmc_project.MCTP.Binding.BindingTypes.PCIe");
    interfaces["xyz.openbmc_project.MCTP.Binding"] = bindingProps;

    // Should NOT call discoveryUpdateResponder due to empty medium type
    EXPECT_CALL(mockApp, discoveryUpdateResponder(testing::_)).Times(0);

    discovery->mctpNewObjectSignal(objPath, interfaces);
    runContext();
}

// Test error path when getBindingType returns empty
TEST_F(MctpDiscoveryTest, MctpNewObjectSignal_EmptyBindingType)
{
    std::unique_ptr<MctpDiscovery> discovery =
        std::make_unique<MctpDiscovery>(mockApp);

    auto csmInterface = dbusServer->add_interface(
        "/xyz/openbmc_project/state/configurableStateManager/MCTP",
        "xyz.openbmc_project.State.FeatureReady");
    csmInterface->register_property(
        "State",
        std::string("xyz.openbmc_project.State.FeatureReady.States.Enabled"));
    csmInterface->initialize();
    runContext();

    sdbusplus::object_path objPath("/xyz/openbmc_project/mctp/endpoint/1");
    dbus::InterfaceMap interfaces;

    std::map<std::string, dbus::Value> uuidProps;
    uuidProps["UUID"] = std::string("11111111-2222-3333-4444-555555555555");
    interfaces["xyz.openbmc_project.MCTP.UUID"] = uuidProps;

    std::map<std::string, dbus::Value> endpointProps;
    endpointProps["EID"] = static_cast<uint32_t>(42);
    endpointProps["MediumType"] =
        std::string("xyz.openbmc_project.MCTP.Endpoint.MediaTypes.PCIe");
    std::vector<uint8_t> msgTypes = {5};
    endpointProps["SupportedMessageTypes"] = msgTypes;
    interfaces["xyz.openbmc_project.MCTP.Endpoint"] = endpointProps;

    // No binding interface - should cause getBindingType to return empty
    std::map<std::string, dbus::Value> emptyBindingProps;
    interfaces["xyz.openbmc_project.MCTP.Binding"] = emptyBindingProps;

    // Should NOT call discoveryUpdateResponder due to empty binding type
    EXPECT_CALL(mockApp, discoveryUpdateResponder(testing::_)).Times(0);

    discovery->mctpNewObjectSignal(objPath, interfaces);
    runContext();
}

} // namespace spdmd
