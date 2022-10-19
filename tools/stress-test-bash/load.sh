#!/bin/bash

source _utils.sh

HMC=${1:-localhost:3080}

DUMP_TASK_ID=""
DUMP_START_TIME="0"
TELEMETRY_START_TIME="0"
while true; do
    if [[ -z ${DUMP_TASK_ID} ]]; then
        echo "DUMP TIME: $(echo "$(get_time) - ${DUMP_START_TIME}" | bc)"
        DUMP_START_TIME=$(get_time)
        REQ_RSP=$(curl -s -d '{"DiagnosticDataType":"OEM", "OEMDiagnosticDataType":"DiagnosticType=SelfTest"}' -X POST http://${HMC}/redfish/v1/Systems/HGX_Baseboard_0/LogServices/Dump/Actions/LogService.CollectDiagnosticData/)
        echo ${REQ_RSP}
        DUMP_TASK_ID=$(get_value "${REQ_RSP}" 'Id')
        echo ${DUMP_TASK_ID}
        if [[ ${#REQ_RSP} == "0" ]]; then
            exit 1
        fi
    elif [[ ! -z "${DUMP_TASK_ID}" ]]; then
        DUMP_TASK_RSP=$(curl -s http://${HMC}/redfish/v1/TaskService/Tasks/${DUMP_TASK_ID})
        if [[ ${#DUMP_TASK_RSP} == "0" ]]; then
            exit 1
        fi
        DUMP_TASK_STATE=$(get_value "${DUMP_TASK_RSP}" 'TaskState')
        echo ${DUMP_TASK_STATE}
        if [[ "${DUMP_TASK_STATE}" != "Running" ]]; then
            DUMP_TASK_ID=""
            DUMP_TASK_STATE=""
        fi
    fi
    echo "TELEM TIME: $(echo "$(get_time) - ${TELEMETRY_START_TIME}" | bc)"
    TELEMETRY_START_TIME=$(get_time)
    REQ_RSP=$(curl -s http://${HMC}/redfish/v1/TelemetryService/MetricReports/HGX_PlatformEnvironmentMetrics_0)
    echo ${#REQ_RSP}
    if [[ ${#REQ_RSP} == "0" ]]; then
        exit 1
    fi
    sleep 0.1
done
