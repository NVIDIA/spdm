#!/bin/bash

HMC=${1:-localhost:3080}

DUMP_TASK_ID=""
while true; do
    if [[ -z ${DUMP_TASK_ID} ]] || [[ "${DUMP_TASK_ID}" == "null" ]]; then
        REQ_RSP=$(curl -s -d '{"DiagnosticDataType":"OEM", "OEMDiagnosticDataType":"DiagnosticType=SelfTest"}' -X POST http://${HMC}/redfish/v1/Systems/HGX_Baseboard_0/LogServices/Dump/Actions/LogService.CollectDiagnosticData/)
        echo ${REQ_RSP}
        DUMP_TASK_ID=$(echo ${REQ_RSP} | jq -r '.Id')
        if [[ ${#REQ_RSP} == "0" ]]; then
            exit 1
        fi
    elif [[ ! -z "${DUMP_TASK_ID}" ]] && [[ "${DUMP_TASK_ID}" != "null" ]]; then
        DUMP_TASK_RSP=$(curl -s http://${HMC}/redfish/v1/TaskService/Tasks/${DUMP_TASK_ID})
        if [[ ${#DUMP_TASK_RSP} == "0" ]]; then
            exit 1
        fi
        DUMP_TASK_STATE=$(echo ${DUMP_TASK_RSP} | jq -r '.TaskState')
        echo ${DUMP_TASK_STATE}
        if [[ "${DUMP_TASK_STATE}" != "Running" ]]; then
            DUMP_TASK_ID=""
            DUMP_TASK_STATE=""
        fi
    fi
    REQ_RSP=$(curl -s http://${HMC}/redfish/v1/TelemetryService/MetricReports/HGX_PlatformEnvironmentMetrics_0)
    echo ${#REQ_RSP}
    if [[ ${#REQ_RSP} == "0" ]]; then
        exit 1
    fi
    sleep 0.01
done
