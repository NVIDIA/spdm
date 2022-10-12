#!/bin/bash

HMC=${1:-localhost:3080}
IMG1=${2:-img1.fwpkg}
IMG2=${3:-img2.fwpkg}

DUMP_TASK_ID=""

IMG=""
UPDATE_TASK_ID=""
TOKEN=`curl -k -H "Content-Type: application/json" -X POST http://${HMC}/login -d '{"username" : "root", "password" : "0penBmc"}' | grep token | awk '{print $2;}' | sed 's/\"//g'`

while true; do
    if [[ -z ${UPDATE_TASK_ID} ]] || [[ "${UPDATE_TASK_ID}" == "null" ]]; then
        if [[ -z ${IMG} ]] || [[ "${IMG}" == "${IMG2}" ]]; then
            IMG=${IMG1}
        else
            IMG=${IMG2}
        fi
        echo ${IMG}
        REQ_RSP=$(curl -s -H "Content-Type: application/octet-stream" -X POST -T ${IMG} http://${HMC}/redfish/v1/UpdateService)
        echo ${REQ_RSP}
        if [[ -z "${REQ_RSP}" ]]; then
            exit 1
        fi
        UPDATE_TASK_ID=$(echo ${REQ_RSP} | jq -r '.Id')
    elif [[ ! -z "${UPDATE_TASK_ID}" ]] && [[ "${UPDATE_TASK_ID}" != "null" ]]; then
        UPDATE_TASK_RSP=$(curl -s -k -H "X-Auth-Token: ${TOKEN}" -X GET http://${HMC}/redfish/v1/TaskService/Tasks/${UPDATE_TASK_ID})
        if [[ ! -z "${UPDATE_TASK_RSP}" ]]; then
            UPDATE_TASK_STATE=$(echo ${UPDATE_TASK_RSP} | jq -r '.TaskState')
            echo ${UPDATE_TASK_STATE}
            if [[ "${UPDATE_TASK_STATE}" != "Running" ]]; then
                UPDATE_TASK_ID=""
                UPDATE_TASK_STATE=""
            fi
        fi
    fi
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
    sleep 0.1
done
