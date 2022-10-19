#!/bin/bash

source _utils.sh

HMC=${1}
CHASSIS=${2}
REQ_DATA=${3}
RESULT_FILE=${4}
OUTPUT_FOLDER=${5}

mkdir -p ${OUTPUT_FOLDER}

REQ_START=$(get_time)
REQ_RSP=$(curl -s -d "${REQ_DATA}" -X POST http://${HMC}/redfish/v1/ComponentIntegrity/${CHASSIS}/Actions/SPDMGetSignedMeasurements)
TASK_ID=$(get_value "${REQ_RSP}" 'Id')
if [[ -z "${TASK_ID}" ]]; then
    SIGNED_MEAS=$(echo ${REQ_RSP} | grep 'SignedMeasurements')
    if [[ ! -z "${SIGNED_MEAS}" ]]; then
        REQ_END=$(get_time)
        OUTPUT=$(echo ${REQ_RSP})
        OUTPUT_FILENAME="meas-$(get_random 4).json"
        echo ${OUTPUT} > ${OUTPUT_FOLDER}/${OUTPUT_FILENAME}
        OUTPUT=${OUTPUT_FILENAME}
    fi
else
    TASK_RSP=$(curl -s http://${HMC}/redfish/v1/TaskService/Tasks/${TASK_ID})
    TASK_STATE=$(get_value "${TASK_RSP}" 'TaskState')
    while [[ "${TASK_STATE}" == "Running" ]]; do
        sleep 0.05
        TASK_RSP=$(curl -s http://${HMC}/redfish/v1/TaskService/Tasks/${TASK_ID})
        TASK_STATE=$(get_value "${TASK_RSP}" 'TaskState')        
    done
    if [[ "${TASK_STATE}" == "Completed" ]]; then
        START_TIME=$(get_value "${TASK_RSP}" 'StartTime')
        END_TIME=$(get_value "${TASK_RSP}" 'EndTime')
        LOCATION=$(get_value "${TASK_RSP}" 'Location')
        if [[ ! -z "${LOCATION}" ]]; then
            OUTPUT=$(curl -s http://${HMC}${LOCATION})
        fi
        OUTPUT_FILENAME="meas-$(get_random 8).json"
        echo ${OUTPUT} > ${OUTPUT_FOLDER}/${OUTPUT_FILENAME}
        OUTPUT=${OUTPUT_FILENAME}
    elif [[ "${TASK_STATE}" != "Running" ]]; then
        if [[ ! -z "${TASK_RSP}" ]]; then
            OUTPUT=$(echo "${TASK_RSP}" | grep "has detected errors" | awk -F '"Message": ' '{print $2}')
        else
            OUTPUT="Empty task response"
        fi
    fi
    REQ_END=$(get_time)
fi

echo "${CHASSIS};${REQ_DATA};${REQ_START};${REQ_END};${OUTPUT};${START_TIME};${END_TIME}" >> ${RESULT_FILE}
