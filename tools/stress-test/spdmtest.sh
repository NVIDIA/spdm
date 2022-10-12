#!/bin/bash
PAR_JSON=${1}
PAR_CHASSIS=${2:-None}
HMC=${3:-localhost:3080}

declare -a REQ_ARR=()

process_request() {
    local REQ=${1}
    local REQ_JSON=""
    local CHASSIS=""
    local HAS_CHASSIS=$(echo ${REQ} | jq -r 'has("Chassis")')
    if [[ "${HAS_CHASSIS}" == "true" ]]; then
        REQ_JSON=$(echo ${REQ} | jq 'del(.Chassis)')
    else
        REQ_JSON=$(echo ${REQ})
    fi
    if [[ -z "${PAR_CHASSIS}" ]] || [[ "${PAR_CHASSIS}" == "None" ]]; then
        CHASSIS=$(echo ${REQ} | jq -r '.Chassis')
    else
        CHASSIS=${PAR_CHASSIS}
    fi

    local REQ_START=$(date +"%s.%3N")
    local REQ_END=""
    local OUTPUT=""
    local MEASUREMENT_DURATION=""
    local REQUEST_DURATION=""

    local REQ_RSP=$(curl -s -d "${REQ_JSON}" -X POST http://${HMC}/redfish/v1/ComponentIntegrity/${CHASSIS}/Actions/SPDMGetSignedMeasurements)
    local TASK_ID=$(echo ${REQ_RSP} | jq -r '.Id')
    if [[ -z "${TASK_ID}" ]] || [[ "${TASK_ID}" == "null" ]]; then
        SIGNED_MEAS=$(echo ${REQ_RSP} | jq -r '.SignedMeasurements')
        if [[ ! -z "${SIGNED_MEAS}" ]] && [[ "${SIGNED_MEAS}" != "null" ]]; then
            REQ_END=$(date +"%s.%3N")
            OUTPUT=${REQ_RSP}
            MEASUREMENT_DURATION=$(echo "${REQ_END}-${REQ_START}" | bc)
            REQUEST_DURATION=$(echo "${REQ_END}-${REQ_START}" | bc)
        fi
    fi
    local RESULT=""
    if [[ ! -z "${OUTPUT}" ]]; then
        local OUTPUT_FILENAME="meas-$(md5sum <<< $(date +"%s.%3N") | sed 's/[^[:alnum:]]//g').json"
        echo ${OUTPUT} | jq -S "." > ./measurementdata/${OUTPUT_FILENAME}
        RESULT=$(jq -nc \
            --arg Chassis "${CHASSIS}" \
            --argjson RequestParameters "${REQ_JSON}" \
            --arg RequestTimestamp "${REQ_START}" \
            --arg RequestDuration "${REQUEST_DURATION}" \
            --arg MeasurementDuration "${MEASUREMENT_DURATION}" \
            --arg Output "\"${OUTPUT_FILENAME}\"" \
            '$ARGS.named')
    elif [[ ! -z "${TASK_ID}" ]]; then
        RESULT=$(jq -nc \
            --arg Chassis "${CHASSIS}" \
            --argjson RequestParameters "${REQ_JSON}" \
            --arg RequestTimestamp "${REQ_START}" \
            --arg TaskID "${TASK_ID}" \
            '$ARGS.named')
    elif [[ ! -z "${REQ_RSP}" ]]; then
        RESULT=$(jq -nc \
            --arg Chassis "${CHASSIS}" \
            --argjson RequestParameters "${REQ_JSON}" \
            --arg RequestTimestamp "${REQ_START}" \
            --argjson Output "${REQ_RSP}" \
            '$ARGS.named')
    else
        RESULT=$(jq -nc \
            --arg Chassis "${CHASSIS}" \
            --argjson RequestParameters "${REQ_JSON}" \
            --arg RequestTimestamp "${REQ_START}" \
            --arg Output "Error - empty response" \
            '$ARGS.named')
    fi
    REQ_ARR+=("${RESULT}")
}

finalize_request() {
    local REQ=${REQ_ARR[${1}]}
    local TASK_ID=$(echo ${REQ} | jq -r '.TaskID')
    local TASK_RSP=""
    local TASK_STATE=""
    local OUTPUT=""
    if [[ ! -z "${TASK_ID}" ]] && [[ "${TASK_ID}" != "null" ]]; then
        TASK_RSP=$(curl -s http://${HMC}/redfish/v1/TaskService/Tasks/${TASK_ID})
        TASK_STATE=$(echo ${TASK_RSP} | jq -r '.TaskState')
    fi
    if [[ "${TASK_STATE}" == "Completed" ]]; then
        local REQ_START=$(echo ${REQ} | jq -r '.RequestTimestamp')
        local REQ_END=$(date +"%s.%3N")
        local REQUEST_DURATION=$(echo "${REQ_END}-${REQ_START}" | bc)
        local START_TIME=$(echo ${TASK_RSP} | jq -r '.StartTime' | sed 's/T/\ /g')
        local END_TIME=$(echo ${TASK_RSP} | jq -r '.EndTime'| sed 's/T/\ /g')
        local T1=$(date -d "${START_TIME}" +%s)
        local T2=$(date -d "${END_TIME}" +%s)
        local MEASUREMENT_DURATION=$(echo "${T2}-${T1}" | bc)
        local HTTP_HEADERS=$(echo ${TASK_RSP} | jq '[.Payload.HttpHeaders | to_entries[]]')
        local LOC_FIELD=$(echo ${HTTP_HEADERS} | jq -r '.[] | select(.value | contains("Location")) | .value')
        local LOC=${LOC_FIELD#"Location: "}
        if [[ ! -z "${LOC}" ]]; then
            OUTPUT=$(curl -s http://${HMC}${LOC})
        fi
        local OUTPUT_FILENAME="meas-$(md5sum <<< $(date +"%s.%3N") | sed 's/[^[:alnum:]]//g').json"
        echo ${OUTPUT} | jq -S "." > ./measurementdata/${OUTPUT_FILENAME}
        local RESULT=$(echo ${REQ} | jq ". += { RequestDuration:"${REQUEST_DURATION}", "MeasurementDuration":${MEASUREMENT_DURATION}, "Output":\"${OUTPUT_FILENAME}\" }")
        REQ_ARR[${1}]=${RESULT}
    elif [[ "${TASK_STATE}" != "Running" ]]; then
        if [[ ! -z "${TASK_RSP}" ]]; then
            local RESULT=$(echo ${REQ} | jq ". += {"Output": "${TASK_RSP}" }")
            REQ_ARR[${1}]=${RESULT}
        else
            local RESULT=$(echo ${REQ} | jq ". += {"Output": "Error - empty task response" }")
            REQ_ARR[${1}]=${RESULT}
        fi
    fi
}

mkdir -p measurementdata
if [[ ! -z "${PAR_JSON}" ]] && [[ -f "${PAR_JSON}" ]]; then
    START=$(date +"%s.%3N")
    readarray -t REQUESTS < <(jq -c '.[]' "${PAR_JSON}")
    for R in "${REQUESTS[@]}"; do
        process_request ${R}
    done
    FINISHED="false"
    while [[ ${FINISHED} == "false" ]]; do
        FINISHED="true"
        for i in "${!REQ_ARR[@]}"; do            
            READY=$(echo ${REQ_ARR[$i]} | jq -r 'has("Output")')
            if [[ ${READY} == "false" ]]; then
                finalize_request ${i}
                FINISHED="false"
            fi
        done
    done
    END=$(date +"%s.%3N")
    DURATION=$(echo "${END}-${START}" | bc)
    OUTPUT_ARRAY="["
    for R in "${REQ_ARR[@]}"; do
        OUTPUT_ARRAY="${OUTPUT_ARRAY}${R},"
    done
    OUTPUT_ARRAY=${OUTPUT_ARRAY%","}
    OUTPUT_ARRAY="${OUTPUT_ARRAY}]"
    echo $(jq -n \
        --arg Duration "${DURATION}" \
        --argjson Results "${OUTPUT_ARRAY}" \
        '$ARGS.named')
fi
