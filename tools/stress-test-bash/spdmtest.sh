#!/bin/bash

source _utils.sh

PAR_FILE=${1}
OUTPUT_DIR=${2}
HMC=${3:-localhost:3080}

if [[ -z "${OUTPUT_DIR}" ]]; then
    OUTPUT_DIR="output-$(get_random 8)"
fi
mkdir -p ${OUTPUT_DIR}
mkdir -p ${OUTPUT_DIR}/measurementdata

if [[ ! -z "${PAR_FILE}" ]] && [[ -f "${PAR_FILE}" ]]; then
    START=$(get_time)
    while read R; do
        CHASSIS=$(echo ${R} | cut -d ';' -f 1)
        INDICES=$(echo ${R} | cut -d ';' -f 2)
        NONCE=$(echo ${R} | cut -d ';' -f 3)
        SLOT_ID=$(echo ${R} | cut -d ';' -f 4)
        REQ="{"
        if [[ ! -z "${INDICES}" ]]; then
            REQ=${REQ}'"MeasurementIndices":['${INDICES}'],'
        fi
        if [[ ! -z "${NONCE}" ]]; then
            REQ=${REQ}'"Nonce:'"${NONCE}"','
        fi
        if [[ ! -z "${SLOT_ID}" ]]; then
            REQ=${REQ}'"SlotId:'"${SLOT_ID}"','
        fi
        REQ=$(echo ${REQ} | sed 's/\(.*\),/\1/')
        REQ=${REQ}"}"
        /bin/bash _sendrequest.sh ${HMC} ${CHASSIS} ${REQ} ${OUTPUT_DIR}/results-${CHASSIS}.csv ${OUTPUT_DIR}/measurementdata &
    done <${PAR_FILE}
    FINISHED="false"
    while [[ ${FINISHED} == "false" ]] && [[ $(echo "$(get_time) - ${START} < 60" | bc -l) ]]; do
        FINISHED="true"
        while read R; do
            CHASSIS=$(echo ${R} | cut -d ';' -f 1)
            if [[ ! -f ${OUTPUT_DIR}/results-${CHASSIS}.csv ]]; then
                FINISHED="false"
            fi
        done <${PAR_FILE}
        sleep 0.1
    done
    for FILE in ${OUTPUT_DIR}/results-*.csv; do
        cat ${FILE} >> ${OUTPUT_DIR}/results.csv
        rm ${FILE}
    done
    echo ${OUTPUT_DIR}/results.csv
fi
