#!/bin/bash

source _utils.sh

REQUEST_FOLDER=${1:-requests}
ITERATIONS=${2:-1}
HMC_HOST=${3:-192.168.31.1}
HMC_HTTP_PORT=${4:-80}
HMC_SSH_PORT=${5:-22}

CPU_LOAD="top -bn1 | sed -n '2{p;q}' | cut -d% -f1 | sed 's/[^.0-9]//g'"

OUTPUT_DIR=output-$(date "+%F-%H-%M-%S")
rm -rf ${OUTPUT_DIR}
mkdir -p ${OUTPUT_DIR}

for FILE in ./${REQUEST_FOLDER}/*.csv; do
    FULLNAME=$(basename -- "${FILE}")
    NAME="${FULLNAME%.*}"
    mkdir -p ${OUTPUT_DIR}/${NAME}
    ITER=1
    while [ ${ITER} -le ${ITERATIONS} ]; do
        mkdir -p ${OUTPUT_DIR}/${NAME}/${ITER}
        echo "${FILE} - iteration ${ITER}"
        CPU_LOAD_START=$(ssh -p ${HMC_SSH_PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@${HMC_HOST} ${CPU_LOAD} 2>/dev/null)
        START_TIME=$(get_time)
        RESULT=$(/bin/bash spdmtest.sh ${FILE} ${OUTPUT_DIR}/${NAME}/${ITER} ${HMC_HOST}:${HMC_HTTP_PORT})
        END_TIME=$(get_time)
        CPU_LOAD_END=$(ssh -p ${HMC_SSH_PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@${HMC_HOST} ${CPU_LOAD} 2>/dev/null)
        echo "${START_TIME};${END_TIME};${CPU_LOAD_START};${CPU_LOAD_END}" >> ${RESULT}
        ITER=$(( ITER + 1 ))
    done
done
tar czf ${OUTPUT_DIR}.tar.gz ${OUTPUT_DIR}
echo ${OUTPUT_DIR}.tar.gz
