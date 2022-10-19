#!/bin/bash

get_time() {
    cat /proc/uptime | cut -d ' ' -f 1
}

get_random() {
    echo $(openssl rand -hex ${1})
}

get_value() {
    echo ${1} | sed 's/[{\":,}]//g' | awk -F ${2} '{print $2}' | cut -d ' ' -f 2
}
