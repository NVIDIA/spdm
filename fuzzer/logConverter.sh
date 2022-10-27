#!/bin/bash
grep -e "^.*ResponseBuffer =*" ${1} | sed 's/^.*ResponseBuffer = //' > ${1}.hex

