#!/usr/bin/python3

import csv
import json
import sys
from dateutil import parser as dateparser
from pathlib import Path


def get_min_timestamp(json):
    try:
        timestamps = []
        results = json["Results"]
        for r in results:
            timestamps.append(float(r["RequestTimestamp"]))
        return int(min(timestamps))
    except KeyError:
        return 0


def aggregate_iterations(json_paths):
    j = {}
    iterationResults = []
    cpuLoadsStart = []
    cpuLoadsEnd = []
    durations = []
    timestamps = []
    for path in json_paths:
        with open(path) as f:
            iter = json.load(f)
            cpuLoadsStart.append(iter['CPULoadStart'])
            cpuLoadsEnd.append(iter['CPULoadEnd'])
            durations.append(iter['Duration'])
            for request in iter['Results']:
                timestamps.append(request['RequestTimestamp'])
            iterationResults.append(iter)
    if len(cpuLoadsStart) != len(cpuLoadsEnd) or len(cpuLoadsStart) != len(durations):
        print("Data lengths mismatch for: " + str(json_paths[0].parent))
        return
    j['StartTimestamp'] = min(timestamps)
    j['Iterations'] = len(json_paths)
    j['AvgCPULoadStart'] = format(sum([float(x) for x in cpuLoadsStart]) / float(len(cpuLoadsStart)), '.2f')
    j['AvgCPULoadEnd'] = format(sum([float(x) for x in cpuLoadsEnd]) / float(len(cpuLoadsEnd)), '.2f')
    j['AvgDuration'] = format(sum([float(x) for x in durations]) / float(len(durations)), '.3f')
    j['IterationsResults'] = sorted(iterationResults, key=get_min_timestamp)
    json_file = str(json_paths[0].parent.parent) + '/' + str(json_paths[0].parent.parent.stem) + '.json'
    with open(json_file, 'w') as f:
        json.dump(j, f, indent=4)


def csv_to_json(csv_path):
    data = []
    with open(csv_path) as csvfile:
        reader = csv.reader(csvfile, delimiter=';')
        for row in reader:
            if row:
                data.append(row)
    last = data[-1]
    del data[-1]
    if len(last) != 4:
        print("Invalid csv file (last line should have 4 elements): " + csv_path)
        return
    j = {}
    j['Duration'] = format(float(last[1]) - float(last[0]), '.3f')
    j['CPULoadStart'] = last[2]
    j['CPULoadEnd'] = last[3]
    j['Results'] = []
    for d in data:
        if len(d) != 7:
            print("Invalid csv file (result line should have 7 elements, has " + str(len(data)) +"): " + str(csv_path))
            return
        r = {}
        r['Chassis'] = d[0]
        r['RequestParameters'] = json.loads(d[1])
        r['RequestTimestamp'] = d[2]
        r['RequestDuration'] = format(float(d[3]) - float(d[2]), '.3f')
        r['Output'] = d[4]
        try:
            meas_duration = dateparser.parse(d[6]) - dateparser.parse(d[5])
            r['MeasurementDuration'] = format(meas_duration.total_seconds(), '.3f')
        except:
            r['MeasurementDuration'] = 0.000
            print("Measurement duration exception (error) for " + str(csv_path) + ": " + str(d))            
        j['Results'].append(r)
    json_file = str(csv_path.parent) + '/' + str(csv_path.stem) + '.json'
    with open(json_file, 'w') as f:
        json.dump(j, f, indent=4)


def process_directory(dir_path):
    results_csv = dir_path / Path('results.csv')
    have_results = results_csv.exists()
    if have_results:
        csv_to_json(results_csv)
        return have_results
    all_children_have_results = True
    for x in dir_path.iterdir():
        if x.is_dir():
            if process_directory(x) is False:
                all_children_have_results = False
    if all_children_have_results is True:
        iteration_jsons = []
        for x in dir_path.iterdir():
            results_json = x / Path('results.json')
            if results_json.exists():
                iteration_jsons.append(results_json)
        aggregate_iterations(iteration_jsons)
    return False


if len(sys.argv) < 2 or not Path(sys.argv[1]).is_dir():
    print("Usage: process-results.py <path-to-results-directory>")
    exit(1)

dir = Path(sys.argv[1])
process_directory(dir)
