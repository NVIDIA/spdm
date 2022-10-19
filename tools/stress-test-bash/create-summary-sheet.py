#!/usr/bin/python3

import csv
import json
import sys
from dateutil import parser as dateparser
from pathlib import Path, PurePath
from xlsxwriter.workbook import Workbook

def gen_ranges(lst):
    s = e = None
    for i in sorted(lst):
        if s is None:
            s = e = i
        elif i == e or i == e + 1:
            e = i
        else:
            yield (s, e)
            s = e = i
    if s is not None:
        yield (s, e)

def json_to_csv(json_path):
    with open(json_path) as json_file:
        global_indices = None
        erot_durations = dict()
        global_durations = []
        j = json.load(json_file)
        iteration_count = j["Iterations"]
        iterations = j["IterationsResults"]
        if len(j["IterationsResults"]) == iteration_count:
            for i in iterations:
                global_durations.append(float(i["Duration"]))
                results = i["Results"]
                for r in results:
                    chassis = r["Chassis"]
                    duration = float(r["RequestDuration"])
                    indices = r["RequestParameters"]["MeasurementIndices"]
                    if global_indices is None:
                        global_indices = indices
                    elif indices != global_indices:
                        print("Indices mismatch!")
                    if chassis not in erot_durations:
                        erot_durations[chassis] = []
                    erot_durations[chassis].append(duration)

    csv_path = str(json_path.parent) + '/' + str(json_path.stem) + '.csv'
    with open(csv_path, 'w') as csv_file:
        csv_file.write("Collect SPDM measurement data for following ERoTs parallely;")
        csv_file.write('%s' % ', '.join(['%d' % s if s == e else '%d-%d' % (s, e) for (s, e) in gen_ranges(global_indices)]) + ";")
        csv_file.write(str(iteration_count) + ";")
        csv_file.write(";;;\n")
        for chassis, durations in erot_durations.items():
            csv_file.write(chassis.removeprefix("HGX_ERoT_").replace('_', ' ') + ";;")
            csv_file.write('%s' % ', '.join(map(str, durations)) + ";")
            csv_file.write(str(max(durations)) + ";")
            csv_file.write(str(min(durations)) + ";")
            avg = format(sum(durations) / len(durations), '.3f')
            csv_file.write(str(avg))
            csv_file.write("\n")
        csv_file.write(";;;;;\n")
        csv_file.write("Total;;")
        csv_file.write('%s' % ', '.join(map(str, global_durations)) + ";")
        csv_file.write(str(max(global_durations)) + ";")
        csv_file.write(str(min(global_durations)) + ";")
        avg = format(sum(global_durations) / len(global_durations), '.3f')
        csv_file.write(str(avg))
        csv_file.write("\n")
    return csv_path


def process_directory(dir_path):
    csv_paths = []
    aggregate_json = dir_path / Path(PurePath(dir_path).name + '.json')
    have_json = aggregate_json.exists()
    if have_json:
        output = json_to_csv(aggregate_json)
        csv_paths.append(output)
    for x in dir_path.iterdir():
        if x.is_dir():
            csv_paths += process_directory(x)
    return csv_paths


if len(sys.argv) < 2 or not Path(sys.argv[1]).is_dir():
    print("Usage: create-summary-sheet.py <path-to-results-directory>")
    exit(1)

dir = Path(sys.argv[1])
csv_paths = sorted(process_directory(dir))
xlsx_path = dir / "result.xlsx"
workbook = Workbook(xlsx_path)
cell_format = workbook.add_format()
cell_format.set_text_wrap()
worksheet = workbook.add_worksheet()
row_number = 0
worksheet.write(row_number, 0, 'Test description')
worksheet.write(row_number, 1, 'Requested indices')
worksheet.write(row_number, 2, 'Iterations')
worksheet.write(row_number, 3, 'Max')
worksheet.write(row_number, 4, 'Min')
worksheet.write(row_number, 5, 'Average')
for f in csv_paths:
    with open(f, 'r') as f:
        reader = csv.reader(f, delimiter=';')
        for r, row in enumerate(reader):
            row_number += 1
            for c, col in enumerate(row):
                worksheet.write(row_number, c, col)
    row_number += 1
workbook.close()
