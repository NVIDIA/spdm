# SPDM compliance tool
#
# Verbose levels:
#  0 - print only errors
#  1 - print also successes
#  2 - command messages
#  3 - debug messages
#  4 - trace messages

import json
import sys
import argparse
import re
import time
import traceback
from bmc_connection import BMCConnection

verbose_level = 0

# SPDM tool exec error class
class SpdmExecError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


# Load configuration file
def load_config(config_path, section):
    try:
        with open(config_path, 'r') as file:
            config = json.load(file)[section]
    except Exception as e:
        print(f"Unable to load config: {str(e)}")
        sys.exit(-1)
    return config


# Preconfigure system for test
def system_preconfigure(conn):
    ret, out = conn.execute_cmd('pgrep spdmd')
    if ret==0:
        ret, _ = conn.execute_cmd('systemctl stop spdmd')
        if ret!=0:
            ret, out = conn.execute_cmd('killall spdmd')
            if ret!=0:
                raise SpdmExecError(f"Unable to execute command: {out}")

# System restore stopped services
def system_postconfigure(conn):
    ret, out  = conn.execute_cmd('systemctl start spdmd')
    if ret!=0:
        raise SpdmExecError(f"Unable to start spdmd: {out}")



# Helper function for start spdmtool on particular ifc
def spdmt_cmd_exec(conn, bus, astr):
    match = re.search(r'(.*?)(\d+)$', bus)
    if match:
        bus_id = match.group(1)
        bus_no = match.group(2)
        cmdline = f"spdmtool --interface {bus_id} --bus {bus_no} "
    else:
        cmdline = f"spdmtool --interface {bus} "
    cmdline += astr
    if (verbose_level >= 2):
        print(f"Executing command: {cmdline}")
    for attempt in range(3):
        ret, content = conn.execute_cmd(cmdline)
        if (verbose_level >= 2):
            print(f"The command ret value: {str(ret)}")
        if (verbose_level >= 3):
#            formatted_json = json.dumps(content, indent=4, separators=(",", ": "), ensure_ascii=False)
            print(f"The command ret content: {str(content)}")
        if ret == 0:
            jsons = json.loads(content)
            return jsons
        elif (ret == 1):
            if (verbose_level >= 2):
                print(f"Error on getting command response: {content}")
            return {}
        elif attempt < 2:
            time.sleep(1)
            continue
        raise SpdmExecError(f"Unable to execute cmds {cmdline}: {content}")
    return {}

# Enumerate available endpoints
def enumerate_spdm_endpoints(conn, buses):
    endpoints = {}
    for bus in buses:
        jsons = spdmt_cmd_exec(conn, bus, '--enumerate')
        if jsons != {}:
            endpoints[bus] = jsons.get('Endpoints',[])
            if (verbose_level >= 3):
                formatted_json = json.dumps(endpoints, indent=4, separators=(",", ": "), ensure_ascii=False)
                print(f"Found endpoints on bus {bus}: {str(formatted_json)}")
    return endpoints

# certificate chain numbers
def load_certificate_numbers_from_slots(conn, endpoints, slot):
    CERT_HDR = '-----BEGIN CERTIFICATE-----'
    ret = {}
    for bus, eps in endpoints.items():
        eid_certs = []
        for ep in eps:
            eid = ep['EID']
            jsons = spdmt_cmd_exec(conn, bus, f"--eid {eid} get-cert --slot {slot}")
            if jsons != {}:
                cert = jsons.get('GetCertificate',[])
                rs = cert.get('ResponseCode')
                chain = cert.get('CertChain',[])
                rslot = cert.get('Slot')
                if rs != 'RetStat::OK':
                    ncerts = 0
                elif rslot != slot:
                    ncerts = 0
                else:
                    ncerts = chain.count(CERT_HDR)
                eid_certs.append((eid, ncerts))
            else:
                eid_certs.append((eid, 0))
        ret[bus] = eid_certs
    return ret

# Load certificates from the slot
def load_certificates_numbers(conn, endpoints, conf):
    slots = conf['certs']['slots']
    ret = []
    for slot in slots:
        cert = load_certificate_numbers_from_slots(conn, endpoints, slot)
        ret.append( (slot, cert))
    return ret


# Find slot with cert
def find_slot_with_certs(certs, eid, bus):
    for slot, data in certs:
        for port, num_certs in data[bus]:
            if port == eid:
                if num_certs > 0:
                    return slot
    return None

# Load all measurements data
def load_measurements(conn, endpoints, certs):
    ret = {}
    for bus, eps in endpoints.items():
        eids_data = []
        for ep in eps:
            eid = ep['EID']
            jsons = {}
            try:
                slot = find_slot_with_certs(certs, eid, bus)
                if slot is None:
                    continue
                jsons = spdmt_cmd_exec(conn, bus, f"--eid {eid} get-cert --slot {slot} get-meas --block-index 255")
                if jsons == {}:
                    jsons = spdmt_cmd_exec(conn, bus, f"--eid {eid} get-cert --slot {slot}")
                if (verbose_level >= 2):
                    print(f"Collecting measurements for eid={eid}, bus={bus} -> succeded")
                if (verbose_level >= 3):
                    formatted_json = json.dumps(jsons, indent=4, separators=(",", ": "), ensure_ascii=False)
                    print(f"{str(formatted_json)}")
            except Exception as e:
                print(f"Collecting measurements for eid={eid}, bus={bus} -> failed: {str(e)}")
            if jsons != {}:
                eids_data.append((eid,jsons))
        ret[bus] = eids_data
    return ret

# Compare SPDM versions in resp
def verify_spdm_version(conf, meas):
    errors = []
    report = []
    ver_req = conf['version']
    for bus, eps in meas.items():
        for ep_num, data in eps:
            verstc = data.get('GetVersion')
            if verstc:
                ver = verstc.get('SPDMVersion',[])
                rc =  verstc.get('ResponseCode')
                if rc != 'RetStat::OK':
                    errors.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckVersion' ,
                                    'error' : 'Invalid response code', 'val': rc} )
                    continue
                if ver and (ver_req not in ver):
                    errors.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckVersion' ,
                                    'error' : 'Value not match', 'val': ", ".join(ver)} )
                report.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckVersion' ,
                                    'status' : 'Success', 'val': rc, 'Versions' : ver} )
                print()
            else:
                errors.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckVersion' ,
                                'error' : 'Cmd not executed', 'val': None} )
    if (verbose_level >= 4):
        for log in report:
            formatted_json = json.dumps(log, indent=4, separators=(",", ": "), ensure_ascii=False)
            print(f"{str(formatted_json)}")
    return errors, report

# Compare capabilities
def verify_spdm_capabilities(conf, meas):
    errors = []
    report = []
    cap_req = conf['capabilities']
    for bus, eps in meas.items():
        for ep_num, data in eps:
            cap_resp = data.get('GetCapabilities')
            if cap_resp:
                rc =  cap_resp.get('ResponseCode')
                cap = cap_resp.get('Capabilities')
                if rc != 'RetStat::OK':
                    errors.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckCapabilities' ,
                                    'error' : 'Invalid response code', 'val': rc} )
                    continue
                if cap and (set(cap_req) != set(cap)):
                    errors.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckCapabilities' ,
                                    'error' : 'Value not match', 'val': ', '.join(cap)} )
                else:
                    report.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckCapabilities' ,
                                    'status' : 'Success', 'val': rc, 'cap' : cap} )
            else:
                errors.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckCapabilities' ,
                                'error' : 'Cmd not executed', 'val': None} )
    if (verbose_level >= 4):
        for log in report:
            formatted_json = json.dumps(log, indent=4, separators=(",", ": "), ensure_ascii=False)
            print(f"{str(formatted_json)}")
    return errors, report


# Compare algorithms
def verify_spdm_algo(conf, meas):
    errors = []
    report = []
    halgo_req = conf['hash_algo']
    salgo_req = conf['signature_algo']
    for bus, eps in meas.items():
        for ep_num, data in eps:
            algo_resp = data.get('NegotiateAlgorithms')
            if algo_resp:
                rc =  algo_resp.get('ResponseCode')
                halgo = algo_resp.get('HashingAlgorithm')
                if not isinstance(halgo, list):
                    halgo = [ halgo ]
                salgo = algo_resp.get('SignatureAlgorithm')
                if not isinstance(salgo, list):
                    salgo = [ salgo ]
                if rc != 'RetStat::OK':
                    errors.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckAlgorithms' ,
                                    'error' : 'Invalid response code', 'val': rc} )
                    continue
                if halgo and (set(halgo_req) != set(halgo)):
                    errors.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckAlgorithms' ,
                                    'error' : 'Hashing algorithms not match', 'val': ', '.join(halgo)} )
                if salgo and (set(salgo_req) != set(salgo)):
                    errors.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckAlgorithms' ,
                                    'error' : 'Signature algorithms not match', 'val': ', '.join(salgo)} )
                report.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckAlgorithms' ,
                                    'status' : 'Success', 'val': rc, 'HashingAlgo' : halgo, 'SignatureAlgo' : salgo} )
            else:
                errors.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckAlgorithms' ,
                                'error' : 'Cmd not executed', 'val': None} )
    if (verbose_level >= 4):
        for log in report:
            formatted_json = json.dumps(log, indent=4, separators=(",", ": "), ensure_ascii=False)
            print(f"{str(formatted_json)}")
    return errors, report



# Check if index with measurements data exists
def meas_index_with_data_exists(data, search_idx):
    for idx, didx in data:
        if idx == search_idx and didx:
            return True
    return False


# Compare measurements data
def verify_spdm_measurements_serial_and_debug_token(certs, meas):
    match_meas = []
    report = []
    max_certs = {}
    for _, cert_info in certs:
        for data_type, ports in cert_info.items():
            if data_type not in max_certs:
                max_certs[data_type] = {}
            for port, value in ports:
                if port in max_certs[data_type]:
                    max_certs[data_type][port] = max(max_certs[data_type][port], value)
                else:
                    max_certs[data_type][port] = value

    final_certs = {data_type: [(port, value) for port, value in ports.items()] for data_type, ports in max_certs.items()}
    for bus, certs in final_certs.items():
        for idx, ncerts in certs:
            if ncerts > 0:
                mbus = meas.get(bus)
                for lidx, lmeas in mbus:
                    if lidx == idx:
                        xmeas = lmeas.get('GetMeasurement')
                        match_meas.append((bus, idx, xmeas))

    errors = []
    for bus, ep, meas in match_meas:
        if not meas:
            continue
        rc =  meas.get('ResponseCode')
        if rc != 'RetStat::OK':
            errors.append( { 'bus': bus, 'endpoint': ep, 'reason' : 'CheckMeasurements' ,
                    'error' : 'invalid response code', 'val': rc} )
            continue
        mdata = meas.get('MeasurementData')
        # Check for serial number
        if not meas_index_with_data_exists(mdata, 26):
            errors.append( { 'bus': bus, 'endpoint': ep, 'reason' : 'CheckSerial' ,
                'error' : 'Missing serial number', 'val': str(mdata)} )
        else:
            report.append( { 'bus': bus, 'endpoint': ep, 'reason' : 'CheckSerial',
                                    'status' : 'Success', 'val': rc} )
         # Check for debug token
        if not meas_index_with_data_exists(mdata, 50):
            errors.append( { 'bus': bus, 'endpoint': ep, 'reason' : 'DebugToken' ,
                'error' : 'Debug token', 'val': str(mdata)} )
        else:
            report.append( { 'bus': bus, 'endpoint': ep, 'reason' : 'DebugToken',
                                    'status' : 'Success', 'val': rc} )
        # Compare with required data
    if (verbose_level >= 4):
        for log in report:
            formatted_json = json.dumps(log, indent=4, separators=(",", ": "), ensure_ascii=False)
            print(f"{str(formatted_json)}")
    return errors, report

# Compare SPDM certificates num
def verify_spdm_certs(certs):
    errors = []
    report = []
    for slot, data in certs:
        for bus, buscrts in data.items():
            for eid, num_crts in buscrts:
                if num_crts < 1:
                    errors.append( { 'bus': bus, 'endpoint': eid, 'reason' : 'CheckCerts' ,
                        'error' : 'Invalid number of certs', 'val': f"{num_crts} slot {slot}"} )
                else:
                    report.append( { 'bus': bus, 'endpoint': eid, 'reason' : 'CheckCerts' ,
                        'status' : 'Success', 'Certificates': str(num_crts), 'Slot' : str(slot)} )
    if (verbose_level >= 4):
        for log in report:
            formatted_json = json.dumps(log, indent=4, separators=(",", ": "), ensure_ascii=False)
            print(f"{str(formatted_json)}")
    return errors, report

# Show compliance tool results
def show_compliance_tool_report(errors, reports):
    if not errors:
        print('Compliance tool: PASSED')
    else:
        print('Compliance tool: FAILED')
    print('FULL REPORT')
    # all together by eid
    if (verbose_level >= 1):
        all_msgs = errors + reports
    else:
        all_msgs = errors

    sorted_by_endpoint = {}
    for msg in all_msgs:
        endpoint = msg['endpoint']
        if endpoint not in sorted_by_endpoint:
            sorted_by_endpoint[endpoint] = []
        sorted_by_endpoint[endpoint].append(msg)

    for endpoint, msgs in sorted_by_endpoint.items():
        print(f'Endpoint: {endpoint}')
        #sorted_msgs = sorted(msgs, key=lambda x: x['reason'], reverse=False)
        for msg in msgs:
            if 'error' in msg:
                print(f"\tError  : {str(msg)}")
            else:
                print(f"\tSuccess: {str(msg)}")

# Main function
if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser("SPDM compliance tool")
    parser.add_argument('--netconf', help="Network topology config file", required=True)
    parser.add_argument('--conf', help="Configuration file", required=True)
    parser.add_argument('--verbose', help="Debug verbose level (0..2)", required=False, default=1)
    parser.add_argument('--start-spdm', help="Start SPDM daemon only", action='store_true')
    args = parser.parse_args()

    verbose_level = int(args.verbose)
    if (verbose_level >= 1):
        print(f"Verbose level: {verbose_level}")
    netconf = load_config(args.netconf, 'network')
    conf = load_config(args.conf, 'compliance')

    # Connect to the target host
    try:
        conn = BMCConnection(netconf)
        print(f"Connecting to target {str(conn)} ...")
        conn.connect()
    except Exception as e:
        print(f"Unable to connect: {str(e)}")
        sys.exit(-1)

    # Start spdm only and don't perform a tests
    if args.start_spdm:
        print('Starting spdm ...')
        system_postconfigure(conn)
        sys.exit(0)

    try:
        # Preconfigure
        print('Preconfiguring target ...')
        system_preconfigure(conn)

        # Getting data from the system
        if "bus" in conf:
            buses = [ conf.get("bus") ]
            print(f'Tool run on bus {buses[0]}')
        else:
            print('Bus for scan is not specified ...')
            exit(-1)
        print('Enumerating endpoints ...')
        eps = enumerate_spdm_endpoints(conn, buses)

        print('Loading certificates ...')
        certs = load_certificates_numbers(conn, eps, conf)

        print('Loading measurements ...')
        meas = load_measurements(conn, eps, certs)
                # Postconfigure and close connection
        print('Restoring target configuration ...')
        system_postconfigure(conn)
        print('Disconnecting from target ...')
        conn.disconnect()
    except Exception as e:
        print(f"Collecting target data failed: {str(e)}")
        # Get the stack trace as a string
        stack_trace = traceback.format_exc()
        print("Stack trace:")
        print(stack_trace)
        sys.exit(-1)

    try:
        # Compare the results
        errs = []
        reports = []
        err, rep = verify_spdm_version(conf, meas)
        errs += err
        reports += rep
        err, rep = verify_spdm_capabilities(conf, meas)
        errs += err
        reports += rep
        err, rep = verify_spdm_algo(conf, meas)
        errs += err
        reports += rep
        err, rep = verify_spdm_certs(certs)
        errs += err
        reports += rep
        err, rep = verify_spdm_measurements_serial_and_debug_token(certs, meas)
        errs += err
        reports += rep
        show_compliance_tool_report(errs, reports)
    except Exception as e:
        print(f"Compare results failed {str(e)}")
        # Get the stack trace as a string
        stack_trace = traceback.format_exc()
        print("Stack trace:")
        print(stack_trace)
        sys.exit(-1)