import json
import sys
import argparse
import re
import time
from bmc_connection import BMCConnection


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

# Determine mctp buses
def scan_mctp_buses(conn):
    buses = set()
    bus_mapping = { 0: 'pcie', 1: 'spi', 2: 'i2c' }
    processes = ['mctp-pcie-ctrl', 'mctp-spi-ctrl', 'mctp-ctrl']
    for img in processes:
        ret, _ = conn.execute_cmd(f"pgrep {img}")
        if ret==0:
            index = processes.index(img)
            buses.add(bus_mapping.get(index,'unknown'))
    # If i2c detected scan for busses
    if 'i2c' in buses:
        ret, files = conn.execute_cmd('ls /usr/share/mctp/mctp*.json')
        if ret==0:
            for fil in files.strip().split('\n'):
                ret, json_txt = conn.execute_cmd(f"cat {fil}")
                if ret==0:
                    jsons = json.loads(json_txt)
                    socket_names = [bus['socket_name'] for bus in jsons['i2c']['buses']]
                    i2c_nm = [re.search(r'mctp-(.*?)-mux', name).group(1) for name in socket_names if re.search(r'mctp-(.*?)-mux', name)]
                    buses.update(i2c_nm)
    buses.discard('i2c')
    return buses

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
    for attempt in range(3):
        ret, content = conn.execute_cmd(cmdline)
        if ret == 0:
            jsons = json.loads(content)
            return jsons
        elif attempt < 2:
            time.sleep(1)
            continue
        raise SpdmExecError(f"Unable to execute cmds {cmdline}: {content}")

# Enumerate available endpoints
def enumerate_spdm_endpoints(conn, buses):
    endpoints = {}
    for bus in buses:
        jsons = spdmt_cmd_exec(conn, bus, '--enumerate')
        if jsons:
            endpoints[bus] = jsons.get('Endpoints',[])
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

# Load all measurements data
def load_measurements(conn, endpoints):
    ret = {}
    for bus, eps in endpoints.items():
        eids_data = []
        for ep in eps:
            eid = ep['EID']
            jsons = spdmt_cmd_exec(conn, bus, f"--eid {eid} get-meas --block-index 255")
            eids_data.append((eid,jsons))
        ret[bus] = eids_data
    return ret

# Compare SPDM versions in resp
def verify_spdm_version(conf, meas):
    errors = []
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
            else:
                errors.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckVersion' ,
                                'error' : 'Cmd not executed', 'val': None} )
    return errors

# Compare capabilities
def verify_spdm_capabilities(conf, meas):
    errors = []
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
                errors.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckCapabilities' ,
                                'error' : 'Cmd not executed', 'val': None} )
    return errors


# Compare algorithms
def verify_spdm_algo(conf, meas):
    errors = []
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
            else:
                errors.append( { 'bus': bus, 'endpoint': ep_num, 'reason' : 'CheckAlgorithms' ,
                                'error' : 'Cmd not executed', 'val': None} )
    return errors

# Compare uuid and eid data
def verify_spdm_uuid_and_eid(conf, eps):
    matching_uuid = {}
    errors = []
    for bus_type, eps1 in eps.items():
        for ep1 in eps1:
            eid1 = ep1['EID']
            uuid1 = ep1['UUID']
            buses1 = set([bus_type])
            for erots in conf['erots']:
                buses2 = set(erots.get('buses', []))
                if buses1.intersection(buses2) and eid1 == erots['eid'] and uuid1 == erots['uuid']:
                    matching_uuid.setdefault(bus_type, {})[eid1] = erots['uuid']
                    break
    for erot in conf['erots']:
        eid = erot['eid']
        uuid = erot['uuid']
        buses = erot['buses']
        for bus in buses:
            match_bus = matching_uuid.get(bus)
            if not match_bus:
                errors.append( { 'bus': bus, 'endpoint': eid, 'reason' : 'VerifyUUID' ,
                    'error' : 'UUID not match to the bus', 'val': uuid} )
            else:
                match_uuid = match_bus.get(eid)
                if not match_uuid:
                    errors.append( { 'bus': bus, 'endpoint': eid, 'reason' : 'VerifyUUID' ,
                        'error' : 'UUID not match to the eid', 'val': uuid} )
                elif match_uuid != uuid:
                    errors.append( { 'bus': bus, 'endpoint': eid, 'reason' : 'VerifyUUID' ,
                        'error' : 'UUID not match to the uuid', 'val': match_uuid} )
    return errors

# Check if index with measurements data exists
def meas_index_with_data_exists(data, search_idx):
    for idx, didx in data:
        if idx == search_idx and didx:
            return True
    return False


# Compare measurements data
def verify_spdm_measurements_serial_and_debug_token(conf, meas):
    erots = conf['erots']
    match_meas = []
    for bus_type, eps in meas.items():
        buses1 = set([bus_type])
        for ep_num, data in eps:
            for erot in erots:
                buses2 = set(erot.get('buses',[]))
                if buses1.intersection(buses2) and ep_num == erot['eid']:
                    meas = data.get('GetMeasurement')
                    if meas:
                        match_meas.append((bus_type, ep_num, meas))
                    break
    errors = []
    for bus, ep, meas in match_meas:
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
         # Check for debug token
        if not meas_index_with_data_exists(mdata, 50):
            errors.append( { 'bus': bus, 'endpoint': ep, 'reason' : 'DebugToken' ,
                'error' : 'Debug token', 'val': str(mdata)} )
        # Compare with required data
        req_data = [erot for erot in erots if erot["eid"] == ep][0]
        if ("measurements" in req_data) and (mdata != req_data["measurements"]):
            errors.append( { 'bus': bus, 'endpoint': ep, 'reason' : 'CheckMeasurements' ,
                'error' : 'Measurements data invalid', 'val': str(mdata)} )
    need_eids = [(bus, entry["eid"]) for entry in erots for bus in entry["buses"]]
    result_set = set((item[0], item[1]) for item in need_eids)
    check_set = set((item[0], item[1]) for item in match_meas)
    missing_eids = result_set - check_set
    if missing_eids:
        for bus, ep in missing_eids:
            errors.append( { 'bus': bus, 'endpoint': ep, 'reason' : 'CheckMeasurements' ,
                'error' : 'ERoT does not exists', 'val': ''} )
    return errors

# Compare SPDM certificates num
def verify_spdm_certs(certs):
    errors = []
    for slot, data in certs:
        for bus, buscrts in data.items():
            for eid, num_crts in buscrts:
                if num_crts < 1:
                    errors.append( { 'bus': bus, 'endpoint': eid, 'reason' : 'CheckCerts' ,
                        'error' : 'Invalid number of certs', 'val': str(num_crts)} )
    return errors

# Show compliance tool results
def show_compliance_tool_report(errors):
    if not errors:
        print('Compliance tool: PASSED')
    else:
        print('Compliance tool: FAILED')
    for err in errors:
        print(f"Error: {str(err)}")

# Main function
if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser("SPDM compliance tool")
    parser.add_argument('--netconf', help="Network topology config file", required=True)
    parser.add_argument('--conf', help="Configuration file", required=True)
    args = parser.parse_args()
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

    try:
        # Preconfigure
        print('Preconfiguring target ...')
        system_preconfigure(conn)

        # Getting data from the system
        print('Scanning buses ...')
        buses = scan_mctp_buses(conn)
        print('Enumerating endpoints ...')
        eps = enumerate_spdm_endpoints(conn, buses)
        print('Loading measurements ...')
        meas = load_measurements(conn, eps)
        print('Loading certificates ...')
        certs = load_certificates_numbers(conn, eps, conf)

        # Postconfigure and close connection
        print('Restoring target configuration ...')
        system_postconfigure(conn)
        print('Disconnecting from target ...')
        conn.disconnect()
    except Exception as e:
        print(f"Collecting target data failed: {str(e)}")
        sys.exit(-1)

    try:
        # Compare the results
        errs = []
        err = verify_spdm_certs(certs)
        errs += err
        err = verify_spdm_version(conf, meas)
        errs += err
        err = verify_spdm_capabilities(conf, meas)
        errs += err
        err = verify_spdm_algo(conf, meas)
        errs += err
        err = verify_spdm_measurements_serial_and_debug_token(conf, meas)
        errs += err
        err = verify_spdm_uuid_and_eid(conf, eps)
        errs += err
        show_compliance_tool_report(errs)
    except Exception as e:
        print(f"Compare results failed {str(e)}")
        sys.exit(-1)