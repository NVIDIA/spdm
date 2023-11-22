import paramiko
from paramiko_jump import SSHJumpClient

class BMCConnectionError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


#BMC connection device class
class BMCConnection:
    def __init__(self, config, debug=False):
        self.circuit = []
        self.debug = debug
        self.ses = None
        if not isinstance(config, dict):
            raise BMCConnectionError('Invalid connection configuration data')
        # Build the connection list
        self.hosts_list = config.get('jump_hosts', [])
        bmc_host = config.get('bmc')
        if bmc_host:
            self.hosts_list.append(bmc_host)
        hmc_host = config['hmc']
        self.hosts_list.append(hmc_host)
        self.tgt_hostname = f"{bmc_host['host']}:{bmc_host['port']}" if bmc_host else f"{hmc_host['host']}:{hmc_host['port']}"

    # To string conversion operator
    def __str__(self):
        return self.tgt_hostname

    # Connect to the host
    def connect(self):
        phop = None
        # Connect to the circuit
        for jump_host in self.hosts_list:
            if self.debug:
                print(f"Connecting to {jump_host['host']}:{jump_host['port']}...")
            if phop:
                hop = SSHJumpClient(jump_session=phop)
            else:
                hop = SSHJumpClient()
            hop.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if 'password' in jump_host:
                hop.connect(hostname=jump_host['host'], username=jump_host['username'],
                        port=jump_host['port'], password=jump_host['password'])
            else:
                hop.connect(hostname=jump_host['host'], username=jump_host['username'],
                    port=jump_host['port'])
            phop = hop
            self.circuit.append(hop)
        # Connect to final host
        self.ses = self.circuit[-1]
        self.circuit.reverse()

    # Execute command
    def execute_cmd(self, command):
        if not self.ses:
            raise BMCConnectionError('Not connected to the target')
        stdin, stdout, stderr = self.ses.exec_command(command)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        if self.debug:
            if error:
                print(f"Unable to execute command: {error}")
            else:
                print(f"Command results:\n{output}")
        exit_status = stdout.channel.recv_exit_status()
        if self.debug:
            print(f"Command exit_status {exit_status}")
        return exit_status, output if exit_status==0 else error if error else output

    # Download file
    def download_file(self, remote_path, local_path):
        if not self.ses:
            raise BMCConnectionError('Not connected to the target')
        sftp = self.ses.open_sftp()
        sftp.get(remote_path, local_path)

    # Upload file
    def upload_file(self, local_path, remote_path):
        if not self.ses:
            raise BMCConnectionError('Not connected to the target')
        sftp = self.ses.open_sftp()
        sftp.put(local_path, remote_path)

    # Disconnect from host
    def disconnect(self):
        for host in self.circuit:
            host.close()
        self.circuit = []
        self.ses = None

    def __del__(self):
        self.disconnect()
