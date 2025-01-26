from nxc.logger import nxc_logger
import donut
import sys
import hashlib

class NXCModule:
    """
    Donut:
    -------
    Module by @Lavender-exe
    """

    name = "donut"
    description = "Execute Assembly but in Netexec"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = False

    def __init__(self):
        self.context = None
        self.module_options = None

    def options(self, context, module_options):
        """Required.
        BINARY_PATH Path to Dotnet Binary
        URL         URL to host Donut Shellcode
        OUTPUT      Shellcode File Name and Path
        
        Usage: nxc smb $IP -u Username -p Password -M donut -o BINARY_PATH='/tmp/Seatbelt.exe'
            #    nxc smb $IP -u Username -p Password -M donut -o BINARY_PATH='/tmp/Seatbelt.exe' BYPASS=2 ENTROPY=1 OUTPUT='/tmp/Seatbelt.bin'
        """

        self.path: str      = ""
        self.url: str       = ""
        self.arch: int      = 3 # AMD64+x86
        self.bypass: int    = 1 # Disable AMSI and WLDP bypass - detected
        self.entropy: int   = None # Default is 3
        self.cls: str       = ""
        self.method: str    = ""
        self.params: str    = ""
        self.runtime: str   = ""
        self.appdomain: str = ""
        self.cleanup: bool  = False

        if "PATH" in module_options:
            self.path = module_options["PATH"]

        if "URL" in module_options:
            self.url = module_options["URL"]

        if "ARCH" in module_options:
            self.arch = module_options["ARCH"]

        if "BYPASS" in module_options:
            self.bypass = module_options["BYPASS"]

        if "ENTROPY" in module_options:
            self.entropy = module_options["ENTROPY"]

        if "CLS" in module_options:
            self.cls = module_options["CLS"]

        if "METHOD" in module_options:
            self.method = module_options["METHOD"]

        if "PARAMS" in module_options:
            self.params = module_options["PARAMS"]

        if "RUNTIME" in module_options:
            self.runtime = module_options["RUNTIME"]

        if "APPDOMAIN" in module_options:
            self.appdomain = module_options["APPDOMAIN"]

    def generate_shellcode(self, module_options):
        """
        
        """
        try:
            shellcode = donut.create(**module_options)

            md5sum    = hashlib.md5(shellcode).hexdigest()
            sha256sum = hashlib.sha256(shellcode).hexdigest()

            context.log.highlight(f"MD5 Hash of Shellcode: {md5sum}")
            context.log.highlight(f"SHA256 Hash of Shellcode: {sha256sum}")
            context.log.success("Shellcode Created!")

        except Exception as e:
            context.log.exception(f"Exception Occurred: {e}")

    def on_login(self, context, connection):
        """
        1. Generate Shellcode
        2. Write loader to temp directory
        3. Execute Shellcode remotely via loader
        4. Send Output to User
        5. Delete Loader
        """

        # Logging best practice
        # Mostly you should use these functions to display information to the user
        # context.log.display("I'm doing something")  # Use this for every normal message ([*] I'm doing something)
        # context.log.success("I'm doing something")  # Use this for when something succeeds ([+] I'm doing something)
        # context.log.fail("I'm doing something")  # Use this for when something fails ([-] I'm doing something), for example a remote registry entry is missing which is needed to proceed
        # context.log.highlight("I'm doing something")  # Use this for when something is important and should be highlighted, printing credentials for example

        # # These are for debugging purposes
        # context.log.info("I'm doing something")  # This will only be displayed if the user has specified the --verbose flag, so add additional info that might be useful
        # context.log.debug("I'm doing something")  # This will only be displayed if the user has specified the --debug flag, so add info that you would might need for debugging errors

        # # These are for more critical error handling
        # context.log.error("I'm doing something")  # This will not be printed in the module context and should only be used for critical errors (e.g. a required python file is missing)
        # try:
        #     raise Exception("Exception that might have occurred")
        # except Exception as e:
        #     context.log.exception(f"Exception occurred: {e}")  # This will display an exception traceback screen after an exception was raised and should only be used for critical errors

