#####################
#  INIPATCH TOOL    #
# php.ini hardening #
#####################

import sys
import ConfigParser
from os.path import abspath

from pwn import log, util

# Set sane defaults that should not affect
# the services running.
def safe_fix (ini):
    # Error handling
    ini.set("PHP", "expose_php", "Off")
    ini.set("PHP", "display_errors", "Off")
    ini.set("PHP", "log_errors", "On")

# Set defaults that might stop really stupid
# code from running.
def normal_fix (ini):
    print "NORMAL HARDENING"

    # Turn off stupid features
    answer = util.prompt("Do you need register_globals and magic quotes? (n): ", "n")
    setting = "On" if answer == "y" or answer == "yes" else "Off"
    ini.set("PHP" , "register_globals", setting)
    ini.set("PHP" , "magic_quotes_gpc", setting)

    # Stop file inclusion vulns
    answer = util.prompt("Do you need remote file inclusion? (n): ", "n")
    setting = "On" if answer == "y" or answer == "yes" else "Off"
    ini.set("PHP" , "allow_url_fopen", setting)
    ini.set("PHP" , "allow_url_include", setting)

    # File uploading is dangerous
    answer = util.prompt("Do you need to upload files? (n): ", "n")
    setting = "On" if answer == "y" or answer == "yes" else "Off"
    ini.set("PHP" , "file_uploads", setting)

    # Fixing cookies
    answer = util.prompt("Do you need to read cookies using javascript? (n): ", "n")
    setting = "0" if answer == "y" or answer == "yes" else "1"
    ini.set("Session" , "session.cookie_httponly", setting)

    # Set safe mode
    ini.set("PHP" , "safe_mode", "On")
    ini.set("PHP" , "safe_mode_gid", "On")

    answer = util.prompt("Constrain directories allow for include and exec? (y): ", "y")
    answer = True if answer == "y" or answer == "yes" else False
    if answer:
        include_dir = util.prompt("Directory to limit included files to (./): ", "./")
        ini.set("PHP" , "safe_mode_include_dir", abspath(include_dir))
        exec_dir = util.prompt("Directory to limit executables to (./): ", "./")
        ini.set("PHP" , "safe_mode_exec_dir", abspath(exec_dir))
        base_dir = util.prompt("Directory to restrict includes to (./): ", "./")
        ini.set("PHP" , "open_basedir", abspath(base_dir))

def search_for_calls (ini, search_directory):
    pass

# Lock down everything. If it doesn't break the
# service, it will be extremely hard to exploit.
def iron_hand (ini):
    print "IRON HAND"

    # Drop new .htaccess in the directory
    answer = util.prompt("Drop a sensible .htaccess in the current directory? (y): ", "n")
    answer = True if answer == "y" or answer == "yes" else False
    if answer:
        log.error("TODO: HTACCESS")

    # Run PHPIDS before everything
    answer = util.prompt("Run PHPIDS before all scripts? (y): ", "n")
    answer = True if answer == "y" or answer == "yes" else False
    if answer:
        log.error("TODO: PHPIDS")

    # Finally disable all functions and classes that are not called
    answer = util.prompt("disable ALL functions and classes not used? (y): ", "n")
    answer = True if answer == "y" or answer == "yes" else False
    if answer:
        search_dir = util.prompt("Directory to search recursively for calls (./): ", "./")
        remove_functions, remove_classes = search_for_calls(ini, search_dir)
        ini.set("PHP" , "disable_functions", remove_functions)
        ini.set("PHP" , "disable_classes", remove_classes)

def interactive_mode ():
    default_location = "/etc/php5/apache2/php.ini"
    ini_location = util.prompt("Location of php.ini (%s): " % default_location, default_location)

    answer = util.prompt("Apply an iron hand to the php.ini? (n): ", "n")
    want_iron_hand = True if answer == "y" or answer == "yes" else False

    return (ini_location, want_iron_hand)

def main ():
    print "PHP.INI HARDENING TOOL"

    ini_location, want_iron_hand = interactive_mode()

    ini = ConfigParser.RawConfigParser()
    ini.read(ini_location)

    with open(ini_location + ".backup", "wb") as f:
        ini.write(f)

    safe_fix(ini)
    normal_fix(ini)
    if want_iron_hand: iron_hand(ini)

    with open(ini_location, "wb") as f:
        ini.write(f)

if __name__ == "__main__":
    main()
