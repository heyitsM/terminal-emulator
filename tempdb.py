def gen_help_string():
    help_string = """HELP
Here are a list of commands and their function:

C:
cd <new_dir>: changes current directory to new directory
clear: clears all previous commands from the terminal

E:
echo <text>: prints out what you type, and eventually will be able to send it to a file

H:
help: brings up this general help menu

L:
logout: allows user to logout from terminal
ls: prints out what files/folders are in the current directory

M:
mkdir <dir_name>: makes a new directory in the current directory with that filename

P:
pwd: prints out the directory you are currently in (just the name of the current directory)
path:prints the path to the current directory. In the future it may also take an argument to print path to that file

T:
touch <filename>: creates a new file in the current directory with the given filename
"""
    #split_string = help_string.split("\n")
    return help_string
