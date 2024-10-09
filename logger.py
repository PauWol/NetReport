import colorama , re, time
from colorama import Fore, Style
colorama.init()


def log_error(message):
    print(f'{Fore.RED}[{time.strftime("%H:%M:%S")}] [error] {message}{Style.RESET_ALL}')

def log_warning(message):
    print(f'{Fore.YELLOW}[{time.strftime("%H:%M:%S")}] [warning] {message}{Style.RESET_ALL}')

def log_info(message):
    print(f'{Fore.BLUE}[{time.strftime("%H:%M:%S")}] [info] {message}{Style.RESET_ALL}')

def log_success(message):
    print(f'{Fore.GREEN}[{time.strftime("%H:%M:%S")}] [success] {message}{Style.RESET_ALL}')