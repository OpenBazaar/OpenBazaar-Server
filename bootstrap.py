import os
import subprocess
import sys


def bootstrap(use_testnet):
    subprocess.call(['pip', 'install', '-r', 'requirements.txt'])
    if use_testnet:
        os.system('python openbazaard.py start --testnet')
    else:
        os.system('python openbazaard.py start')


if __name__ == '__main__':
    use_testnet = False
    if len(sys.argv) > 1:
        if sys.argv[1] == 'testnet':
            use_testnet = True
    bootstrap(use_testnet)
