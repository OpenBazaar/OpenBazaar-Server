import os
import subprocess
import sys


def bootstrap(use_testnet):
    script_dir = os.path.dirname(os.path.abspath(__file__))

    if sys.platform == "darwin":

        # OSX won't pass the PATH
        subprocess.call(['/usr/local/bin/pip', 'install', '-r', '%s/requirements.txt' % script_dir])
        os.chdir(script_dir)
        if use_testnet:
            os.system('/usr/local/bin/python openbazaard.py start --testnet')
        else:
            os.system('/usr/local/bin/python openbazaard.py start')

    else:
        subprocess.call(['pip', 'install', '-r', '%s%srequirements.txt' % (script_dir, os.pathsep)])
        os.chdir(script_dir)
        if use_testnet:
            os.system('python sopenbazaard.py start --testnet')
        else:
            os.system('python openbazaard.py start')


if __name__ == '__main__':
    testnet = False
    if len(sys.argv) > 1:
        if sys.argv[1] == 'testnet':
            testnet = True
    bootstrap(testnet)
