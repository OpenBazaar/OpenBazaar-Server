import os
import subprocess
import sys


def bootstrap(use_testnet):
    script_dir = os.path.dirname(os.path.abspath(__file__))

    if sys.platform == "darwin":

        # OSX won't pass the PATH
        subprocess.call(['/usr/local/bin/pip', 'install', '-r', '%s/requirements.txt' % script_dir])
        if use_testnet:
            os.system('/usr/local/bin/python %s/openbazaard.py start --testnet' % script_dir)
        else:
            os.system('/usr/local/bin/python %s/openbazaard.py start' % script_dir)

    else:
        subprocess.call(['pip', 'install', '-r', '%s%srequirements.txt' % (script_dir, os.pathsep)])
        if use_testnet:
            os.system('python %s%sopenbazaard.py start --testnet' % (script_dir, os.pathsep))
        else:
            os.system('python %s%sopenbazaard.py start' % (script_dir, os.pathsep))


if __name__ == '__main__':
    testnet = False
    if len(sys.argv) > 1:
        if sys.argv[1] == 'testnet':
            testnet = True
    bootstrap(testnet)
