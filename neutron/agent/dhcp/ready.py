import sys
from os import path

def main():
    if path.isfile('/var/lib/neutron/dhcp_sync_finished'):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    sys.exit(main())
