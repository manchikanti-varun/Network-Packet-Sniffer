from scapy.all import get_if_list

def list_interfaces():
    """Lists all available network interfaces."""
    interfaces = get_if_list()
    print("Available Network Interfaces:")
    for iface in interfaces:
        print(iface)

if __name__ == "__main__":
    list_interfaces()
