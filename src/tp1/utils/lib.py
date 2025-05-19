from scapy.all import get_if_list # type: ignore

def hello_world() -> str:
    """
    Hello world function
    """
    return "hello world"


def choose_interface() -> str:
    """
    Return network interface and input user choice
    """
    print("Choose network interface:")
    if_list = get_if_list()
    for i, iface in enumerate(if_list):
        print(f"{i}: {iface}")
    try:
        choice = int(input("Enter the number of the interface: "))
        if choice < 0 or choice >= len(if_list):
            raise ValueError
    except ValueError:
        print("Invalid choice. Please enter a number between 0 and", len(interface) - 1)
        return choose_interface()
    interface = if_list[choice]
    print(f"You selected: {interface}")
    return interface
