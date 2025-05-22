from capstone import *
from pylibemu import *
import textwrap

def disassemble(shellcode, address=0):
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for i in md.disasm(shellcode, 0x1000):
            print("0x{0:x}:\t{1}\t{2}".format(i.address, i.mnemonic, i.op_str))
            if i.mnemonic == "jmp" and i.op_str == "short 0x54":
                print("Found the jump instruction at address: 0x{0:x}".format(i.address))
                break
    except CsError as e:
        print("ERROR: %s" % e)
    

def print_hex(data):
    """
    Print the hex representation of the data.
    """
    hex_data = " ".join(f"{byte:02x}" for byte in data)
    print(textwrap.fill(hex_data, width=80))


def analyzeShellcode(shellcode):
    print(print_hex(shellcode))
    try:
        from pylibemu import Emulator
        emu = Emulator()
        emu.prepare(shellcode, len(shellcode))
        emu_result = emu.run(shellcode)
        print("------ Emu résultat -------")
        print(f"Résultat de l'émulateur : {emu_result}")
    except ImportError:
        print("pylibemu non installé, aucune émulation faîte.")
    info_all = (
        "Hexdump:\n" + hexdump(shellcode) + "\n\n"
        "Désassemblage:\n" + "\n".join(instructions) + "\n\n"
        "Résultat émulateur:\n" + str(emu_result)
    )
    return info_all

    