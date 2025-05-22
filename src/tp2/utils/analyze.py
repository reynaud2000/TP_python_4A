from capstone import *
from pylibemu import *

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
    


def analyzeShellcode(shellcode):
    emu = Emulator()
    emu.prepare(shellcode, len(shellcode))
    found, info = emu.run(shellcode)  # <--- Passes le buffer, pas une adresse d'int

    print(f"Shellcode found: {found}")
    print(f"Info: {info}")
    disassemble(shellcode)
    return info

    