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

def analyzeShellcode(shellcode):
    # Capture hex string instead of printing it directly
    hex_data = " ".join(f"{byte:02x}" for byte in shellcode)
    hex_str = textwrap.fill(hex_data, width=80)
    print(hex_str)
    try:
        from pylibemu import Emulator
        emu = Emulator()
        emu.prepare(shellcode, len(shellcode))
        emu_result = emu.run(shellcode)
        print("------ Emu résultat -------")
        print(f"Résultat de l'émulateur : {emu_result}")
    except ImportError:
        print("pylibemu non installé, aucune émulation faîte.")
        emu_result = None
    # 'instructions' is undefined, so we need to define it or leave it empty
    instructions = []
    info_all = (
        "Hexdump:\n" + hex_str + "\n\n"
        "Désassemblage:\n" + "\n".join(instructions) + "\n\n"
        "Résultat émulateur:\n" + str(emu_result)
    )
    return info_all

    