from capstone import *
from pylibemu import *
import textwrap

def analyzeShellcode(shellcode):
    hex_data = " ".join(f"{byte:02x}" for byte in shellcode)
    hex_str = textwrap.fill(hex_data, width=80)
    print("Hexdump:")
    print(hex_str)
    instructions = []
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for insn in md.disasm(shellcode, 0x1000):
            instructions.append(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    except ImportError:
        print("Capstone non installé, désassemblage non effectué.")
        instructions.append("Désassemblage non disponible.")
    emu_result = None
    try:
        from pylibemu import Emulator
        emu = Emulator()
        emu.prepare(shellcode, len(shellcode))
        emu_result = emu.run()
        print("\n------ Emulation Résultat -------")
        print(f"Résultat de l'émulateur : {emu_result}")
    except ImportError:
        print("pylibemu non installé, aucune émulation faîte.")
    
    info_all = (
        "Hexdump:\n" + hex_str + "\n\n"
        "Désassemblage:\n" + "\n".join(instructions) + "\n\n"
        "Résultat émulateur:\n" + str(emu_result)
    )
    return info_all

    