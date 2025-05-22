import textwrap
import re
import codecs

def parse_shellcode(shellcode):
    """Accepte bytes, string '\\x..', ou hexdump d'octets."""
    if isinstance(shellcode, bytes):
        return shellcode
    if isinstance(shellcode, str):
        s = shellcode.strip().replace('\n', '').replace(' ', '')
        if "\\x" in s:
            s = s.replace("\\x", "")
            return codecs.decode(s, "hex")
        if re.fullmatch(r'[0-9A-Fa-f]+', s):
            return bytes.fromhex(s)
    raise ValueError("Format de shellcode non supporté")

def disassemble(shellcode, base_address=0x1000):
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CsError
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions = []
        for i in md.disasm(shellcode, base_address):
            line = "0x{0:x}:\t{1}\t{2}".format(i.address, i.mnemonic, i.op_str)
            print(line)
            instructions.append(line)
            if i.mnemonic == "jmp" and i.op_str == "short 0x54":
                found = f"Found the jump instruction at address: 0x{i.address:x}"
                print(found)
                instructions.append(found)
                break
        return instructions
    except ImportError:
        return ["Capstone non installé"]
    except Exception as e:
        return [f"ERROR: {e}"]

def analyzeShellcode(shellcode):
    shellcode = parse_shellcode(shellcode)
    # Hexdump
    hex_data = " ".join(f"{byte:02x}" for byte in shellcode)
    hex_str = textwrap.fill(hex_data, width=80)

    # Désassemblage et détection jump
    instructions = disassemble(shellcode)

    # Emulation
    try:
        from pylibemu import Emulator
        emu = Emulator()
        emu.prepare(shellcode, len(shellcode))
        emu_result = emu.run(shellcode)
        print("------ Emu résultat -------")
        print(f"Résultat de l'émulateur : {emu_result}")
    except ImportError:
        emu_result = "pylibemu non installé, aucune émulation faîte."
    except Exception as ex:
        emu_result = f"Erreur pylibemu: {ex}"

    info_all = (
        "Hexdump:\n" + hex_str + "\n\n"
        "Désassemblage:\n" + "\n".join(instructions) + "\n\n"
        "Résultat émulateur:\n" + str(emu_result)
    )
    return info_all

# Utilisation type:
# shellcode = "\\x90\\x90\\xeb\\x05\\xe8..."   # ou bytes, ou hexdump
# print(analyzeShellcode(shellcode))
