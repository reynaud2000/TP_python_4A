import textwrap
from pathlib import Path
from typing import Union
from pylibemu import Emulator
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def load_shellcode_bin(input_path: Union[str, Path]) -> bytes:
    path = Path(input_path)
    if path.suffix != ".bin":
        raise ValueError("Seuls les .bin sont acceptés")
    if not path.exists():
        raise FileNotFoundError(f"{path} introuvable")
    return path.read_bytes()

def analyze_shellcode(input_bin: Union[str, Path]) -> str:
    # 1) Chargement
    try:
        sc_bytes = load_shellcode_bin(input_bin)
    except Exception as e:
        return f"ERREUR: {e}"

    # 2) Hexdump
    hexdump = [
        f"Hexdump ({len(sc_bytes)} octets):",
        textwrap.fill(" ".join(f"{b:02x}" for b in sc_bytes), width=80)
    ]

    # 3) Désassemblage
    disasm = []
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    for insn in cs.disasm(sc_bytes, 0x1000):
        disasm.append(f"0x{insn.address:08x}: {insn.mnemonic:8} {insn.op_str}")

   # 4) Emulation libemu
    emu_log = {"api_calls": [], "errors": []}
    try:
        emu = Emulator()
        BASE = 0x1000
        ret = emu.prepare(sc_bytes, BASE)

        # ancien test (ne fonctionne plus car ret == None)
        # if ret != 0:
        #     emu_log["errors"].append(f"emu.prepare a retourné {ret}")
        # else:
        #     emu.run()
        #
        # nouveau test : on ne signale l'erreur que si ret est un entier != 0
        if isinstance(ret, int) and ret != 0:
            emu_log["errors"].append(f"emu.prepare a retourné {ret}")
        else:
            emu.run()
            if hasattr(emu, 'shellcode') and emu.shellcode:
                for call in emu.shellcode.calls:
                    emu_log["api_calls"].append(
                        f"{call.name} (0x{call.address:x})"
                    )
    except Exception as e:
        emu_log["errors"].append(str(e))
