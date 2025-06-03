import textwrap
import sys
from pathlib import Path
from typing import Union
from pylibemu import Emulator
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# =================== CHARGE LES .BIN ===================
def load_shellcode_bin(input_path: Union[str, Path]) -> bytes:
    """Lit un fichier .bin et retourne les bytes bruts"""
    path = Path(input_path)
    if path.suffix != ".bin":
        raise ValueError("Seuls les .bin sont acceptés (extension .bin obligatoire)")
    if not path.exists():
        raise FileNotFoundError(f"Fichier {path} introuvable")
    return path.read_bytes()

# =================== ANALYSE PRINCIPALE ===================
def analyze_shellcode(input_bin: Union[str, Path]) -> str:
    # 1) Chargement
    try:
        sc_bytes = load_shellcode_bin(input_bin)
    except (ValueError, FileNotFoundError) as e:
        return f"ERREUR: {e}"

    # 2) Hexdump
    hexdump = [
        f"Hexdump ({len(sc_bytes)} octets):",
        textwrap.fill(" ".join(f"{b:02x}" for b in sc_bytes), width=80)
    ]

    # 3) Désassemblage Capstone
    disasm = []
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    try:
        for insn in cs.disasm(sc_bytes, 0x1000):
            disasm.append(f"0x{insn.address:08x}: {insn.mnemonic:8} {insn.op_str}")
    except Exception as e:
        disasm.append(f"Erreur de désassemblage: {e}")

    # 4) Emulation libemu
    emu_log = {"api_calls": [], "errors": []}
    try:
        emu = Emulator()
        BASE = 0x1000
        ret = emu.prepare(BASE, sc_bytes)
        if ret != 0:
            emu_log["errors"].append(f"emu.prepare a retourné {ret}")
        else:
            emu.run()
            if hasattr(emu, 'shellcode') and emu.shellcode:
                for call in emu.shellcode.calls:
                    emu_log["api_calls"].append(f"{call.name} (0x{call.address:x})")
    except Exception as e:
        emu_log["errors"].append(str(e))

    # 5) Construction du rapport
    report = []
    report.append(f"=== Analyse de {Path(input_bin).name} ===")
    report.extend(hexdump)
    report.append("\n[CAPSTONE] Instructions désassemblées:")
    report.extend(disasm)            # ou disasm[:15] si vous voulez limiter
    report.append("\n[LIBEMU] Détections dynamiques:")
    if emu_log["api_calls"]:
        for c in emu_log["api_calls"]:
            report.append(f"• {c}")
    else:
        report.append("Aucune détection")
    for err in emu_log["errors"]:
        report.append(f"⚠ {err}")

    return "\n".join(report)