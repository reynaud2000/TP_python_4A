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
    # 1) chargement
    try:
        sc_bytes = load_shellcode_bin(input_bin)
    except Exception as e:
        return f"ERREUR: {e}"

    # 2) hexdump
    hexdump = [
        f"Hexdump ({len(sc_bytes)} octets):",
        textwrap.fill(" ".join(f"{b:02x}" for b in sc_bytes), width=80)
    ]

    # 3) désassemblage
    disasm = []
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    for insn in cs.disasm(sc_bytes, 0x1000):
        disasm.append(f"0x{insn.address:04x}: {insn.mnemonic:8} {insn.op_str}")

    # 4) émulation
    emu = Emulator()
    BASE = 0x1000
    ret = emu.prepare(sc_bytes, BASE)
    emu_log = {"api_calls": [], "errors": []}

    if isinstance(ret, int) and ret != 0:
        emu_log["errors"].append(f"emu.prepare a retourné {ret}")
    else:
        # === Ajouts pour simuler les DLL et leurs exports ===
        K32_BASE   = 0x7C800000  # base arbitraire pour kernel32.dll
        URLM_BASE  = 0x6F1D0000  # base arbitraire pour urlmon.dll

        emu.add_library("kernel32.dll", K32_BASE)
        emu.add_import("kernel32.dll", "LoadLibraryA",    K32_BASE + 0x0001F000)
        emu.add_import("kernel32.dll", "GetProcAddress",  K32_BASE + 0x0001E000)
        emu.add_import("kernel32.dll", "WinExec",         K32_BASE + 0x0005A000)
        emu.add_import("kernel32.dll", "CreateProcessA",  K32_BASE + 0x0006B000)

        emu.add_library("urlmon.dll", URLM_BASE)
        emu.add_import("urlmon.dll", "URLDownloadToFileA", URLM_BASE + 0x0003A000)
        # ======================================================

        # on exécute l'émulation : buffer + max instructions
        max_instr = 5000
        emu.run(sc_bytes, max_instr)

        # on collecte les appels détectés
        if getattr(emu, "shellcode", None):
            for call in emu.shellcode.calls:
                emu_log["api_calls"].append(f"{call.name} @0x{call.address:x}")

    # 5) construction du rapport
    report = [f"=== Analyse de {Path(input_bin).name} ===",
              *hexdump,
              "\n[CAPSTONE] Instructions désassemblées:"]
    report += disasm
    report += ["\n[LIBEMU] Détections dynamiques:"]
    if emu_log["api_calls"]:
        for c in emu_log["api_calls"]:
            report.append(f"• {c}")
    else:
        report.append("Aucune détection")
    for e in emu_log["errors"]:
        report.append(f"⚠ {e}")

    return "\n".join(report)
