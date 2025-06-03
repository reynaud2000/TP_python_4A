#!/usr/bin/env python3
import sys
import textwrap
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# pylibemu binding classique
from pylibemu import Emulator
from pylibemu.const import EMU_HOOK_CODE, PAGE_EXECUTE_READWRITE

#
# Table de hash→nom d’API
# Remplacez par vos propres valeurs extraites du shellcode
#
HASH_API = {
    0xec0e4e8e: "LoadLibraryA",
    0x702f1a36: "GetProcAddress",
    0x0e8afe98: "URLDownloadToFileA",
    0x73e2d87e: "WinExec",
}

def load_shellcode_bin(path: Path) -> bytes:
    if not path.exists():
        raise FileNotFoundError(path)
    if path.suffix.lower() != ".bin":
        raise ValueError("attendu un .bin")
    return path.read_bytes()

def analyze_with_pylibemu(binpath: Path) -> str:
    sc = load_shellcode_bin(binpath)

    # 1) hexdump
    dump = " ".join(f"{b:02x}" for b in sc)
    hexd = [
        f"Hexdump ({len(sc)} octets):",
        textwrap.fill(dump, width=80)
    ]

    # 2) désassemblage statique
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    disasm = [
        f"0x{ins.address:04x}: {ins.mnemonic:8} {ins.op_str}"
        for ins in md.disasm(sc, 0x1000)
    ]

    # 3) configuration de l’émulateur
    BASE        = 0x1000
    STACK_BASE  = 0x200000
    STACK_SIZE  = 0x10000
    MAX_STEPS   = 50000

    api_calls = []
    errors    = []

    emu = Emulator()

    # map shellcode + stub override
    size_map = 0x1000 * ((len(sc) // 0x1000) + 1)
    emu.mem_map(BASE, size_map, PAGE_EXECUTE_READWRITE)
    emu.mem_write(BASE, sc)

    # on remplace le stub de résolution à 0x1002 par un RET (0xC3)
    # pour ne pas émuler la PEB, etc.
    emu.mem_write(0x1002, b"\xC3")

    # map stack
    emu.mem_map(STACK_BASE, STACK_SIZE, PAGE_EXECUTE_READWRITE)
    emu.reg_write("ESP", STACK_BASE + STACK_SIZE // 2)

    # 4) hook CODE pour capturer chaque CALL
    def hook_code(emu_obj, address, size, user_data):
        # lecture de l’instruction en place
        code = emu_obj.mem_read(address, size)
        for ins in md.disasm(code, address):
            if ins.mnemonic == "call":
                op = ins.op_str.strip()
                # immediate
                if op.startswith("0x"):
                    tgt = int(op, 16)
                else:
                    # registre (eax, ebx, etc.)
                    tgt = emu_obj.reg_read(op.upper())
                # si c’est notre stub (0x1002), on lit EDI et on résout
                if tgt == 0x1002:
                    h = emu_obj.reg_read("EDI")
                    name = HASH_API.get(h, f"unk_{h:08x}")
                    api_calls.append(f"{name} @{hex(address)}")

    emu.hook_add(EMU_HOOK_CODE, hook_code)

    # 5) on lance l’émulation
    try:
        # méthode run_code ou run selon votre binding
        # vous pouvez remplacer par emu.run(BASE) ou emu.run_code(BASE)
        emu.run(BASE, count=MAX_STEPS)
    except Exception as e:
        errors.append(f"Émulation interrompue : {e!s}")

    # 6) on construit le rapport
    rpt = []
    rpt.append(f"=== Analyse de {binpath.name} ===")
    rpt.extend(hexd)
    rpt.append("\n[CAPSTONE] Instructions désassemblées:")
    rpt.extend(disasm)
    rpt.append("\n[PYLIBEMU] API calls détectées :")
    if api_calls:
        rpt.extend(f"• {c}" for c in api_calls)
    else:
        rpt.append("Aucune détection")
    for e in errors:
        rpt.append("⚠ " + e)

    return "\n".join(rpt)