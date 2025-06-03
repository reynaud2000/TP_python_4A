#!/usr/bin/env python3
import sys
import textwrap
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# import pylibemu CORRECTEMENT : module unique, pas de sous-package const
from pylibemu import Emulator, EMU_HOOK_CODE, PAGE_EXECUTE_READWRITE

#
# Table de hash→nom d’API (remplacez par VOS hashes)
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

    # map shellcode
    size_map = 0x1000 * ((len(sc) // 0x1000) + 1)
    emu.mem_map(BASE, size_map, PAGE_EXECUTE_READWRITE)
    emu.mem_write(BASE, sc)

    # patch stub de résolveur en RET pour éviter les accès PEB non mappés
    emu.mem_write(0x1002, b"\xC3")

    # map stack
    emu.mem_map(STACK_BASE, STACK_SIZE, PAGE_EXECUTE_READWRITE)
    emu.reg_write("ESP", STACK_BASE + STACK_SIZE // 2)

    # 4) hook CODE : capturer chaque CALL
    def hook_code(emu_obj, addr, size, user_data):
        code = emu_obj.mem_read(addr, size)
        for ins in md.disasm(code, addr):
            if ins.mnemonic == "call":
                op = ins.op_str.strip()
                if op.startswith("0x"):
                    tgt = int(op, 16)
                else:
                    tgt = emu_obj.reg_read(op.upper())
                if tgt == 0x1002:
                    h = emu_obj.reg_read("EDI")
                    name = HASH_API.get(h, f"unk_{h:08x}")
                    api_calls.append(f"{name} @{hex(addr)}")

    emu.hook_add(EMU_HOOK_CODE, hook_code)

    # 5) exécution
    try:
        emu.run(BASE, count=MAX_STEPS)
    except Exception as e:
        errors.append(f"Émulation interrompue : {e!s}")

    # 6) rapport
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

