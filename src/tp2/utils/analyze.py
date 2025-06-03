# src/tp2/utils/analyze.py

import textwrap
from pathlib import Path
from typing import Union

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EDI

#
# 1) Fonction de chargement du shellcode .bin
#
def load_shellcode_bin(input_path: Union[str, Path]) -> bytes:
    path = Path(input_path)
    if path.suffix.lower() != ".bin":
        raise ValueError("Seuls les .bin sont acceptés")
    if not path.exists():
        raise FileNotFoundError(f"{path} introuvable")
    return path.read_bytes()

#
# 2) Table de résolution des 4 appels WinAPI
#    On repère le hash (EDi) passé au stub. Vous devez remplir
#    ces valeurs par celles qu’on voit dans votre désassemblage
#
HASH_API = {
    0xec0e4e8e: "LoadLibraryA",        # mov edi,0xec0e4e8e ; call 0x1002
    0x702f1a36: "GetProcAddress",     # mov edi,0x702f1a36 ; call 0x1002
    0x0e8afe98: "URLDownloadToFileA", # mov edi,0x0e8afe98 ; call 0x1002
    0x73e2d87e: "WinExec",            # mov edi,0x73e2d87e ; call 0x1002
}

#
# 3) Analyse : hexdump + désassemblage Capstone + émulation Unicorn
#
def analyze_shellcode(input_bin: Union[str, Path]) -> str:
    # a) chargement + hexdump
    sc = load_shellcode_bin(input_bin)
    hexdump = [
        f"Hexdump ({len(sc)} octets):",
        textwrap.fill(" ".join(f"{b:02x}" for b in sc), width=80)
    ]

    # b) désassemblage statique
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    disasm = [
        f"0x{ins.address:04x}: {ins.mnemonic:8} {ins.op_str}"
        for ins in cs.disasm(sc, 0x1000)
    ]

    # c) émulation et hook CALL
    BASE, STACK_BASE, STACK_SIZE = 0x1000, 0x200000, 0x10000
    MAX_STEPS = 5000
    api_calls = []
    errors = []

    try:
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        # map shellcode
        size_map = 0x1000 * ((len(sc) // 0x1000) + 1)
        uc.mem_map(BASE, size_map, UC_PROT_ALL)
        uc.mem_write(BASE, sc)
        # map stack
        uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        uc.reg_write(UC_X86_REG_ESP, STACK_BASE + STACK_SIZE // 2)

        # hook sur chaque instruction
        def hook_code(uc_engine, address, size, user_data):
            code = uc_engine.mem_read(address, size)
            for insn in cs.disasm(code, address):
                if insn.mnemonic == "call":
                    op = insn.op_str.strip()
                    # 1) appel immédiat : stub de résolution des imports
                    if op.startswith("0x"):
                        addr = int(op, 16)
                        if addr == 0x1002:  # adresse de votre stub unique
                            h = uc_engine.reg_read(UC_X86_REG_EDI)
                            name = HASH_API.get(h)
                            if name:
                                api_calls.append(f"{name} @{hex(address)}")

        uc.hook_add(UC_HOOK_CODE, hook_code)
        uc.emu_start(BASE, BASE + len(sc), timeout=0, count=MAX_STEPS)

    except Exception as e:
        errors.append(f"Émulation Unicorn interrompue: {e}")

    # d) construction du rapport
    report = []
    report.append(f"=== Analyse de {Path(input_bin).name} ===")
    report.extend(hexdump)
    report.append("\n[CAPSTONE] Instructions désassemblées:")
    report.extend(disasm)
    report.append("\n[UNICORN] API calls détectées (émulation pas-à-pas):")
    if api_calls:
        report.extend(f"• {c}" for c in api_calls)
    else:
        report.append("Aucune détection")
    for e in errors:
        report.append("⚠ " + e)

    return "\n".join(report)
