import textwrap
from pathlib import Path
from typing import Union

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# on importe Unicorn
try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL
    from unicorn.x86_const import *
except ImportError as ie:
    raise ImportError("Il vous faut installer unicorn-engine (poetry add unicorn-engine)") from ie

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
        sc = load_shellcode_bin(input_bin)
    except Exception as e:
        return f"ERREUR: {e!s}"

    # 2) hexdump
    hexdump = [
        f"Hexdump ({len(sc)} octets):",
        textwrap.fill(" ".join(f"{b:02x}" for b in sc), width=80)
    ]

    # 3) désassemblage statique
    disasm = []
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    for insn in cs.disasm(sc, 0x1000):
        disasm.append(f"0x{insn.address:04x}: {insn.mnemonic:8} {insn.op_str}")

    # 4) émulation avec Unicorn + hook CALL
    BASE       = 0x1000
    STACK_BASE = 0x200000
    STACK_SIZE = 0x10000
    MAX_STEPS  = 5000

    # table API factice
    SYM = {
        0x7C810000: "LoadLibraryA",
        0x7C820000: "GetProcAddress",
        0x7C830000: "URLDownloadToFileA",
        0x7C840000: "WinExec",
        0x7C850000: "CreateProcessA",
    }

    api_calls = []
    errors    = []

    try:
        uc = Uc(UC_ARCH_X86, UC_MODE_32)

        # mappez le shellcode en RX à BASE
        uc.mem_map(BASE, 0x1000 + ((len(sc)//0x1000)+1)*0x1000, UC_PROT_ALL)
        uc.mem_write(BASE, sc)

        # mappez une stack
        uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        uc.reg_write(UC_X86_REG_ESP, STACK_BASE + STACK_SIZE//2)

        # mappez des stubs RET à chaque adresse d'API,
        # pour que le call n'explose pas la mémoire
        for addr in SYM:
            uc.mem_map(addr & 0xFFFFF000, 0x1000, UC_PROT_ALL)
            uc.mem_write(addr, b"\xC3")  # RET

        # désassembleur pour le hook
        cs_run = Cs(CS_ARCH_X86, CS_MODE_32)

        # hook sur CHAQUE instruction
        def hook_code(uc_engine, address, size, user_data):
            code = uc_engine.mem_read(address, size)
            insn = next(cs_run.disasm(code, address, count=1), None)
            if not insn:
                return
            if insn.mnemonic == "call":
                op = insn.op_str.strip()
                target = None
                # CALL imm
                if op.startswith("0x"):
                    try:
                        target = int(op, 16)
                    except:
                        pass
                # CALL reg
                else:
                    reg = None
                    if op.lower() == "eax": reg = UC_X86_REG_EAX
                    elif op.lower() == "ebx": reg = UC_X86_REG_EBX
                    elif op.lower() == "ecx": reg = UC_X86_REG_ECX
                    elif op.lower() == "edx": reg = UC_X86_REG_EDX
                    elif op.lower() == "esi": reg = UC_X86_REG_ESI
                    elif op.lower() == "edi": reg = UC_X86_REG_EDI
                    elif op.lower() == "ebp": reg = UC_X86_REG_EBP
                    elif op.lower() == "esp": reg = UC_X86_REG_ESP
                    if reg is not None:
                        target = uc_engine.reg_read(reg)
                if target in SYM:
                    api_calls.append(f"{SYM[target]} @{hex(address)}")

        uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)

        # lancement
        uc.emu_start(BASE, BASE + len(sc), timeout=0, count=MAX_STEPS)

    except Exception as e:
        errors.append(f"Émulation Unicorn interrompue: {e!s}")

    # 5) rapport final
    report = [f"=== Analyse de {Path(input_bin).name} ===", *hexdump,
              "\n[CAPSTONE] Instructions désassemblées:"]
    report += disasm
    report.append("\n[UNICORN] API calls détectées (émulation pas-à-pas):")
    if api_calls:
        report += [f"• {c}" for c in api_calls]
    else:
        report.append("Aucune détection")
    for e in errors:
        report.append("⚠ " + e)

    return "\n".join(report)
