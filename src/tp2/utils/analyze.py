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

    # 3) désassemblage statique
    disasm = []
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    for insn in cs.disasm(sc_bytes, 0x1000):
        disasm.append(f"0x{insn.address:04x}: {insn.mnemonic:8} {insn.op_str}")

    # 4) émulation + hook « à la main » des CALL
    emu = Emulator()
    BASE = 0x1000
    ret = emu.prepare(sc_bytes, BASE)
    api_calls = []
    errors = []
    MAX_STEPS = 5000

    if isinstance(ret, int) and ret != 0:
        errors.append(f"emu.prepare a retourné {ret}")
    else:
        # 4.a) on injecte une table {adresse: nom_API} que le shellcode va
        #      appeler (CALL <imm> ou CALL reg). Adresses totalement
        #      arbitraires, mais en-dehors du buffer 0x1000–0x1000+len().
        SYM = {
            0x7C810000: "LoadLibraryA",
            0x7C820000: "GetProcAddress",
            0x7C830000: "URLDownloadToFileA",
            0x7C840000: "WinExec",
            0x7C850000: "CreateProcessA",
        }
        # pour éviter de sauter hors mémoire valide, on peut écrire un
        # RET (0xC3) sur chaque stub. Ici on ne le fait pas, l'ému
        # va planter dès qu'il tombera dessus, ce qu'on catchera.

        # 4.b) on boucle en pas-à-pas
        step = 0
        cs_run = Cs(CS_ARCH_X86, CS_MODE_32)
        pc = BASE
        try:
            while step < MAX_STEPS:
                # fetch+disasm
                buf = emu.memory_read(pc, 16)
                insns = list(cs_run.disasm(buf, pc, count=1))
                if not insns:
                    break
                ins = insns[0]
                # si c'est un CALL
                if ins.mnemonic == "call":
                    target = None
                    op = ins.op_str.strip()
                    # CALL imm
                    if op.startswith("0x"):
                        target = int(op, 16)
                    # CALL reg
                    elif op in ("eax","ebx","ecx","edx","edi","esi","ebp","esp"):
                        target = emu.get_register(op.upper())
                    # appelle notre table
                    if target and target in SYM:
                        api_calls.append(f"{SYM[target]} @{hex(ins.address)}")

                # on avance d'une instruction
                r = emu.step()
                if r != 0:
                    # ex: accès mémoire invalide => on sort
                    break
                pc = emu.get_register("EIP")
                step += 1

        except Exception as e:
            errors.append(f"Emulation interrompue: {e}")

    # 5) on construit le rapport
    report = []
    report.append(f"=== Analyse de {Path(input_bin).name} ===")
    report.extend(hexdump)
    report.append("\n[CAPSTONE] Instructions désassemblées:")
    report.extend(disasm)
    report.append("\n[HOOK-SHELL] API calls détectées (pas-à-pas):")
    if api_calls:
        for c in api_calls:
            report.append("• " + c)
    else:
        report.append("Aucune détection")
    for e in errors:
        report.append("⚠ " + e)

    return "\n".join(report)
