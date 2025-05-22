from capstone import *
from pylibemu import *

def disassemble(shellcode, address=0):
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for i in md.disasm(shellcode, 0x1000):
            print("0x{0:x}:\t{1}\t{2}".format(i.address, i.mnemonic, i.op_str))
            if i.mnemonic == "jmp" and i.op_str == "short 0x54":
                print("Found the jump instruction at address: 0x{0:x}".format(i.address))
                break
    except CsError as e:
        print("ERROR: %s" % e)
    


def analyzeShellcode(shellcode):
    """
    This function takes a shellcode with pylibemu and disassembles it using Capstone.
    """
    # Initialize the emulator
    emu = Emulator()
    emu.mem_map(0x1000, 0x10000)  # Map memory for the shellcode

    # Write the shellcode to memory
    emu.mem_write(0x1000, shellcode)

    # Disassemble the shellcode
    disassemble(shellcode)

    # Execute the shellcode
    emu.reg_write(Emulator.REG_EIP, 0x1000)  # Set instruction pointer to the start of the shellcode
    emu.emu_start(0x1000, 0x1000 + len(shellcode))


    # Get the result of the execution
    result = emu.reg_read(Emulator.REG_EAX)  # Read the EAX register
    return result
    