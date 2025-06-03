from src.tp2.utils.analyze import analyze_shellcode
from src.tp2.utils.llm import response_Analyze_shellcode
import os
def main():

    shellcode_file = os.path.join(os.path.dirname(__file__), "utils", "shellcode.bin")
    if not os.path.exists(shellcode_file):
        print(f"Shellcode file '{shellcode_file}' not found.")
        return
    with open(shellcode_file, "rb") as f:
        shellcode = f.read()
    
    result = analyze_shellcode(shellcode_file)
    print(f"Execution result: {result}")

    # analysis_result = response_Anal
    # yze_shellcode(result)
    # print(analysis_result)

if __name__ == "__main__":
    main()
