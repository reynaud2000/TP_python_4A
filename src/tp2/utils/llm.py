from ollama import Client

def AnalyzeShellcode(shellcode):
    """
    This function takes a shellcode as input and uses the Ollama API to analyze it.
    It returns the analysis result.
    """
    client = Client(
    host='http://10.33.2.121:33020',
    headers={'x-some-header': 'some-value'}
    )
    response = client.chat(model='deepseek-r1:1.5b', messages=[
        {
            'role': 'user',
            'content': f'Clearly explain what this shellcode does. What is the danger for the user and the recommendations.\
            What to do if the user has launched the shellcode. Answers in English and French.\n\nShellcode:\n{shellcode}',
        },
    ])
    return response['message']['content']