from ollama import Client
import os
client = Client(
  host='http://10.33.2.121:33020',
  headers={'x-some-header': 'some-value'}
)
response = client.chat(model='deepseek-r1:1.5b', messages=[
  {
    'role': 'user',
    'content': 'Clearly explain what this shellcode does. What is the danger for the user and the recommendations.\
    What to do if the user has launched the shellcode. Answers in English and French.',
  },
])

output_path = os.path.join(os.path.dirname(__file__), "shellcode.txt")
with open(output_path, "w", encoding="utf-8") as f:
    f.write(response.message.content)
    print(response.message.content)
