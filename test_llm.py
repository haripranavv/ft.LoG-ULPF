from llama_cpp import Llama

MODEL_PATH = r"C:\Users\harip\ulpf\models\qwen2.5-3b-instruct-q4_k_m.gguf"

llm = Llama(
    model_path=MODEL_PATH,
    n_ctx=2048,
    n_gpu_layers=0,
    verbose=False,
)

response = llm.create_chat_completion(
    messages=[
        {
            "role": "user",
            "content": "Reply with exactly: ULPF local AI is working"
        }
    ],
    temperature=0,
)

print(response["choices"][0]["message"]["content"])