from llm_query import query_gemini

print("Testing Gemini API...")

try:
    prompt = "Say 'Hello, I am working!' in one sentence."
    response = query_gemini(prompt)
    print(f"\nResponse: {response}")
    print("\nSuccess! Gemini API is working.")
except Exception as e:
    print(f"\nError: {str(e)}")
    print("\nMake sure:")
    print("1. .env file exists with GEMINI_API_KEY")
    print("2. API key is valid from https://aistudio.google.com/app/apikey")

