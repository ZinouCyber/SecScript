import requests
import json
from utils.logger import log_info, log_succes, log_error

WINDOWS_HOST_IP = "192.168.0.1"
OLLAMA_URL = "http://192.168.0.138:11434/api/generate"

MODEL_NAME = "qwen2:1.5b"

def analyze_with_ai(scan_data_summary):
    """
    Sends scan results to local lightweight qwen LLM for security analysis.
    """
    log_info(f"Sending scan data to local AI ({MODEL_NAME}) for security analysis...")

    prompt = f"""
    You are an expert Offensive Security AI assistant.
    Analyze the following network scan results and service banners discovered during reconnaissance:

    {scan_data_summary}
     
    Provide a professional penetration testing report including:
    1. Potential security risks or outdated services.
    2. Recommended next steps or specific tools for further testing.
    Keep the response concise, technical, and structured.
    """

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=60)
        if response.status_code == 200:
            result = response.json()
            analysis_text = result.get("response", "No response generated.")
            return analysis_text
        else:
            log_error(f"Qwen returned status code: {response.status_code}")
            return None
    except Exception as e:
        log_error(f"Faild to connect to local AI service (qwen): {e}")
        return

    