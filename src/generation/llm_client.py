
import ollama
from typing import Optional, Dict
from src.core.logger import get_logger

logger = get_logger(__name__)

class LLMClient:
    def __init__(self, model_name: str = 'deepseek-coder-v2:16b'):
        self.model_name = model_name

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        try:
            logger.info(f"Generating with model {self.model_name}...")
            response = ollama.chat(
                model=self.model_name,
                messages=[
                    {'role': 'system', 'content': system_prompt},
                    {'role': 'user', 'content': user_prompt},
                ],
            )
            content = response.get('message', {}).get('content', "") or ""
            return content.strip()
        except Exception as e:
            logger.error(f"Error communicating with Ollama: {e}")
            return ""
