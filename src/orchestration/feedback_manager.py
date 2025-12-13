
from pathlib import Path
from typing import Dict, Any
from src.core.config import POCS_DIR
from src.core.logger import get_logger
from src.generation.llm_client import LLMClient
from src.generation.prompt_builder import PromptBuilder
from src.generation.code_cleaner import sanitize_code_fences
from src.data.rag_repository import RagRepository
from src.data.memory_log import MemoryLog
from src.orchestration.executor import Executor

logger = get_logger(__name__)

class FeedbackManager:
    def __init__(self):
        self.llm = LLMClient()
        self.rag = RagRepository()
        self.memory = MemoryLog()
        self.prompt_builder = PromptBuilder()

    def run_feedback_loop(self, service_info: Dict[str, Any], target_cve: str, max_iters: int = 3):
        run_id = self.memory.start_run(
            service_info.get("ip"), 
            service_info.get("port"), 
            service_info.get("product"), 
            target_cve
        )
        
        # Retrieve Context
        context = self.rag.retrieve_context_for_service(service_info, target_cve)
        
        if context:
            logger.info(f"RAG Context retrieved. Length: {len(context)} chars")
            print(f"\n--- RAG CONTEXT PREVIEW ---\n{context[:500]}...\n---------------------------\n")
        else:
            logger.warning("No context found in RAG.")
            context = f"Generic context for {target_cve}"

        last_code = ""
        last_out, last_err = "", ""

        for i in range(1, max_iters + 1):
            logger.info(f"--- Attempt {i}/{max_iters} for {target_cve} ---")
            
            # Generate or Fix
            if i == 1:
                prompt_sys = "You are a security engineer."
                prompt_user = self.prompt_builder.build_verification_prompt(context, service_info)
            else:
                prompt_sys = "You are a security engineer fixing a script."
                prompt_user = self.prompt_builder.build_fix_prompt(context, last_code, last_out, last_err)
            
            # Call LLM
            code = self.llm.generate(prompt_sys, prompt_user)
            code = sanitize_code_fences(code)
            
            if not code:
                logger.error("LLM returned empty code.")
                break

            # Save
            filename = POCS_DIR / f"poc_{target_cve}_{run_id}_iter{i}.py"
            filename.write_text(code, encoding="utf-8")
            
            # Execute
            rc, out, err = Executor.run_poc(str(filename))
            last_code = code
            last_out = out
            last_err = err

            # Check Success
            if "POSSIBLE VULNERABILITY" in out or "VULNERABLE" in out:
                logger.info("SUCCESS: Vulnerability detected.")
                self.memory.finish_run(run_id, "success", f"Found at iter {i}")
                return True
            
            logger.info(f"Attempt failed. RC={rc}")
        
        self.memory.finish_run(run_id, "failed", "Max iterations reached")
        return False
