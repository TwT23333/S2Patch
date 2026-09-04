

import os
import threading
import time
from tqdm import tqdm
import concurrent.futures
from google import genai
import google.generativeai as genai_google

thread_lock = threading.Lock()


max_threads = 64


def load_Gemini_model(model_name: str):


    return None, model_name


def get_gemini_api_key(model_config: dict) -> str:
    api_key = model_config.get("api_key")
    if api_key:
        return api_key

    api_key_from_env = os.getenv("GEMINI_API_KEY")
    if api_key_from_env:
        return api_key_from_env

    raise ValueError(
        "Gemini API key not found in model_config (key: 'api_key') "
        "or environment variable ('GEMINI_API_KEY'). Please ensure it is set."
    )

def generate_with_Gemini_model(
    prompt: str,
    model_config: dict,
    n: int = 1,
    max_tokens: int = 8192,
    temperature: float = 0.5,
    top_p: float = 0.95,

    top_k: Optional[int] = None
):
    model_name = model_config.get("model_name")
    if not model_name:
        raise ValueError("model_config must contain 'model_name' for Gemini.")

    api_key = get_gemini_api_key(model_config)


    genai_google.configure(api_key=api_key)


    generation_config_params = {
        "candidate_count": n,
        "max_output_tokens": model_config.get("max_tokens", max_tokens),
        "temperature": model_config.get("temperature", temperature),
        "top_p": model_config.get("top_p", top_p),
    }
    if model_config.get("top_k", top_k) is not None:
        generation_config_params["top_k"] = model_config.get("top_k", top_k)


    generation_config = genai_google.types.GenerationConfig(**generation_config_params)


    safety_settings = model_config.get("safety_settings", None)


    try:
        model_instance = genai_google.GenerativeModel(
            model_name=model_name,
            generation_config=generation_config,
            safety_settings=safety_settings
        )
    except Exception as e:
        print(f"Error initializing Gemini model '{model_name}': {e}")
        return []


    ans_texts, timeout_val = [], 5
    max_retries = 5
    current_retry = 0

    while not ans_texts and current_retry < max_retries:
        try:

            response = model_instance.generate_content(contents=prompt)


            if response.candidates:
                ans_texts = [candidate.content.parts[0].text for candidate in response.candidates if candidate.content and candidate.content.parts]
            else:
                if response.prompt_feedback and response.prompt_feedback.block_reason:
                    print(f"Gemini content generation blocked for model '{model_name}'. Reason: {response.prompt_feedback.block_reason_message or response.prompt_feedback.block_reason}")
                    return []
                else:
                    print(f"Gemini response for model '{model_name}' had no candidates. Full response: {response}")

            if ans_texts and ans_texts[0]:
                 break

        except Exception as e:
            current_retry += 1
            print(f"Gemini API call error for model '{model_name}': {e}. Retry {current_retry}/{max_retries}.")
            if not ans_texts or not ans_texts[0]:
                if current_retry >= max_retries:
                    print(f"Max retries reached for Gemini model {model_name}. Returning empty response.")
                    return []

                time.sleep(timeout_val)
                timeout_val = min(timeout_val * 2, 60)

                try:
                    print(f"Retrying Gemini ({current_retry}/{max_retries}) for model {model_name}. Will retry in {timeout_val} seconds...")
                except:
                    pass
            else:
                break

    if not ans_texts:
        print(f"Failed to get a response from Gemini model {model_name} after {max_retries} retries.")
        return []

    return ans_texts


def generate_n_with_Gemini_model(
    prompt: str,
    model_config: dict,
    n: int = 1,
    max_tokens: int = 8192,
    temperature: float = 0.5,
    top_k: Optional[int] = None,
    top_p: float = 0.95,


):

    preds = generate_with_Gemini_model(
        prompt, model_config, n, max_tokens, temperature, top_p, top_k
    )
    return preds


def generate_prompts_with_Gemini_model(
    prompts: list,
    model_config: dict,
    n: int = 1,
    max_tokens: int = 8192,
    temperature: float = 0.5,
    top_k: Optional[int] = None,
    top_p: float = 0.95,

    max_threads: int = 10,
    disable_tqdm: bool = True,
):
    preds = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=max_threads) as executor:
        futures = [

            executor.submit(
                generate_with_Gemini_model, prompt, model_config, n, max_tokens, temperature, top_p, top_k
            )
            for prompt in prompts
        ]
        for i, future in tqdm(
            enumerate(concurrent.futures.as_completed(futures)),
            total=len(futures),
            desc="running evaluate",
            disable=disable_tqdm,
        ):
            ans = future.result()
            preds.append(ans)
    return preds
