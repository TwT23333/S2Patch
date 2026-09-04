

import os
import os
import threading
import time
from tqdm import tqdm
import concurrent.futures
from openai import AzureOpenAI, OpenAI

thread_lock = threading.Lock()


max_threads = 10


def load_OpenAI_model(model):


    return None, model


def get_api_key_for_provider(provider_name: str, model_config: dict) -> str:
    api_key = model_config.get("api_key")
    if api_key:
        return api_key

    env_var_name = f"{provider_name.upper()}_API_KEY"
    api_key_from_env = os.getenv(env_var_name)
    if api_key_from_env:
        return api_key_from_env


    if provider_name.lower() == "openai" and os.getenv("OPENAI_API_KEY"):
        return os.getenv("OPENAI_API_KEY")

    if provider_name.lower() == "openrouter" and os.getenv("OPENROUTER_API_KEY"):
        return os.getenv("OPENROUTER_API_KEY")

    raise ValueError(
        f"API key for provider '{provider_name}' not found in model_config (key: 'api_key') "
        f"or environment variable ('{env_var_name}'). "
        f"Please ensure it is set."
    )

def generate_with_OpenAI_model(
    prompt,
    model_config: dict,
    n=1,
    max_tokens=512,
    temperature=0.5,
    top_p=0.95,


    stop=None,
):
    provider = model_config.get("provider", "openrouter").lower()
    model_name = model_config.get("model_name")

    if not model_name:
        raise ValueError("model_config must contain 'model_name'")

    api_key = get_api_key_for_provider(provider, model_config)

    client_instance = None

    if provider == "openrouter":
        base_url = model_config.get("base_url", "https://openrouter.ai/api/v1")
        client_instance = OpenAI(base_url=base_url, api_key=api_key)
    elif provider == "openai":
        base_url = model_config.get("base_url")
        client_instance = OpenAI(api_key=api_key, base_url=base_url if base_url else None)
    elif provider == "azure":
        azure_endpoint = model_config.get("azure_endpoint") or os.getenv("AZURE_OPENAI_ENDPOINT")
        api_version = model_config.get("azure_api_version") or os.getenv("AZURE_OPENAI_API_VERSION")
        if not azure_endpoint or not api_version:
            raise ValueError("For Azure provider, 'azure_endpoint' and 'azure_api_version' must be in model_config or env vars.")
        client_instance = AzureOpenAI(
            api_key=api_key,
            api_version=api_version,
            azure_endpoint=azure_endpoint
        )

    elif provider == "volcengine":
        base_url = model_config.get("base_url", "https://ark.cn-beijing.volces.com/api/v3")
        client_instance = OpenAI(api_key=api_key, base_url=base_url)
    else:
        raise ValueError(f"Unsupported provider: {provider}. Supported providers: openrouter, openai, azure, volcengine.")

    messages = [{"role": "user", "content": prompt}]
    parameters = {
        "model": model_name,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "top_p": top_p,
        "n": n,
    }

    if stop is not None:
        parameters["stop"] = stop

    ans, timeout = "", 5
    max_retries = 5
    current_retry = 0

    while not ans and current_retry < max_retries:
        try:

            completion = client_instance.chat.completions.create(messages=messages, **parameters)
            ans = [choice.message.content for choice in completion.choices]
            if ans and ans[0]:
                break
        except Exception as e:
            current_retry += 1
            print(f"API call error for provider '{provider}', model '{model_name}': {e}. Retry {current_retry}/{max_retries}.")
            if not ans or not ans[0]:
                if current_retry >= max_retries:
                    print(f"Max retries reached for model {model_name}. Returning empty response.")
                    return []


                time.sleep(timeout)
                timeout = min(timeout * 2, 60)

                try:
                    print(f"Retrying ({current_retry}/{max_retries})... Current response: {ans}")
                    print(f"Message length: {len(messages[0]['content'])}")
                    print(f"Will retry in {timeout} seconds...")
                except:
                    pass
            else:
                break

    if not ans:
        print(f"Failed to get a response from {model_name} after {max_retries} retries.")
        return []

    return ans


def generate_n_with_OpenAI_model(
    prompt,
    model_config: dict,
    n=1,
    max_tokens=512,
    temperature=0.8,

    top_p=0.95,
    stop=["\n"],


):

    preds = generate_with_OpenAI_model(prompt, model_config, n, max_tokens, temperature, top_p, stop)
    return preds

def generate_prompts_with_OpenAI_model(
    prompts: list,
    model_config: dict,
    n=1,
    max_tokens=512,
    temperature=0.8,

    top_p=0.95,
    stop=["\n"],
    max_threads=10,
    disable_tqdm=True,
):
    preds = []


    with concurrent.futures.ProcessPoolExecutor(max_workers=max_threads) as executor:
        futures = [

            executor.submit(generate_with_OpenAI_model, prompt, model_config, n, max_tokens, temperature, top_p, stop)
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
