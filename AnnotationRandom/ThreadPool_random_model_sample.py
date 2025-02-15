import json
import os
import time
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import threading
import random

# 设置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def save_failed_request(dataset_name, file_path, question, llm_model, api_collections, error_message):
    """将失败的请求信息保存到 JSON 文件中"""
    failed_data = {
        'dataset_name': dataset_name,
        'file_path': file_path,
        'question': question,
        'llm_model': llm_model,
        'error_message': error_message,
        # 'api_collections': api_collections
    }
    timestamp = str(int(time.time()))
    filename = f"failed_requests_{dataset_name}_{timestamp}.json"
    failed_dir = "./failed_requests"
    os.makedirs(failed_dir, exist_ok=True)
    file_path = os.path.join(failed_dir, filename)
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(failed_data, f, ensure_ascii=False, indent=4)
    except IOError as e:
        logging.error(f"Error writing failed request to file {file_path}: {e}")

def get_answer_from_llm(llm_model, messages, api_collections, dataset_name=None, file_path=None, retry_count=3, retry_delay=1):
    """获取 LLM 的答案，并添加重试机制和速率控制"""
    api_key = api_collections[llm_model]['api_key']
    api_url = api_collections[llm_model]['api_url']
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }
    data = {
        "model": llm_model,
        "messages": messages,
        "temperature": 0.00
    }

    for attempt in range(retry_count):
        try:
            response = requests.post(api_url, headers=headers, json=data, stream=True)
            response.raise_for_status()
            response_json = response.json()
            if 'choices' in response_json and response_json['choices']:
                return response_json['choices'][0]['message']['content']
            else:
                logging.warning(f"Unexpected response structure: {response_json}")
                return ""
        except requests.exceptions.RequestException as e:
            logging.warning(f"Attempt {attempt + 1} for {llm_model} failed: {e}")
            if attempt < retry_count - 1:
                logging.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                logging.error(f"API request failed after {retry_count} attempts: {e}")
                if dataset_name and file_path:
                    save_failed_request(dataset_name, file_path, str(messages), llm_model, api_collections, str(e))
                return ""
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON response: {e}")
            if dataset_name and file_path:
                save_failed_request(dataset_name, file_path, str(messages), llm_model, api_collections, str(e))
            return ""

def analyze_code_with_llm(llm_model, code, api_collections, dataset_name, file_path):
    """使用 LLM 分析代码"""
    system_prompt_list = [
        """
        Role: 高级代码审查专家
        Profile
        description: 担任资深代码审查专家，负责对代码进行人工按顺序走查，识别潜在的安全缺陷，
        并给出具体的CWE类型，直接给出规定格式的结果，不需要额外的解释。
        """,
        """
        Role: 高级代码审查专家
        Profile
        description: 担任资深代码审查专家，负责对代码进行人工按顺序走查，识别潜在的安全缺陷，
        并给出具体的CWE类型，直接给出规定格式的结果，不需要额外的解释。

        Skills
        - 熟悉常见的软件安全漏洞和CWE (Common Weakness Enumeration) 列表
        - 具备代码静态分析和人工代码走查的能力
        - 能够识别多种编程语言的潜在安全风险
        - 能够清晰地描述安全缺陷并给出CWE类型
        - 能够理解并应用安全编程最佳实践

        Background:
        - 具备多年软件开发和代码安全审查经验
        - 熟悉常见的软件安全标准和规范

        Constraints
        - 严格按照代码执行顺序进行审查
        - 审查报告需清晰简洁，避免使用模糊的描述
        - 必须充分理解代码逻辑，避免误判和漏判
        """,
        """
        Role: 资深的代码修复专家

        Profile
        - description: 你是一名资深的代码修复专家，你需要根据上文提供的代码、代码功能以及代码缺陷CWE类型，对代码中存在的CWE类型进行修复。

        Skills

        - 精通各种编程语言，包括但不限于C/C++、Java、Python、JavaScript等。
        - 深入理解各种常见的代码缺陷类型（CWE），并能准确识别代码中存在的安全漏洞。
        - 能够根据代码功能、上下文和CWE类型，提出有效的代码修复方案。
        - 能够清晰地解释代码缺陷产生的原因和修复方案的原理。
        - 能够编写高质量、安全的代码，并进行充分的测试验证。

        Goals

        - 准确识别并修复代码中存在的指定CWE类型的缺陷。
        - 确保修复后的代码能够正常实现原有功能。
        - 提供清晰的修复说明和建议，帮助开发者理解并避免类似问题。

        Constraints

        - 修复方案必须针对指定的CWE类型。
        - 修复后的代码必须保持原有的编程语言和代码风格。
        - 必须清晰解释修复思路和原理。
        """
    ]

    # 步骤 1: 理解代码功能
    history = [
        {"role": "user", "content": f"请仔细阅读以下代码，请用不超过三十个字来描述这段代码的功能:\n{code}"}
    ]
    count = 0
    prompt = [{"role": "system", "content": system_prompt_list[count]}] + history
    # 50%的概率使用gpt-4o，50%的概率使用deepseek-chat
    if random.random() < 0.5:
        llm_model_first_step = 'gpt-4o'
    else:
        llm_model_first_step = 'deepseek-chat'
    count += 1
    function_description = get_answer_from_llm(llm_model_first_step, prompt, api_collections, dataset_name, file_path)
    if not function_description:
        return None, None, None, llm_model_first_step, None, None

    # time.sleep(2)

    # 步骤 2: 分析代码漏洞
    history.append({"role": "assistant", "content": f"{function_description}"})

    analysis_prompt_temp = [
        {"role": "user", "content": f"""请根据上述代码及信息，是否存在任何潜在的软件漏洞或缺陷？如果有，请详细描述漏洞的成因，并尝试指出可能的CWE类型（CWE Top10CWE-other），缺陷原因，产生缺陷的代码【可能存在多行代码】，CWE-Top10解释如下：重点关注以及CWE-787（越界写入）、CWE-79（在Web页面生成时对输入的转义处理不恰当）、CWE-89（SQL注入问题）、CWE-416（内存安全：释放后使用）、CWE-78（OS命令注入）、CWE-20（不正确的输入验证）、CWE-125（越界读取）、CWE-22（文件处理；对路径名的限制不恰当）、CWE-352（数据真实性验证不足；跨站请求伪造）、CWE-434（危险类型文件的不加限制上传）。
        请按照如下格式给出答案：
        如果代码中不存在缺陷，则输出：{{'CWE_Type':'pass!'}}\n
        如果代码中存在缺陷，则输出：\n
        [
           {{'CWE_Type':''# 指CWE类型, 'CWE_Code':''# 指具有缺陷的代码, 'CWE_Description':''# 中文解释}},\n
           {{'CWE_Type':''# 指CWE类型, 'CWE_Code':''# 指具有缺陷的代码, 'CWE_Description':''# 中文解释}}
        ]"""
        }
    ]
    history.extend(analysis_prompt_temp)
    prompt = [{"role": "system", "content": system_prompt_list[count]}] + history
    count += 1
    # 40%的概率使用gpt-4o，30%的概率使用deepseek-chat，30%的概率使用claude-3-5-sonnet-20241022
    if random.random() < 0.4:
        llm_model_second_step = 'gpt-4o'
    elif random.random() < 0.7:
        llm_model_second_step = 'deepseek-chat'
    else:
        llm_model_second_step = 'claude-3-5-sonnet-20241022'
    vulnerability_analysis = get_answer_from_llm(llm_model_second_step, prompt, api_collections, dataset_name, file_path)
    if not vulnerability_analysis or "{'CWE_Type':'pass!'}" in vulnerability_analysis:
        return function_description, vulnerability_analysis, None, llm_model_first_step, llm_model_second_step, None
    
    # time.sleep(2)

    # 步骤 3: 修复代码
    history.append({'role': 'assistant', 'content': f'{vulnerability_analysis}'})

    repair_prompt_temp = [
        {"role": "user", "content": f"""
        基于以上的代码漏洞分析和代码，给出修改之后的代码（主要是完整代码），并给出简要的修复方法(指你是如何修复的)，不需要再进行额外的解释。
        请你按照如下格式给出答案：
        [
            {{'repair_code':'',  # 修复后完整的代码
            'repair_method':'' # 中文解释
            }},\n
        ]
        """}
    ]
    history.extend(repair_prompt_temp)
    prompt = [{"role": "system", "content": system_prompt_list[count]}] + history
    # 25%的概率使用gpt-4o，25%的概率使用deepseek-chat，25%的概率使用claude-3-5-sonnet-20241022，25%的概率使用gemini-1.5-pro-latest
    if random.random() < 0.25:
        llm_model_third_step = 'gpt-4o'
    elif random.random() < 0.5:
        llm_model_third_step = 'deepseek-chat'
    elif random.random() < 0.75:
        llm_model_third_step = 'claude-3-5-sonnet-20241022'
    else:
        llm_model_third_step = 'gemini-1.5-pro-latest'
    repaired_code = get_answer_from_llm(llm_model_third_step, prompt, api_collections, dataset_name, file_path)
    if not repaired_code:
        return function_description, vulnerability_analysis, None, llm_model_first_step, llm_model_second_step, llm_model_third_step
    
    # time.sleep(2)

    return function_description, vulnerability_analysis, repaired_code, llm_model_first_step, llm_model_second_step, llm_model_third_step

def process_single_record(args):
    """处理单个记录"""
    llm_model, record, api_collections, dataset_name, file_path   = args
    code = record['source_code']
    function_description, vulnerability_analysis, repaired_code, llm_model_first_step, llm_model_second_step, llm_model_third_step = analyze_code_with_llm(
        llm_model, code, api_collections, dataset_name, file_path)
    return {
        'question': code,
        'function_description': function_description,
        'vulnerability_analysis': vulnerability_analysis,
        'repaired_code': repaired_code,
        'llm_model_first_step': llm_model_first_step,
        'llm_model_second_step': llm_model_second_step,
        'llm_model_third_step': llm_model_third_step,
        'source': record['source'], 
    }

def process_batch_records(batch, llm_model, api_collections, dataset_name, file_path):
    """处理一组记录"""
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [
            executor.submit(process_single_record, (llm_model, record, api_collections, dataset_name, file_path))
            for record in batch
        ]
        for future in tqdm(as_completed(futures), total=len(futures), desc=f"Processing batch"):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                logging.error(f"Error processing record: {e}")
                results.append({'error': str(e)})
    return results

def append_results_to_file(output_file, results, lock):
    """将结果追加到输出文件中"""
    with lock:
        if not os.path.exists(output_file):
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=4)
        else:
            try:
                with open(output_file, 'r+', encoding='utf-8') as f:
                    existing_data = json.load(f)
                    existing_data.extend(results)
                    f.seek(0)
                    json.dump(existing_data, f, ensure_ascii=False, indent=4)
            except json.JSONDecodeError:
                logging.error(f"Invalid JSON format in {output_file}. Overwriting the file.")
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(results, f, ensure_ascii=False, indent=4)
            except Exception as e:
                logging.error(f"Error appending results to file {output_file}: {e}")

def main():
    """主函数"""
    input_file = './remaining_60.json'
    llm_model = 'deepseek-chat'
    # 获取input_file的文件名
    input_file_name = os.path.basename(input_file).replace('.json','')
    # 拼上模型名字
    output_file = f'./{input_file_name}_output_random_model_sample.json'
    split_size = 20

    api_collections = {
        'deepseek-chat':{
            'api_url': '',
            'api_key': ''
        },
        'gpt-4o':{
            'api_url': '',
            'api_key': ''
        },
        'claude-3-5-sonnet-20241022': {
            'api_url': '',
            'api_key': ''
        },
        'gemini-1.5-pro-latest':{
            'api_url': '',
            'api_key': ''
        },
        'yi-lightning':{
            'api_url':'',
            'api_key':''
        }
    }

    

    # 读取输入数据
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Error reading input file {input_file}: {e}")
        return

    # 拆分数据成每组20条
    batches = [data[i:i + split_size] for i in range(0, len(data), split_size)]

    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_batch = {
            executor.submit(process_batch_records, batch, llm_model, api_collections, 'Dataset_Name', input_file): batch
            for batch in batches
        }
        for future in tqdm(as_completed(future_to_batch), total=len(future_to_batch), desc="Processing all batches"):
            batch = future_to_batch[future]
            try:
                batch_result = future.result()
                append_results_to_file(output_file, batch_result, lock)
                logging.info(f"Batch processed and saved. Batch size: {len(batch)}")
            except Exception as e:
                logging.error(f"Error processing batch: {e}")

if __name__ == '__main__':
    main()