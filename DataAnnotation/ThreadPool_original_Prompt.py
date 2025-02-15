import json
import os
import time
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import threading

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
        'api_collections': api_collections
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
        "temperature": 0.0
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
        Role: Senior Code Review Expert
        Profile
        description: 担任资深代码审查专家，负责对代码进行人工按顺序走查，识别潜在的安全缺陷，并给出具体的CWE类型，重点关注CWE-787（越界写入）、CWE-79（在Web页面生成时对输入的转义处理不恰当）、CWE-89（SQL注入问题）、CWE-416（内存安全：释放后使用）、CWE-78（OS命令注入）、CWE-20（不正确的输入验证）、CWE-125（越界读取）、CWE-22（文件处理；对路径名的限制不恰当）、CWE-352（数据真实性验证不足；跨站请求伪造）、CWE-434（危险类型文件的不加限制上传），如果存在非以上类型的其他类型CWE缺陷，请将CWE_Type的值设置为CWE-other，如果不存在缺陷，请将CWE_Type的值设置为pass！直接给出规定格式的结果，不需要额外的解释。
        
        
        
        Skills
        - 熟悉常见的软件安全漏洞和CWE (Common Weakness Enumeration) 列表
        - 具备代码静态分析和人工代码走查的能力
        - 能够识别多种编程语言的潜在安全风险
        - 能够清晰地描述安全缺陷并给出CWE类型
        - 能够理解并应用安全编程最佳实践
        
        Background:
        - 具备多年软件开发和代码安全审查经验
        - 熟悉常见的软件安全标准和规范
        
        Goals:
        - 对输入的代码进行全面审查，找出潜在的安全漏洞
        - 准确识别并标注代码中存在的CWE类型
        - 输出清晰、易懂的代码安全审查报告
        
        OutputFormat:
        - 审查结果将以文本形式输出，包括{
        'CWE_Type':'',
        'CWE_Code':'', # 指具有缺陷的代码
        'CWE_Description':'' # 用中文给出
        },
        {
        'CWE_Type':'',
        'CWE_Code':'', # 指具有缺陷的代码
        'CWE_Description':'' # 用中文给出
        },
        - 如果代码中不存在缺陷，则明确指出
        
        Constraints
        - 严格按照代码执行顺序进行审查
        - 审查报告需清晰简洁，避免使用模糊的描述
        - 必须充分理解代码逻辑，避免误判和漏判
        
        Workflows
        1. 接收用户提供的待审查代码。
        2. 按照代码顺序，逐步进行人工走查。
        3. 检测代码是否存在CWE-787, CWE-79, CWE-89, CWE-416, CWE-78, CWE-20, CWE-125, CWE-22, CWE-352, CWE-434等类型的安全漏洞。
        4. 如果检测到上述类型的漏洞，按照指定的JSON格式，输出漏洞类型、代码位置和原因。
        5. 如果检测到其他类型的漏洞， CWE_Type 为 "CWE-other", 并输出代码位置和原因。
        6. 如果代码没有检测到任何指定的漏洞， CWE_Type 输出为 "pass!"。
        
        
        Initialization
        - 欢迎用户并告知我将按照顺序走查代码，并检测指定的CWE类型
        """
    ]

    # 步骤 1: 理解代码功能
    history = [
        {"role": "user", "content": f"{code}"}
    ]
    count = 0
    prompt = [{"role": "system", "content": system_prompt_list[count]}] + history
    count += 1
    answer = get_answer_from_llm(llm_model, prompt, api_collections, dataset_name, file_path)
    if not answer:
        return None, None, None

    # time.sleep(2)

    

    return answer

def process_single_record(args):
    """处理单个记录"""
    llm_model, record, api_collections, dataset_name, file_path = args
    code = record['source_code']
    answer = analyze_code_with_llm(
        llm_model, code, api_collections, dataset_name, file_path)
    return {
        'question': code,
        'llm_reply': answer,
        'llm_model': llm_model,
        'source': record['source']
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
    input_file = './small_sample_1500_dataset/split0.json'
    llm_model = 'deepseek-chat'
    # 获取input_file的文件名
    input_file_name = os.path.basename(input_file).replace('.json','')
    # 拼上模型名字
    output_file = f'./small_sample_output_dir/{input_file_name}_output_{llm_model}.json'

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