import json
import os
import time
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import re
import threading

# 设置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def save_failed_request(dataset_name, file_path, question, llm_model, api_collections, error_message):
    """将失败的请求信息保存到 JSON 文件中"""
    simplified_api_info = {
        model: {
            'api_url': info['api_url'],
            'api_key': info['api_key']
        } for model, info in api_collections.items()
    }
    
    failed_data = {
        'dataset_name': dataset_name,
        'file_path': file_path,
        'question': question,
        'llm_model': llm_model,
        'error_message': error_message,
        'api_collections': simplified_api_info  # 使用简化版的 api 信息
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

    rate_limiter = api_collections[llm_model].get('rate_limiter')
    if rate_limiter:
        rate_limiter.wait(api_key)
    
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

def analyze_code_with_llm(llm_model, original_code,fixed_code,function_description,function_description_voted_answer, vulnerability_analysis, api_collections, dataset_name, file_path):
    """使用 LLM 分析代码"""
    system_prompt_list = [
        """
        Role: 软件开发老师

        Profile
        description: 分析学生提交的作业答案，学生答案由两轮回答组成，分别是函数功能描述和CWE缺陷类型描述，找出以下几位学生答案中最不一致的答案。

        Skills
        - 语义差异识别
        - 代码分析
        - 软件缺陷检测
        - 教学指导

        Constraints
        - 以下是一些学生的作业答案，这些作业答案是根据缺陷类型的CWE预测，请直接根据学生的答案进行判断。

        Workflows
        - 分析学生提交的作业答案。
        - 对比每个学生答案中的函数功能描述或CWE类型。
        - 运用语义差异识别能力、代码知识和软件缺陷检测能力，找出以下几位学生答案中最不一致的答案。
        """
        # 待改
        ,"""
        Role: 软件开发老师

        Profile Description: 你是一位经验丰富的软件开发老师，任务是分析学生对同一段有缺陷代码的CWE类型判断，并找出其中最不恰当的答案。其中，修改后的代码只是参考答案，它对应的缺陷代表了学生应该掌握及检测的基本漏洞，学生的作业会表现更出色，寻找出更多漏洞。你需要判断哪个学生的修复方案未能有效检测出基本漏洞或者与其他同学差异最大，即与实际情况偏差最大，最不准确或最不相关的答案。


        Skills:
        - 代码分析
        - 软件缺陷识别 (CWE)
        - 教学评估
        - 语义差异识别

        Constraints:
        - 你将会收到一段有缺陷的原始代码、一段修复后的代码以及多个学生对原始代码中存在的CWE类型的判断。
        - 你的任务是评估学生对CWE类型判断的准确性。
        - 请根据原始代码、修复后的代码以及通用的CWE定义来判断学生的答案。

        Workflows:
        - 仔细阅读原始的有缺陷代码和修复后的代码，理解代码的功能和修复前后的差异。
        - 逐一审查每个学生对原始代码中存在的CWE类型的判断。
        - 运用你的代码分析能力和软件缺陷预测知识，判断每个学生答案的合理性和准确性 。
        - 对比所有学生的答案，找出对CWE类型判断最不恰当、最不准确或与实际情况偏差最大的一个或多个答案。
        - 在整个分析过程中，保持中立和客观，确保对每个学生答案的评估都是公平和一致的。
        """
    ]

    # 步骤 1: 理解代码功能
    history = [
        {"role": "user", "content": f"现在判断第一轮学生关于函数功能的描述，请你先阅读五位学生提供的作业答案，请你选出来最多一个最不一致的答案，在你的回复中你需要先简要分析四位学生的答案，你的答案从A、B、C、D、E、None中选择，其中None表示四位同学的答案基本一致。你的回复以”所以我的答案是：！”结尾，如“所以我的答案是：A！”以下是四位同学关于同一段代码函数功能的描述：\n{function_description}"}
    ]
    prompt = [{"role": "system", "content": system_prompt_list[0]}] + history
    # function_description_voted_answer = get_answer_from_llm(llm_model, prompt, api_collections, dataset_name, file_path)
    answer = re.search(r'所以我的答案是：(None|\w)', function_description_voted_answer)
    if answer:
        extracted_answer = answer.group(1)  # 获取匹配的答案 (A/B/C/D/None)
    else:
        extracted_answer = None
        logging.warning("未能找到预期格式的答案")
    info = ""
    if extracted_answer == 'None':
        info = "四位同学的答案基本一致"
        rest_answer = ['A','B','C','D','E']

    else:
        info = f"排除{extracted_answer}同学的答案"
        rest_answer = ['A','B','C','D','E']
        try:
            rest_answer.remove(extracted_answer)
            vulnerability_analysis.pop(extracted_answer,None)
        except Exception as e:
            logging.error(f"{extracted_answer} is not in rest_answer")
            extracted_answer = None
        
    if extracted_answer == None:
        info = '请你根据上文，判断四位同学的答案是否一致，”'
        rest_answer = ['A','B','C','D','E']
    


    # 步骤 2: 分析代码漏洞
    history.append({"role": "assistant", "content": f"{function_description_voted_answer}"})

    # Prompt待改
    analysis_prompt_temp = [
        {"role": "user", "content": f"""
            现在进行第二轮学生关于CWE类型描述，请结合第一轮的信息，阅读以下剩余学生对同一段有缺陷代码的CWE类型判断，你需要根据提供的原始代码、修复后的代码和学生们的CWE类型判断，找出最不恰当的一个或多个答案。{info}答案从{rest_answer}中进行选择。
            你需要对原始代码和修复后的代码进行简要分析，指出原始代码中的缺陷及修复后的变化。然后评估每个学生的CWE类型判断是否准确，并指出其合理性或不合理之处。再找出最不恰当的一个或多个答案，并在回复最后以特定格式给出你的最终选择。
            如果你认为只有一个答案最不恰当，请用 "所以，我的答案是：[选项字母]!" 的格式；如果有多个答案最不恰当，请用 "所以，我的答案是：[选项字母1],[选项字母2]...!" 的格式。例如："所以，我的答案是：A!" 或 "所以，我的答案是：A,B!"\n原始的有软件缺陷代码：{question}
            \n修复后的代码：{fixed_code}\n以下是五位学生对这段原始代码的CWE类型判断 (请注意，A-E是学生的编号，冒号后是学生的答案):{vulnerability_analysis}
        """}
    ]
    history.extend(analysis_prompt_temp)
    prompt = [{"role": "system", "content": system_prompt_list[1]}] + history

    vulnerability_analysis_voted_answer = get_answer_from_llm(llm_model, prompt, api_collections, dataset_name, file_path)
    if not vulnerability_analysis_voted_answer:
        return None

    return vulnerability_analysis_voted_answer

def process_single_record(args):
    """处理单个记录"""
    llm_model, record, api_collections, dataset_name, file_path = args
    function_description = record['function_description']
    code = record['question']
    repair_code = record['repaired_code']
    vulnerability_analysis = record['vulnerability_analysis']
    function_description_voted_answer = record['function_description_voted_answer']
    fixed_code = record['fixed_code']
    vulnerability_analysis_voted_answer_with_code = analyze_code_with_llm(
        llm_model, code,fixed_code,function_description,function_description_voted_answer, vulnerability_analysis, api_collections, dataset_name, file_path
    )
    return {
        'question': code,
        'function_description': function_description,
        'vulnerability_analysis': record['vulnerability_analysis'],
        'repaired_code': repair_code,
        'function_description_voted_answer': function_description_voted_answer,
        'vulnerability_analysis_voted_answer': record['vulnerability_analysis_voted_answer'],
        'vulnerability_analysis_voted_answer_with_code': vulnerability_analysis_voted_answer_with_code,
        'llm_model': llm_model,
        'source': record['source']
    }

def process_batch_records(batch, llm_model, api_collections, dataset_name, file_path):
    """处理一组记录，并行发送API请求"""
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
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
# def process_batch_records(batch, llm_model, api_collections, dataset_name, file_path):
#     """处理一组记录"""
#     results = []
#     # 直接串行处理每个记录，不使用内层线程池
#     for record in tqdm(batch, desc=f"Processing batch"):
#         try:
#             result = process_single_record((llm_model, record, api_collections, dataset_name, file_path))
#             results.append(result)
#         except Exception as e:
#             logging.error(f"Error processing record: {e}")
#             results.append({'error': str(e)})
#         time.sleep(0.5)
#     return results



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


class RateLimiter:
    def __init__(self, requests_per_minute):
        self.requests_per_minute = requests_per_minute
        self.interval = 60.0 / requests_per_minute
        self.last_request = {}
        self.lock = threading.Lock()

    def wait(self, api_key):
        with self.lock:
            current_time = time.time()
            if api_key in self.last_request:
                time_since_last = current_time - self.last_request[api_key]
                if time_since_last < self.interval:
                    time.sleep(self.interval - time_since_last)
            self.last_request[api_key] = time.time()

def main():
    """主函数"""
    input_file = './small_sample_output_dir/split0_output_summary_voted_processed_five_models_deepseek-chat_voted_five_models_new.json'
    llm_model = 'gpt-4o'
    # 获取input_file的文件名
    input_file_name = os.path.basename(input_file).replace('.json','')
    # 拼上模型名字
    output_file = (
        f"./small_sample_output_dir/"
        f"{input_file_name}_{llm_model.replace('/', '-')}_with_code.json"
    )
    if os.path.exists(output_file):
        # 在outputfile文件名后加上当前时间
        output_file = f"{output_file.replace('.json','')}_{time.strftime('%Y%m%d%H%M%S')}.json"
    # output_file = f'./small_sample_output_dir/{input_file_name}'
    # output_file = './small_sample_output_dir/split1_output_gemini-exp-1206.json'  
    split_size = 20

    api_collections = {
        'deepseek-chat': {
            'api_url': '',
            'api_key': '',
        },
        'gpt-4o':{
            'api_url': '',
            'api_key': '',
        },
        'claude-3-5-sonnet-20241022': {
            'api_url': '',
            'api_key': ''
        },
        'gemini-1.5-pro-latest':{
            'api_url': '',
            'api_key': ''
        },
        'o1-mini':{
            'api_url':'',
            'api_key':'',
            'rate_limiter': RateLimiter(requests_per_minute=2)
        },
        'Qwen/Qwen2.5-72B-Instruct-128K':{
            'api_url':'',
            'api_key':''
        },
        'qwen-max':{
            'api_url':'',
            'api_key':'',
            'rate_limiter': RateLimiter(requests_per_minute=100)
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

    # 先将batches保存至磁盘中，防止中途断开
    os.makedirs('./batches',exist_ok=True)
    for i,batch in enumerate(batches):
        with open(f'./batches/{input_file_name}_batches_{i}.json','w') as f:
            json.dump(batch,f,ensure_ascii=False,indent=4)

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
                # logging.info(f"Batch processed and saved. Batch size: {len(batch)}")
            except Exception as e:
                logging.error(f"Error processing batch: {e}")
                time.sleep(2)
if __name__ == '__main__':
    main()