import ast
import json
import re
import difflib
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def before_process_data(data: str) -> str:
    """
    清理和预处理代码字符串，包括去除注释、多余空白和无用的标记。
    """
    # 移除类似 JS 的注释
    cleaned_string = re.sub(r'//.*', '', data)
    # 移除类似 JS 的字符串拼接符号
    cleaned_string = re.sub(r"\s*'\s*\+\s*'\s*", '', cleaned_string)
    # 替换标记和其他格式处理
    cleaned_string = (
        cleaned_string.replace("```json", "")
        .replace("```", "")
        .replace("```javascript", "")
        .replace("```python", "")
        .replace("```cpp", "")
        .strip()
    )
    # 替换单引号为双引号，确保是有效的 JSON 格式
    cleaned_string = cleaned_string.replace("'", '"')
    return cleaned_string


def calculate_code_diff(original_code: str, repaired_code: str) -> dict:
    """
    使用 difflib 计算代码差异，并抽取添加和删除的代码行。
    """
    # 标准化代码（去掉多余的空白行）
    original_norm = normalize_code(original_code)
    repaired_norm = normalize_code(repaired_code)

    # 使用 difflib 获取统一格式的差异
    diff = list(
        difflib.unified_diff(
            original_norm.splitlines(),
            repaired_norm.splitlines(),
            lineterm=""
        )
    )
    # 提取新增和删除的行
    added_lines = [line[1:] for line in diff if line.startswith('+') and not line.startswith('+++')]
    removed_lines = [line[1:] for line in diff if line.startswith('-') and not line.startswith('---')]

    return {
        "added_lines": added_lines,
        "removed_lines": removed_lines,
        "diff_details": diff
    }


def normalize_code(code: str) -> str:
    """
    代码标准化处理，移除无意义的空行和多余的空格。
    """
    return '\n'.join(line.strip() for line in code.splitlines() if line.strip())


def process_file(input_file: str, output_file: str):
    """
    读取 JSON 文件，处理修复代码并计算差异，保存结果到新文件中。
    """
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        logging.error(f"找不到输入文件：{input_file}")
        return
    except json.JSONDecodeError as e:
        logging.error(f"解析 JSON 文件失败：{input_file}, 错误信息: {e}")
        return

    # 存储处理结果
    reparied_codes_results = []

    # 逐条处理数据
    for item in data:
        repaired_code_entries = item.get('repaired_code', {})
        original_code = item.get('question', "")
        fixed_code = item.get('fixed_code', "")

        logging.info(f"正在处理问题 ID: {item.get('source', '未知')}")

        for key, code in repaired_code_entries.items():
            if code is None:
                repaired_code = ""  # 修复代码为空
            else:
                try:
                    # 预处理和解析修复代码
                    processed_data = before_process_data(code)
                    repaired_list = ast.literal_eval(processed_data)

                    # 确保修复代码符合预期结构
                    if isinstance(repaired_list, list) and len(repaired_list) > 0 and 'repair_code' in repaired_list[0]:
                        repaired_code = repaired_list[0]['repair_code']
                    else:
                        logging.warning(f"修复代码结构异常，跳过: {processed_data}")
                        repaired_code = ""

                except (ValueError, SyntaxError) as e:
                    logging.error(f"解析修复代码失败！Key: {key}，Content: {code}，Error: {e}")
                    continue

            # 如果修复代码存在，则计算差异
            if repaired_code:
                diff_result = calculate_code_diff(original_code, repaired_code)
                reparied_codes_results.append({
                    "key": key,
                    "diff": diff_result
                })

    # 保存结果到文件
    try:
        with open(output_file, 'w') as f:
            json.dump(reparied_codes_results, f, ensure_ascii=False, indent=2)
        logging.info(f"处理完成，结果保存至文件：{output_file}")
    except Exception as e:
        logging.error(f"保存结果到文件失败：{output_file}, 错误信息: {e}")


if __name__ == "__main__":
    input_file = './small_sample_output_dir/With_Original_Code/Task3/split0_output_deepseek-chat_voted_five_models_with_code.json'
    output_file = 'repair_validation_report.json'
    process_file(input_file, output_file)