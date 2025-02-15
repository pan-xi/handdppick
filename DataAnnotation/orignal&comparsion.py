import difflib
import json
from typing import Dict, List
import ast

def normalize_code(code: str) -> str:
    """统一代码格式以便比较"""
    # 1. 去除多余空白和换行
    code = '\n'.join([line.strip() for line in code.splitlines() if line.strip()])
    # 2. 统一字符串引号（可选）
    # code = code.replace("'", "\"")  # 如果修复代码可能修改引号风格
    
    return code

def extract_repaired_codes(repaired_entry) -> List[str]:
    """解析不同格式的repaired_code"""
    codes = []
    
    print(f"Type of repaired_entry: {type(repaired_entry)}")
    print(f"Value of repaired_entry: {repaired_entry}")
    
    if isinstance(repaired_entry, list):
        # 处理JSON数组格式（如 [{'repair_code': ...}, ...]）
        for item in repaired_entry:
            if 'repair_code' in item:
                code = item['repair_code'].strip()
                if code.startswith('```'):  # 去除代码块标记
                    code = '\n'.join(code.split('\n')[1:-1])
                codes.append(code)
    elif isinstance(repaired_entry, str):
        # 处理纯字符串格式
        if repaired_entry.startswith('['):  # 可能是未解析的JSON字符串
            try:
                codes.extend(extract_repaired_codes(json.loads(repaired_entry)))
            except Exception as e:
                print(f"Exception during JSON parsing: {e}")
                codes.append(repaired_entry)
        else:
            codes.append(repaired_entry)
    elif isinstance(repaired_entry, dict):
        # 增加处理字典类型的逻辑（如果字典中有'repair_code'键）
        for key,value in repaired_entry.items():
            if value == None:
                continue
            # print(f"key: {key}")
            

            try:
                json_string = value.replace("```json", "").replace("```", "").strip()
                data = json.loads(json_string)
                codes.append(data[0])
            except:
                try:
                    value = value.replace("```json", "").replace('```javascript', '').replace("```", "").strip()
                    data = ast.literal_eval(value)
                    codes.append(data[0]['repair_code'])
                except Exception as e:
                    print(f"Exception during JSON parsing: {e}")
            
            # codes.append({"repair_code": repair_code.strip(), "repair_method": repair_method})
    else:
        print("传入的repaired_entry数据类型不符合预期。")
    
    print(f"Extracted codes: {codes}")
    
    return codes

def validate_repair(original: str, repaired: str, fixed: str) -> Dict:
    """验证修复完整性"""
    # 标准化代码
    original_norm = normalize_code(original)
    repaired_norm = normalize_code(repaired)
    fixed_norm = normalize_code(fixed)
    
    # 比较差异
    diff_fixed = list(difflib.unified_diff(
        original_norm.splitlines(),
        fixed_norm.splitlines(),
        fromfile='original',
        tofile='fixed'
    ))
    
    diff_repaired = list(difflib.unified_diff(
        original_norm.splitlines(),
        repaired_norm.splitlines(),
        fromfile='original',
        tofile='repaired'
    ))
    
    # 关键指标
    required_changes = [line for line in diff_fixed if line.startswith('+') or line.startswith('-')]
    actual_changes = [line for line in diff_repaired if line.startswith('+') or line.startswith('-')]
    
    # 计算修复覆盖率
    covered = 0
    missing_changes = []
    for req in required_changes:
        if req in actual_changes:
            covered += 1
        else:
            missing_changes.append(req)
    
    return {
        "coverage": covered / len(required_changes) if required_changes else 1.0,
        "missing_changes": missing_changes,
        "extra_changes": [chg for chg in actual_changes if chg not in required_changes]
    }

def process_item(item: Dict) -> Dict:
    """处理单个数据条目"""
    results = []
    
    # 提取所有修复方案
    repaired_codes = extract_repaired_codes(item.get('repaired_code', []))
    
    for i, repaired_code in enumerate(repaired_codes):
        result = {
            "repair_id": f"repair_{i+1}",
            "validation": validate_repair(
                item['question'],
                repaired_code,
                item['fixed_code']
            )
        }
        results.append(result)
    
    return {
        "question_id": item.get("source", "unknown"),
        "repair_results": results
    }

if __name__ == "__main__":
    with open('./small_sample_output_dir/With_Original_Code/Task3/split0_output_deepseek-chat_voted_five_models_with_code.json') as f:
        data = json.load(f)
    
    report = []
    for item in data:
        report.append(process_item(item))
    
    # 保存检测报告
    with open('repair_validation_report.json', 'w') as f:
        json.dump(report, f, indent=2)