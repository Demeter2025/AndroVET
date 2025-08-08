"""
MOVERY Preprocessoir - Fixed Version.
Original Author: Seunghoon Woo (seunghoonwoo@korea.ac.kr)
Modified:   July 20, 2025.
Modification author: Esteban Luques (eluqu004@fiu.edu)
Fixed:      Memory optimization, Multiprocessing, Error handling improvements, Data corruption fixes for paralelization
Note: The credit for the development goes to the original author Seunghoon Woo, we only built on top of his ideas.  
"""
import tempfile
import os
import sys
currentPath = os.getcwd()
sys.path.append(currentPath + "/config/")
import subprocess
import re
import json
from hashlib import md5
from datetime import datetime
from tqdm import tqdm
import multiprocessing
import gc
import argparse

def walk_folder(folder):
    files0 = []
    for root, dirs, files in os.walk(folder, topdown = True):
        if len(files) > 0:
            for file in files:
                files0.append(os.path.join(root, file))
    return files0


"""GLOBALS"""
possible  = (".c", ".cc", ".cpp")
delimiter = "\r\0?\r?\0\r"

"""PATHS"""
targetPath  = currentPath + "/dataset/tarFuncs/"
pathToCtags = currentPath + '/config/ctags'

"""FUNCTIONS"""
def intersect(a, b):
    return list(set(a) & set(b))

def union(a, b):
    return list(set(a) | set(b))

def jaccard_sim(a, b):
    inter = len(list(set(a).intersection(b)))
    union = (len(set(a)) + len(b)) - inter
    return float(inter) / union

def normalize(string):
    return ''.join(string.replace('\r', '').replace('\t', '').split(' ')).lower()

def normalize_hash(string):
    return ''.join(string.replace('\n', '').replace('\r', '').replace('\t', '').replace('{', '').replace('}', '').split(' ')).lower()

def abstract(body, ext):

    global delimiter
    suffix = '.' + ext if not ext.startswith('.') else ext
    with tempfile.NamedTemporaryFile(mode='w+', suffix=suffix, delete=False) as tmp:
        tmp.write(body)
        tmp.flush()
        tempFile = tmp.name
    try:
        abstractBody = ""
        originalFunctionBody = body
        abstractBody = originalFunctionBody

        command = pathToCtags + ' -f - --kinds-C=* --fields=neKSt "' + tempFile + '"'
        try:
            astString = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True).decode(errors='ignore')
        except subprocess.CalledProcessError as e:
            print("Parser Error:", e)
            astString = ""

        variables = []
        parameters = []
        dataTypes = []

        functionList = astString.split('\n')
        local = re.compile(r'local')
        parameter = re.compile(r'parameter')
        func = re.compile(r'(function)')
        parameterSpace = re.compile(r'\(\s*([^)]+?)\s*\)')
        word = re.compile(r'\w+')
        dataType = re.compile(r"(typeref:)\w*(:)")
        number = re.compile(r'(\d+)')
        funcBody = re.compile(r'{([\S\s]*)}')

        lines = []

        parameterList = []
        dataTypeList = []
        variableList = []

        for i in functionList:
            elemList = re.sub(r'[\t\s ]{2,}', '', i)
            elemList = elemList.split("\t")
            if i != '' and len(elemList) >= 6 and (local.fullmatch(elemList[3]) or local.fullmatch(elemList[4])):
                variables.append(elemList)

            if i != '' and len(elemList) >= 6 and (parameter.match(elemList[3]) or parameter.fullmatch(elemList[4])):
                parameters.append(elemList)

        for i in functionList:
            elemList = re.sub(r'[\t\s ]{2,}', '', i)
            elemList = elemList.split("\t")
            if i != '' and len(elemList) >= 8 and func.fullmatch(elemList[3]):
                lines = (int(number.search(elemList[4]).group(0)), int(number.search(elemList[7]).group(0)))

                lineNumber = 0
                for param in parameters:
                    if number.search(param[4]):
                        lineNumber = int(number.search(param[4]).group(0))
                    elif number.search(param[5]):
                        lineNumber = int(number.search(param[5]).group(0))
                    if len(param) >= 4 and lines[0] <= int(lineNumber) <= lines[1]:
                        parameterList.append(param[0])
                        if len(param) >= 6 and dataType.search(param[5]):
                            dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", param[5])))
                        elif len(param) >= 7 and dataType.search(param[6]):
                            dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", param[6])))

                for variable in variables:
                    if number.search(variable[4]):
                        lineNumber = int(number.search(variable[4]).group(0))
                    elif number.search(variable[5]):
                        lineNumber = int(number.search(variable[5]).group(0))
                    if len(variable) >= 4 and lines[0] <= int(lineNumber) <= lines[1]:
                        variableList.append(variable[0])
                        if len(variable) >= 6 and dataType.search(variable[5]):
                            dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", variable[5])))
                        elif len(variable) >= 7 and dataType.search(variable[6]):
                            dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", variable[6])))

        for param in parameterList:
            if len(param) == 0:
                continue
            try:
                paramPattern = re.compile("(^|\W)" + param + "(\W)")
                abstractBody = paramPattern.sub("\g<1>FPARAM\g<2>", abstractBody)
            except:
                pass

        for dtype in dataTypeList:
            if len(dtype) == 0:
                continue
            try:
                dtypePattern = re.compile("(^|\W)" + dtype + "(\W)")
                abstractBody = dtypePattern.sub("\g<1>DTYPE\g<2>", abstractBody)
            except:
                pass
        for lvar in variableList:
            if len(lvar) == 0:
                continue
            try:
                lvarPattern = re.compile("(^|\W)" + lvar + "(\W)")
                abstractBody = lvarPattern.sub("\g<1>LVAR\g<2>", abstractBody)
            except:
                pass

        os.remove(tempFile)
        return abstractBody
    
    finally:
        if os.path.exists(tempFile):
            os.remove(tempFile)

def removeComment(string):
    c_regex = re.compile(
        r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE)
    return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])

def readFile(path):
    body = ''
    try:
        fp = open(path, 'r', encoding="UTF-8")
        body = fp.readlines()
        fp.close()
    except:
        try:
            fp = open(path, 'r', encoding="CP949")
            body = fp.readlines()
            fp.close()
        except:
            try:
                fp = open(path, 'r', encoding="euc-kr")
                body = fp.readlines()
                fp.close()
            except:
                pass
    return body

def main_func(element):
    filePath = element[0]
    target = element[1]
    try:
        OSSfuncSet = {}    
        ext = filePath.split('.')[-1]
        functionList = subprocess.check_output(pathToCtags + ' -f - --kinds-C=* --fields=neKSt "' + filePath + '"', stderr=subprocess.STDOUT, shell=True).decode()
        lines = readFile(filePath)
        if not lines:
            return f"{filePath} read error"
        allFuncs = str(functionList).split('\n')
        func = re.compile(r'(function)')
        number = re.compile(r'(\d+)')
        for i in allFuncs:
            elemList = re.sub(r'[\t\s ]{2,}', '', i)
            elemList = elemList.split('\t')
            if len(elemList) >= 8 and func.fullmatch(elemList[3]):
                funcName = elemList[0]
                funcStartLine = int(number.search(elemList[4]).group(0))
                funcEndLine = int(number.search(elemList[7]).group(0))
                tmpString = ""
                tmpString = tmpString.join(lines[funcStartLine - 1: funcEndLine])
                rawBody = tmpString
                for encoder in ['utf-8', 'cp949', 'euc-kr']:
                    try:
                        funcHash = md5(rawBody.encode(encoder)).hexdigest()
                        break
                    except:
                        continue
                newname = (funcName + '##' + '@@'.join(filePath.split(target + '/')[1].split('/')[0:]))
                absBody = abstract(rawBody, ext)
                OSSfuncSet[newname] = {}
                OSSfuncSet[newname]['orig'] = []
                OSSfuncSet[newname]['norm'] = []
                OSSfuncSet[newname]['abst'] = []
                if rawBody != '' and absBody != '':
                    OSSfuncSet[newname]['orig'] = rawBody.split('\n')
                    noComment = removeComment(rawBody)
                    noAbsComment = removeComment(absBody)

                    for eachLine in noComment.split('\n'):
                        OSSfuncSet[newname]['norm'].append(normalize(eachLine))

                    for eachLine in noAbsComment.split('\n'):
                        OSSfuncSet[newname]['abst'].append(normalize(eachLine))
        gc.collect() #trying to manage memory. lets see what happens....
        return OSSfuncSet
        
    except Exception as e:
        return f"{filePath} with exception: {str(e)}"

def save_batch(batch_data, batch_num, target_name): #lets use batchs to avoid the OS killing the process because of memory waste...
    savepath = currentPath + "/dataset/tarFuncs/" + target_name    
    batch_file = f"{savepath}_funcs_batch_{batch_num}.txt"
    with open(batch_file, 'w', encoding="utf-8") as fsave:
        json.dump(batch_data, fsave)
    hash_file = f"{savepath}_hash_batch_{batch_num}.txt"
    with open(hash_file, 'w', encoding="utf-8") as fsave_hash:
        for each in batch_data:
            if batch_data[each].get('norm'):
                funcbody = normalize_hash(''.join(batch_data[each]['norm']))
                fsave_hash.write(md5(funcbody.encode('utf-8')).hexdigest() + '\t' + each + '\n')

def preprocessor(target):
    failed = []
    target_name = target.split('/')[-1]
    
    print("Generating source tree...")
    files = [[x, target_name] for x in walk_folder(target) if any(x.endswith(k) for k in possible)]
    
    if not files:
        return failed
    print("Starting tasks...")
    batch_size = 10000
    batch_num = 0
    max_processes = max(multiprocessing.cpu_count() - 2, 1)
    for i in range(0, len(files), batch_size):
        batch_files = files[i:i + batch_size]
        batch_data = {}
        batch_num += 1
        
        with multiprocessing.Pool() as pool:
            with tqdm(total=len(batch_files), desc=f"Batch {batch_num}") as pbar:
                for result in pool.imap_unordered(main_func, batch_files):
                    if isinstance(result, dict):
                        batch_data.update(result)
                    elif isinstance(result, str):
                        failed.append(result)
                    pbar.update(1)
        if batch_data:
            save_batch(batch_data, batch_num, target_name)
        
        del batch_data
        gc.collect() #more memory celanup ....
    
    print("Combining batch files...")
    combine_batches(target_name, batch_num)
    
    return failed

def combine_batches(target_name, total_batches):
    savepath = currentPath + "/dataset/tarFuncs/" + target_name
    final_funcs = {}
    
    for batch_num in range(1, total_batches + 1):
        batch_file = f"{savepath}_funcs_batch_{batch_num}.txt"
        if os.path.exists(batch_file):
            try:
                with open(batch_file, 'r', encoding="utf-8") as f:
                    batch_data = json.load(f)
                    final_funcs.update(batch_data)
                os.remove(batch_file)  # delete the batch file
            except Exception as e:
                print(f"Error reading batch file {batch_file}: {e}")
    
    with open(f"{savepath}_funcs.txt", 'w', encoding="utf-8") as fsave:
        json.dump(final_funcs, fsave)
    
    with open(f"{savepath}_hash.txt", 'w', encoding="utf-8") as fsave_hash:
        for batch_num in range(1, total_batches + 1):
            hash_file = f"{savepath}_hash_batch_{batch_num}.txt"
            if os.path.exists(hash_file):
                try:
                    with open(hash_file, 'r', encoding="utf-8") as f:
                        fsave_hash.write(f.read())
                    os.remove(hash_file)  # delete the batch file
                except Exception as e:
                    print(f"Error reading hash file {hash_file}: {e}")
    
    
def main(target):
    print('Now MOVERY preprocesses the target repository.')
    print('This requires several minutes...')
    
    failed = preprocessor(target)
    tar_name = target.split('/')[-1]
    
    failed_file = f'{currentPath}/{tar_name}_MOVERY_failed.json'
    with open(failed_file, 'w') as file:
        json.dump(failed, file, indent=2)
        
    return failed


def run():
    parser = argparse.ArgumentParser(description="MOVERY_2")
    parser.add_argument('-t', '--target', required=True, help='Input target root folder')
    args = parser.parse_args()

    start = datetime.now()
    if not os.path.isdir(args.target):
        print(f"No target path: {args.target}")
        pass

    print(f"Processing {args.target}...")
    main(args.target)
    
    end = datetime.now()
    print(f'Time elapsed: {end - start}') 
        
    

""" EXECUTE """
if __name__ == "__main__":
    run()
   