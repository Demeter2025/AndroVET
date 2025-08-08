"""
MOVERY Detector.
Author:        Seunghoon Woo (seunghoonwoo@korea.ac.kr)
Modified:   August 5, 2022.
"""

import os
import sys
currentPath = os.getcwd()
sys.path.append(currentPath + "/config/")
import multiprocessing
import re
import json
from datetime import datetime
from tqdm import tqdm
import ijson
import gc
import Preprocessing
import argparse

"""GLOBALS"""
delimiter = "\r\0?\r?\0\r"
theta = 0.5



"""PATHS"""


vulESSLinePath   = currentPath + "/dataset/vulESSLines/"
vulDEPLinePath   = currentPath + "/dataset/vulDEPLines/"
noOldESSLinePath = currentPath + "/dataset/noOldESSLines/"
noOldDEPLinePath = currentPath + "/dataset/noOldDEPLines/"
patESSLinePath   = currentPath + "/dataset/patESSLines/"
patDEPLinePath   = currentPath + "/dataset/patDEPLines/"
vulBodyPath      = currentPath + "/dataset/vulBodySet/"
vulHashPath      = currentPath + "/dataset/vulHashes/"
targetPath       = currentPath + "/dataset/tarFuncs/"
ossidxPath       = currentPath + "/dataset/oss_idx.txt"
idx2verPath      = currentPath + "/dataset/idx2cve.txt"



"""FUNCTIONS"""

def stream_in_batches(file_path, res, batch_size=1000):
    with open(file_path, 'r', encoding='utf-8') as f:
        parser = ijson.kvitems(f, '')
        batch = {}
        for func_id, func_data in parser:
            if ('@@'.join(func_id.split('##')[1].split('@@')[:-1])) in res:
                batch[func_id] = func_data
                if len(batch) >= batch_size:
                    yield batch
                    batch = {}
                    gc.collect()
        if batch:
            yield batch
            gc.collect()


def walk_folder(folder):
    files0 = []
    for root, dirs, files in os.walk(folder, topdown = True):
        if len(files) > 0:
            for file in files:
                files0.append(os.path.join(root, file))
    return files0

def intersect(a, b):
    return list(set(a) & set(b))

def union(a, b):
    return list(set(a) | set(b))

def jaccard_sim(a, b):
    inter = len(list(set(a).intersection(b)))
    union = (len(set(a)) + len(b)) - inter
    return float(inter) / union

def normalize(string):
    # Code for normalizing the input string.
    # LF and TAB literals, curly braces, and spaces are removed,
    # and all characters are lowercased.
    # ref: https://github.com/squizz617/vuddy
    return ''.join(string.replace('\r', '').replace('\t', '').split(' ')).lower()

def removeComment(string):
    # Code for removing C/C++ style comments. (Imported from ReDeBug.)
    # ref: https://github.com/squizz617/vuddy
    c_regex = re.compile(
        r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE)
    return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])

def readFile(path):
    body = ''
    try:
        fp = open(path, 'r', encoding = "UTF-8")
        body = ''.join(fp.readlines()).strip()
    except:
        try:
            fp = open(path, 'r', encoding = "CP949")
            body = ''.join(fp.readlines()).strip()
        except:
            try:
                fp = open(path, 'r', encoding = "euc-kr")
                body = ''.join(fp.readlines()).strip()
            except:
                pass
    return body

def readOSSIDX():
    ossIDX = {}
    with open(ossidxPath, 'r', encoding = "UTF-8") as foss:
        body = ''.join(foss.readlines()).strip()
        for each in body.split('\n'):
            if each.split('@@')[0] not in ossIDX:
                ossIDX[each.split('@@')[0]] = []
            ossIDX[each.split('@@')[0]].append(each.split('@@')[1])
    return ossIDX

def readIDX2VER():
    idx2ver = {}
    with open(idx2verPath, 'r', encoding = "UTF-8") as idxfp:
        body = ''.join(idxfp.readlines()).strip()
        for each in body.split('\n'):
            idx2ver[each.split('##')[0]] = (each.split('##')[1])
    return idx2ver

def readVulHashes():
    vulHashes = {}
    for files in os.listdir(vulHashPath):
        oss = files.split('_hash.txt')[0]
        vulHashes[oss] = []

        with open(vulHashPath+ files, 'r', encoding = "UTF-8") as fo:
            body = ''.join(fo.readlines()).strip()
            for each in body.split('\n'):
                hashval = each.split('\t')[0]
                vulHashes[oss].append(hashval)
    return vulHashes



def spaceReduction(tar, vulHashes, ossIDX):
    funcHash  = {}
    tarIDX    = []
    tarFuncs  = {}
    res       = {}

    if not os.path.isfile(targetPath + '/' + tar + '_hash.txt') or not os.path.isfile(targetPath + '/' + tar + '_funcs.txt'):
        print ("No tar files (tar_funcs.txt and tar_hash.txt) in './dataset/tarFuncs/'.")
        sys.exit()

    with open(targetPath + '/' + tar + '_hash.txt', 'r', encoding = "UTF-8") as fh:
        body = ''.join(fh.readlines()).strip()
        for each in body.split('\n'):
            hashval = each.split('\t')[0]
            hashpat = each.split('\t')[1]
            if hashval not in funcHash:
                funcHash[hashval] = []
            funcHash[hashval].append(hashpat)

    for oss in vulHashes:
        if oss in ossIDX:
            for hashval in vulHashes[oss]:
                if hashval in funcHash:    
                    tarIDX.extend(ossIDX[oss])
                    for eachPat in funcHash[hashval]:
                        res['@@'.join(eachPat.split('##')[1].split('@@')[:-1])] = 1

    tarIDX = list(set(tarIDX))

    return tarIDX, res #, tarFuncs

def process_file(record):
    try:
        v = record[0]
        idx2ver = record[1]
        tarIDX = record[2]
        res = record[3]
        tar = record[4]
    except Exception as e:
        print(f"{str(e)} with record = {str(record)}")
    temp = {}
    vulFiles = v[v.rfind('/')+1:]
    idx = vulFiles.split('_')[0]

    if idx not in tarIDX:
        # for considering only the OSS that is reused in the target program
        
        return None

    vulBody = ""

    vul_essLines = []
    vul_depLines = {}
    pat_essLines = []
    pat_depLines = {}

    flag = 0
    isAbs = 1



    """ READ VUL INFOS """
    with open(vulBodyPath + vulFiles, 'r', encoding = "UTF-8") as f:
        vulBody = json.load(f)
    
    if idx + "_common.txt" in os.listdir(vulESSLinePath):
        # vul signature
        # The case in which the oldest vulnerable function exists and some code lines were deleted from the patch

        with open(vulESSLinePath + idx + "_common.txt", 'r', encoding = "UTF-8") as f:
            vul_essLines = json.load(f)
        with open(vulDEPLinePath + idx + "_depen.txt", 'r', encoding = "UTF-8") as fd:
            vul_depLines = json.load(fd)
        flag = 1

    elif idx + "_minus.txt" in os.listdir(noOldESSLinePath):
        # The case in which the oldest vulnerable function does not exist and some code lines were deleted from the patch

        with open(noOldESSLinePath + idx + "_minus.txt", 'r', encoding = "UTF-8") as f:
            vul_essLines = json.load(f)
        with open(noOldDEPLinePath + idx + "_depen.txt", 'r', encoding = "UTF-8") as fd:
            vul_depLines = json.load(fd)
        flag = 1


    if idx + "_plus.txt" in os.listdir(patESSLinePath):
        # patch siganture

        with open(patESSLinePath + idx + "_plus.txt", 'r', encoding = "UTF-8") as f:
            pat_essLines = json.load(f)
        with open(patDEPLinePath + idx + "_depen.txt", 'r', encoding = "UTF-8") as fd:
            pat_depLines = json.load(fd)
        flag = 2

    else:
        # for vul parsing err handling
        if len(vul_essLines) == 0:
            
            return None

    # del o add x  1
    # del o add o  2
    # del x add o  3


    # Selective abstraction
    if len(pat_essLines) > 0:
        patLines      = []
        patAbsLines   = []

        vulLines      = []
        vulAbsLines   = []

        tempNewPat    = []
        tempNewAbsPat = []

        for eachPat in pat_essLines:
            patLines.append(normalize(eachPat['pat_body']))
            patAbsLines.append(normalize(eachPat['abs_body']))

            if normalize(eachPat['pat_body']) not in vulBody['vul_body']:
                tempNewPat.append(normalize(eachPat['pat_body']))
                tempNewAbsPat.append(normalize(eachPat['abs_body']))
        temp = []

        temp[:] = (value for value in tempNewPat if value != '{' and value != '}' and value != '')
        newPat = set(temp)

        temp[:] = (value for value in tempNewAbsPat if value != '{' and value != '}' and value != '')
        newAbsPat = set(temp)

        if len(vul_essLines) > 0:
            for eachVul in vul_essLines:
                vulLines.append(normalize(eachVul['vul_body']))
                vulAbsLines.append(normalize(eachVul['abs_body']))
            if (set(patAbsLines) != set(vulAbsLines)): # applying abstraction
                isAbs = 1
            else:
                isAbs = 0
        else:
            flag = 3

    if len(vul_depLines) > 0:
        if "vul" in vul_depLines:
            vulDepens = vul_depLines["vul"]
        else:
            vulDepens = vul_depLines

        absDepens_withoutOLD = []
        norDepens_withoutOLD = []
        absDepens_withOLD    = []
        norDepens_withOLD    = []

        for eachDepen in vulDepens:
            if len(vulDepens[eachDepen]) > 0:
                for each in vulDepens[eachDepen]:
                    absDepens_withoutOLD.append(removeComment(each["abs_norm_vul"]))
                    norDepens_withoutOLD.append(removeComment(each["orig_norm_vul"]))

        if "old" in vul_depLines:
            vulDepens = vul_depLines["old"]
            for eachDepen in vulDepens:
                if len(vulDepens[eachDepen]) > 0:
                    for each in vulDepens[eachDepen]:
                        absDepens_withOLD.append(removeComment(each["abs_norm_vul"]))
                        norDepens_withOLD.append(removeComment(each["orig_norm_vul"]))

        absDepens_withoutOLD = set(absDepens_withoutOLD)
        absDepens_withOLD = set(absDepens_withOLD)
        norDepens_withoutOLD = set(norDepens_withoutOLD)
        norDepens_withOLD = set(norDepens_withOLD)

    coreAbsVulLines = []
    coreVulLines = []

    for val in vul_essLines:
        coreAbsVulLines.append(normalize(val["abs_body"]))
        coreVulLines.append(normalize(val["vul_body"]))

    coreAbsVulLines = set(coreAbsVulLines)
    coreVulLines    = set(coreVulLines)

    vulBodySet = []
    oldBodySet = []


    vulBodySet = set(vulBody['vul_body'])
    if 'old_body' in vulBody:
        oldBodySet = set(vulBody['old_body'])

    ret_val = []
    for tarFuncs in stream_in_batches(targetPath + tar + '_funcs.txt', res, batch_size=5000):
        for file in tarFuncs:
            x = set(tarFuncs[file]["norm"])
            y = set(tarFuncs[file]["abst"])
            
            step = 1

            if flag == 1 or flag == 2:
                # the patch contains both added/deleted code lines

                if isAbs == 1:
                    # USING ABSTRACTION

                    if not coreAbsVulLines.issubset(y):
                        step = 0

                    if step == 1:
                        for absLine in absDepens_withoutOLD:
                            if absLine not in y:
                                step = 0
                                break

                        if step == 0 and len(absDepens_withOLD) > 0:
                            step = 1
                            for absLine in absDepens_withOLD:
                                #print (absLine)
                                if absLine not in y:
                                    step = 0
                                    break
                        
                    if step == 1 and flag == 2:
                        
                        if not newAbsPat.isdisjoint(y):
                            step = 0
                        
                    if step == 1:
                        if len(vulBodySet) <= 3:
                            continue

                        if float(len(vulBodySet&x)/len(vulBodySet)) >= theta:
                            # measuring syntax similarity
                            ret_val.append('* [' + idx2ver[idx] + '] ' + tar + ' contains the vulnerable "' + file.split('##')[0] + '" function in ' + file.split('##')[1].replace('@@', '/'))
                            continue
                        
                        try:
                            # measuring syntax similarity with the oldest vulnerable function
                            if float(len(oldBodySet&x)/len(oldBodySet)) >= theta:
                                ret_val.append('* [' + idx2ver[idx] + '] ' + tar + ' contains the vulnerable "' + file.split('##')[0] + '" function in ' + file.split('##')[1].replace('@@', '/'))
                        except:
                            pass

                else:
                    # WITHOUT ABSTRACTION

                    if not coreVulLines.issubset(x):
                        step = 0                    
                    
                    if step == 1:
                    
                        for absLine in norDepens_withoutOLD:
                            if absLine not in x:
                                step = 0
                                break

                        if step == 0 and len(norDepens_withOLD) > 0:
                            step = 1
                            for absLine in norDepens_withOLD:
                                if absLine not in x:
                                    step = 0
                                    break

                    
                    if step == 1 and flag == 2:
                        if not newPat.isdisjoint(x):
                            step = 0
                    
                    if step == 1:
                        if len(vulBodySet) <= 3: 
                            continue
                        if float(len(vulBodySet&x)/len(vulBodySet)) >= theta:
                            ret_val.append('* [' + idx2ver[idx] + '] ' + tar + ' contains the vulnerable "' + file.split('##')[0] + '" function in ' + file.split('##')[1].replace('@@', '/'))
                            continue
                        
                    
                        try:
                            if float(len(oldBodySet&x)/len(oldBodySet)) >= theta:
                                ret_val.append('* [' + idx2ver[idx] + '] ' + tar + ' contains the vulnerable "' + file.split('##')[0] + '" function in ' + file.split('##')[1].replace('@@', '/'))
                        except:
                            pass
    
            elif flag == 3:
                # NO DELETED CODE LINES

                if (len(newAbsPat) == 0):
                    continue

                if not newAbsPat.isdisjoint(y):
                    step = 0
               
                if step == 1:
                    if len(vulBodySet) <= 3: 
                        continue

                    if float(len(vulBodySet&x)/len(vulBodySet)) >= theta:
                        ret_val.append('* [' + idx2ver[idx] + '] ' + tar + ' contains the vulnerable "' + file.split('##')[0] + '" function in ' + file.split('##')[1].replace('@@', '/'))
                        continue

                    try:
                        if float(len(oldBodySet&x)/len(oldBodySet)) >= theta:
                            ret_val.append('* [' + idx2ver[idx] + '] ' + tar + ' contains the vulnerable "' + file.split('##')[0] + '" function in ' + file.split('##')[1].replace('@@', '/'))
                    except:
                        pass

            else:
                continue
    
    if len(ret_val) > 0:
        return ret_val
    else:
        return None
def detector(tar):
    if '/' in tar:
        tar = tar.split('/')[-1]
    print ()
    print ("[+] NOW MOVERY SCANS " + tar + "...")
    print ()

    """ FOR TIME MEASUREMENT """
    stime  = datetime.now()     

    ossIDX           = readOSSIDX()
    idx2ver           = readIDX2VER()
    vulHashes        = readVulHashes()
    tarIDX, res = spaceReduction(tar, vulHashes, ossIDX)

    detected = []
    files = [[x,idx2ver,tarIDX,res, tar] for x in walk_folder(vulBodyPath)]
    with multiprocessing.Pool() as pool:
        with tqdm(total=len(files)) as pbar:    
            for result in pool.imap_unordered(process_file, files):
                pbar.update(1)
                if result is None:
                    continue
                else:
                    detected.append(result)

    mtime = str(datetime.now() - stime)
    
    my_rep = {'time' : mtime, 'detections': detected}
    with open(f"{currentPath}/{tar}_results.json", 'w', encoding='utf-8') as my_file:
        json.dump(my_rep, my_file, indent=4)
    
    print (f"[+] TOTAL ELAPSED TIME: {mtime}")

def main(target):
    detector(target)

def run():
    parser = argparse.ArgumentParser(description="AndroVET")
    parser.add_argument('-t', '--target', required=True, help='Input target')
    parser.add_argument('-m', '--mode', required=True, help='Mode selector')
    
    args = parser.parse_args()
    pre_times = {}
    testmd = str(args.mode)
    target = args.target
    
    while testmd not in ['0', '1']:
        print('Please enter a valid mode (0 or 1):\n')
        testmd = input()
     

    pre_time = Preprocessing.run(target)
    pre_times[target] = pre_time
    
    if testmd == '1':
        currentPossible = ["arangodb", "crown", "emscripten", "ffmpeg", "freebsd-src", "git", "opencv", "openMVG", "reactos", "redis"]
        if target not in currentPossible:
            print ("Please enter one of the inputs below.")
            print (str(currentPossible))
            sys.exit()
        else:
            main(target)
    else:
        main(target)




""" EXECUTE """
if __name__ == "__main__":
    run()
 