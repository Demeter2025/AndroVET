import mysql.connector
import os
from tqdm import tqdm
import json
import multiprocessing
import tools
import parse_vec
import comp_vec
import counts
import sys
import re
from collections import defaultdict
import time
from datetime import datetime
import gc
import argparse


def test(rep):
   
    [records, cves, bugs] = tools.unique(rep)

    print ("CVE = " + str(len(cves)))
    print ("BUGS = " + str(len(bugs)))
    print ("total = " + str(len(records)))
    print ("=================================")
    c = [x for x in records if x['found'] == x['total']]
    print("COMPLETE = " + str(len(c)))
    print("PARTIAL = " + str(len(records) - len(c)))



def find_all(name, struct):
    f_name = name.split('/')[-1]
    retval = []
    for k in files:
        if f_name == k.split('/')[-1].strip() and struct in k:
            retval.append(k)

    if len(retval) > 1:  
        val_sim = {}
        for p in retval:
            val_sim[p] = tools.get_similarity_ratio(name , p)
        
        max_value = max(val_sim.values())
        retval = []
        for key, value in val_sim.items():
            if value == max_value or value >= 0.95:
                retval.append(key)
    
    if len(retval) > 0:
        return retval 
    else:
        return 'error' 
  
def task01(item):
    optional_path = False
    f = item['file_add'].strip()[1:] 
    if f == "/dev/null":
        f = item['file_rem'].strip()[1:]
    
    struct = item['struct'].strip()
    if struct == '/':
        struct = ''
    tmp0 = argv1 + struct +f
    tmp_arr = [tmp0]
    
    if not os.path.exists(tmp0):
        optional_path = True
        possible = find_all(tmp0 , argv1 + item['struct'].strip())
        if possible is None or len(possible) == 0 or possible == 'error':
            return [None,  {'CVE': item['CVE'], 'ID': item['ID'], 'file': tmp0}]
            
        else:
            tmp_arr = possible
    
        
    plus = tools.clean(item['plus'].split(",+"), 0)
    if len(plus) > 0 and plus[0].startswith("+") and not plus[0].startswith("++"):
        plus[0] = plus[0][1:].strip()   
    rem = tools.clean(item['rem'].split(",-"), 0)
    if len(rem) > 0 and rem[0].startswith("-") and not rem[0].startswith("--"):
        rem[0] = rem[0][1:].strip()
    bfr = tools.clean_2comm(tools.clean(tools.fixsplit(item['context_bfr']).split("`"), 0))
    aft = tools.clean_2comm(tools.clean(tools.fixsplit(item['context_aft']).split("`"), 0))
      

    exceptions = {'{','}',' ', ';'}
    plus_strip = [tools.cl(re.sub(r'\s+', ' ', x).lower().strip()) for x in plus if x not in exceptions and len(x.strip()) > 0]
    minus_strip = [tools.cl(re.sub(r'\s+', ' ', x).lower().strip()) for x in rem if x not in exceptions and len(x.strip()) > 0]
    bfr_strip = [tools.cl(re.sub(r'\s+', ' ', x).lower().strip()) for x in bfr if x not in exceptions and len(x.strip()) > 0] 
    aft_strip = [tools.cl(re.sub(r'\s+', ' ', x).lower().strip()) for x in aft if x not in exceptions and not x.startswith('Powered by') and len(x.strip()) > 0] 
    
    extension = tmp0.split('.')[-1]    
    comments = ['/', '//', '/*', '*']
    if extension not in ['c', 'h', 'ccp', 'ccx']:
        comments.append('#')
    my_type = 'replace'
    if (item['rem']) == 0:
        my_type = 'add'
    
    t = { 
            'ID': item['ID'],
            'CVE': item['CVE'],
            'BUG' : item['bug'],
            'range' : item['ind_range'],
            'rem' : item['rem'],
            'plus' : item['plus'],
            'context_bfr' : item['context_bfr'],
            'context_aft' : item['context_aft'],
            'file' : tmp0,
            'type' : my_type,
            'tabulation' : False,
            'commented' : False,
            'no_rf': False,
            'optional_path_no_patch_check': False,
            'inconclusive' : False,
            'import' : 'patch found',
            'patch_found' : True

        }
    if minus_strip == plus_strip:
        t['tabulation'] = True
        del aft, bfr, rem, plus, plus_strip, minus_strip, aft_strip, bfr_strip
        gc.collect()
        return [t, {}]
    import_val = False
    if all(x.startswith('import') for x in minus_strip):
        import_val = True
    if all(any(line.strip().startswith(k) for k in comments) for line in plus_strip) and len(minus_strip) == 0:
        t['commented'] = True
        del aft, bfr, rem, plus, plus_strip, minus_strip, aft_strip, bfr_strip
        gc.collect()
        return [t, {}]
    
    lengths = {
        'before' : len(bfr),
        'plus' : len(plus),
        'minus' : len(rem),
        'after' : len(aft)
    }

        
    my_results = {}
    
    if len(tmp_arr) > 1:
        t01 = tmp0.split('/')[-2]
        struct_c  = struct + '/'
        tmp_arr_2 = []
        for element_f in tmp_arr :
            if element_f.split('/')[-2].strip() == t01.strip() and struct_c in element_f:
                tmp_arr_2.append(element_f)
        if len(tmp_arr_2) > 0:
            tmp_arr = tmp_arr_2

    for file_count, tmp in enumerate(tmp_arr):
        buffer = 'none'
        encoders = ['utf-8', 'windows-1252', 'iso-8859-1', 'ascii', 'latin1']
        for enc in encoders:
            try:
                with open(tmp, "r", encoding=enc) as buff:
                    buffer = buff.readlines()
                buff.close()
                break
            except:
                pass
        if buffer == "none" and file_count == len(tmp_arr) - 1 and len(my_results) == 0:
            del aft, bfr, rem, plus, plus_strip, minus_strip, aft_strip, bfr_strip
            gc.collect()
            return [None,  {'CVE': item['CVE'], 'ID': item['ID'], 'file': tmp0}]
        for ind, line in enumerate(buffer):
            buffer[ind] = re.sub(r'\s+', ' ', line).lower().strip()
        buffer.append('testLine - avoiding errors on short files')
                     
        used = {
            'plus':{},
            'minus':{},
            'before':{},
            'after':{}
        }
        tempo = {
            'plus': [],
            'minus': [],
            'before': [],
            'after' : []
        }
        for item2 in plus_strip:
            amount = plus_strip.count(item2)
            if item2 not in tempo["plus"]:
                used["plus"][item2] = amount
                tempo["plus"].append(item2)

        for item3 in minus_strip:
            amount = minus_strip.count(item3)
            if item3 not in tempo["minus"]:
                used["minus"][item3] = amount
                tempo["minus"].append(item3)

        for item4 in aft_strip:
            amount = aft_strip.count(item4)
            if item4 not in tempo["after"]:
                used["after"][item4] = amount
                tempo["after"].append(item4)

        for item5 in bfr_strip:
            amount = bfr_strip.count(item5)
            if item5 not in tempo["before"]:
                used["before"][item5] = amount
                tempo["before"].append(item5)
        k = 0
        if len(minus_strip) == 0:
            k = len(buffer) - 1
        
        for i in range(k, len(buffer), 1):
        
            tempo_line = tools.check_(tools.cl(buffer[i]).strip(), minus_strip)
            if tempo_line.startswith("double_rule"):
                tempo_line = tempo_line.split("dr_check")[1].strip()

            if extension == "rc" and len(minus_strip) > 0:
                if minus_strip[0].strip() in tempo_line:
                    ext_text = tempo_line.replace(minus_strip[0], "")
                    if "=" in ext_text and len(ext_text.split("=")[-1].strip().split(" ") ) == 1:
                        tempo_line = minus_strip[0]
                    elif "-" in ext_text and len(ext_text.split("-")[-1].strip().split(" ") ) == 1:
                        tempo_line = minus_strip[0] 

            if len(minus_strip) > 0 and tempo_line == minus_strip[0].strip() and i < len(buffer) - 1:

                if tools.compare_block(lengths, bfr_strip, plus_strip, minus_strip, aft_strip, buffer, i, used, extension):
                    
                    reptmp = {
                        'ID': item['ID'],
                        'CVE': item['CVE'],
                        'BUG' : item['bug'],
                        'range' : item['ind_range'],
                        'rem' : item['rem'],
                        'plus' : item['plus'],
                        'context_bfr' : item['context_bfr'],
                        'context_aft' : item['context_aft'],
                        'file' : tmp,
                        'type' : 'replace',
                        'import' : import_val,
                        'tablulation' : False,
                        'commented' : False,
                        'no_rf' : False,
                        'optional_path_no_patch_check': False,
                        'inconclusive' : False,
                        'patch_found' : False
                    }
                    my_results[file_count] = reptmp
                                            
            
            elif i == len(buffer) - 1:
                if len(plus_strip) > 0 and len(minus_strip) == 0: #add only
                    ret_stat = False
                    if all(x.strip().startswith('import') for x in plus_strip):
                        ret_stat = True
                    
                    if len(struct.strip()) == 0: 
                        reptmp = {
                            'ID': item['ID'],
                            'CVE': item['CVE'],
                            'BUG' : item['bug'],
                            'range' : item['ind_range'],
                            'rem' : item['rem'],
                            'plus' : item['plus'],
                            'context_bfr' : item['context_bfr'],
                            'context_aft' : item['context_aft'],
                            'file' : tmp,
                            'tablulation' : False,
                            'commented' : ret_stat,
                            'no_rf': True,
                            'import' : False,
                            'optional_path_no_patch_check': False,
                            'inconclusive' : False,
                            'patch_found' : True

                        }
                        my_results[file_count] = reptmp
                    elif optional_path == True and 'hardware' not in tmp0:
                        reptmp = {
                            'ID': item['ID'],
                            'CVE': item['CVE'],
                            'BUG' : item['bug'],
                            'range' : item['ind_range'],
                            'rem' : item['rem'],
                            'plus' : item['plus'],
                            'context_bfr' : item['context_bfr'],
                            'context_aft' : item['context_aft'],
                            'file' : tmp,
                            'type' : 'add',
                            'tabulation' : False,
                            'commented' : False,
                            'no_rf': False,
                            'optional_path_no_patch_check': True,
                            'inconclusive' : False,
                            'import' : ret_stat,
                            'patch_found' : True
                        }
                        my_results[file_count] = reptmp

                    elif tools.test_adding(bfr, aft, buffer, plus_strip, used, bfr_strip, aft_strip, minus_strip, extension ) == False:
                        reptmp = {
                            'ID': item['ID'],
                            'CVE': item['CVE'],
                            'BUG' : item['bug'],
                            'range' : item['ind_range'],
                            'rem' : item['rem'],
                            'plus' : item['plus'],
                            'context_bfr' : item['context_bfr'],
                            'context_aft' : item['context_aft'],
                            'file' : tmp,
                            'type' : 'add',
                            'inconclusive' : False,
                            'import' : ret_stat,
                            'patch_found' : False
                        }
                        my_results[file_count] = reptmp
                    else:
                        reptmp = {
                            'ID': item['ID'],
                            'CVE': item['CVE'],
                            'BUG' : item['bug'],
                            'range' : item['ind_range'],
                            'rem' : item['rem'],
                            'plus' : item['plus'],
                            'context_bfr' : item['context_bfr'],
                            'context_aft' : item['context_aft'],
                            'file' : tmp,
                            'type' : 'add',
                            'tabulation' : False,
                            'commented' : False,
                            'no_rf': False,
                            'optional_path_no_patch_check': False,
                            'inconclusive' : False,
                            'import' : ret_stat,
                            'patch_found' : True
                        }
                        my_results[file_count] = reptmp
                else:
                    if len(my_results) == 0:
                        del aft, bfr, rem, plus, plus_strip, minus_strip, aft_strip, bfr_strip, buffer
                        gc.collect()
                        t['inconclusive'] = True
                        return [t, []]
    del aft, bfr, rem, plus, plus_strip, minus_strip, aft_strip, bfr_strip, buffer
    gc.collect()
    if len(my_results) == 0:
        t['inconclusive'] = True
        return [t, []]
    if 'hardware' in tmp0:
        for i2 in my_results:
            if 'CVE' in my_results[i2]['CVE']:
                return [my_results[i2], []]
        t['inconclusive'] = True
        return [t, []]
                               
    else:
        for i2 in my_results:
            if my_results[i2]['patch_found'] == True:
                return [my_results[i2], []]

    try:
        if type(my_results[0]) == dict:
            return [my_results[0], []]
        else:
            return [None,  {'CVE': item['CVE'], 'ID': item['ID'], 'file': tmp0}]

    except:    
        return [None,  {'CVE': item['CVE'], 'ID': item['ID'], 'file': tmp0}]
   

def run():
    parser = argparse.ArgumentParser(description="AndroVET")
    parser.add_argument('-i', '--input', required=True, help='Input COS root folder')
    parser.add_argument('-o', '--output', required=True, help='Output folder')
    parser.add_argument('-t', '--threshold', type=float, default=85.5, help='Similarity threshold value')
    parser.add_argument('-s', '--skip', action='store_true', help='Skip Precision Layer IF you have skip files')
    parser.add_argument('-d', '--database', default='mydata', help='database name')
    parser.add_argument('-du', '--dbuser', default='root', help='database user')
    parser.add_argument('-dp', '--dbpass', default='', help='database password')
    parser.add_argument('-v', '--version', required=True, help='Set up the Android version (and below) filter')
    args = parser.parse_args()
    
    start = datetime.now()
    testing = args.skip
    global report
    report = list()
    global report2
    report2 = list()
    failed = dict()
    
    global argv1
    argv1 = args.input
    if argv1.endswith('/'):
        argv1 = argv2[:-1] 
    argv2 = args.output
    if argv2.endswith('/'):
        argv2 = argv2[:-1] 
    argv4 = args.threshold
    

    if not os.path.exists(argv1):
        print('Wrong COS location, please check the provided parameters.')
        sys.exit()
    
    if not os.path.exists(argv2):
        print('Save folder does not exists, attempting to create it...')
        try:
            os.makedirs(argv2)
        except:
            print('We could not create the save folder.\n please provide an existing location...\nyour folder should start with /home/...')
            argv2 = input()
            if not os.path.exists(argv2):
                print('The provided folder does not exists, please try again.')
                sys.exit()

    global files
    print('Building Source Tree...\n')
    files = tools.walk_folder(argv1)
    
    print('Reading data bases...\n')
    try:
        link = mysql.connector.connect(user=f'{args.dbuser}', password=f'{args.dbpass}',
                              host='127.0.0.1',
                              database=f'{args.database}',
                              use_pure=False)
    
        sql_select_Query = "SELECT * from bugs WHERE ID > 0"; 
        sql_select_Query2 = "SELECT * from common WHERE ID > 0"
        cursor = link.cursor(dictionary=True)
        cursor.execute(sql_select_Query)
        bugs = cursor.fetchall()
        cursor.execute(sql_select_Query2)
        common = cursor.fetchall()
        
        
    except mysql.connector.Error as e:
        print("Error reading data from MySQL table", e)
    finally:
        if link.is_connected():
            link.close()
            cursor.close()
            print("MySQL connection is closed\n")
    if len(bugs) == 0:
        print('Nothing to do, please check your database is being correctly provided')
        sys.exit()
    print('Starting Precision Layer ...')
    print('Please be patient, some systems can fail to update the status bar ...')
    grouped_results = defaultdict(list)
    for row in bugs:
        cve = row['CVE']
        grouped_results[cve].append(row)


    records = []
    for rec in bugs:
        if rec not in records:
            records.append(rec)
    blocks = tools.calculate_blocks(records)
    file = ""
    global buffer
    buffer = []

    if testing == False:
        with multiprocessing.Pool() as pool:
            report = []
            matched = []
            with tqdm(total=len(records)) as pbar:
                for result in pool.imap(task01, records):
                    pbar.update(1)
                    result_val, avoid_res = result[0], result[1]
                    if result_val is not None:
                        if result_val['patch_found'] == True:
                            matched.append(result_val)
                        else:
                            report.append(result_val)
                                    
                    elif len(avoid_res) > 0:
                        my_k = avoid_res['CVE'] 
                        my_v = {'ID' : avoid_res['ID'], 'file': avoid_res['file']} 
                        if my_k in failed.keys():
                            failed[my_k].append(my_v)
                        else:
                            failed[my_k] = [my_v]

    for row in blocks:
        consider = False
        ty = 'add'        
        res = [x for x in report if x['CVE'].strip() == row['CVE'] and x['BUG'].strip() == row['bug'].strip()]
        for ind_x, x in enumerate(res):
            if x['type'] ==  'replace' and x['import'] == True:
                comp_list = grouped_results[x['CVE']]
                del_ind = ind_x
                for y in comp_list:
                    add = [g.strip() for g in y['plus'].split(',+') if len(g.strip()) > 0]
                    for k in add:
                        if k.startswith('+'):
                            k = k[1:]
                        if k in x['rem']:
                            del res[del_ind]
        found = len(res)
        if any(x['type'] == 'replace' for x in res):
            ty = 'replace'
            found_rep = len([x for x in res if x['type'] ==  'replace'])
            if found > int(row['count'] / 2) and found_rep >= int(row['replace'] *0.75):
                consider = True 
        total = row['count']
        
        t = {
            'CVE' : row['CVE'],
            'bug' : row['bug'],
            'type' : ty,
            'found' : found,
            'total' : total,
            'consider' : consider            
        }
        if len(res) > 0:
            report2.append(t)
 
    if testing == False:
        test(report2)

    if testing == True:
        try:
            with open(argv2 +'/report.json', 'r') as f:
                report2 = json.load(f)
                f.close()
            
            with open(argv2 + '/cvereport.json', 'r') as f:
                report = json.load(f)
                f.close()
            debug = True
        except Exception as e:
            print(f'We could not find your skip files, are you sure they are in the output directory?.\n{e}')

    print('\nStarting Abstraction Layer ...')
    
    [records, cves, bugs2] = tools.unique(report2)
    complete = [x for x in records if x['found'] == x['total'] or x['consider'] == True]

    my_list = {}
    add_only = []
    replace = []
    final_report = []
    detected = []
    for item in complete:
        list_comp = [x for x in report if x['CVE'].strip() == item['CVE'].strip()]
        if any(x['type'] == 'replace' for x in list_comp):
            replace.append(item)
            final_report.append(item['CVE'])
        else:
            add_only.append(item)
            my_list[item['CVE'].strip()] = list_comp
    
    print("PATCH ONLY CVEs = " + str(len(add_only)))
    print("REPLECEMENT CVEs = " + str(len(replace)))
    print('========================================')
    print('Bulding block vectors...\n')
    

    with tqdm(total=len(my_list)) as pbar:
        
        for element in my_list:
             
            pbar.update(1)
            final_vals = []
            for i in my_list[element]:
                
                if i['import'] == True: 
                    continue
                #check the extension
                ext = i['file'].split(".")[-1].strip()
                valid = ['cpp', 'cc', 'c', 'cxx', 'java', 'kt', 'kts', 'ktm']
                if ext in valid:
                    [vector, vecs] = parse_vec.parse(i['plus'], i['context_bfr'], i['context_aft'], i['file'], ext, i['range'])
                    values = []
                    if len(vecs) > 50 or len(vecs) == 0 or vecs[0] == 'Layer_1':
                        continue
                    elif vector == 'comments' or vecs[0] == 'checked':
                        values.append(100)
                        continue
                    for v in vecs:
                        values.append(comp_vec.compare_arrays(vector, v))
                    final_vals.append(max(values))
                else:
                    final_vals.append(0) 
            if len(final_vals) == 1 and final_vals[0] >= argv4:
                detected.append(my_list[element])
            elif len(final_vals) > 1 and tools.check_vals(final_vals, argv4) ==  True and sum(final_vals) / len(final_vals) >= 80: 
                detected.append(my_list[element])
            else:
                final_report.append(element) 
    
      
    ver = args.version 
    results = []
    arr = [row for row in common if row['CVE'] in final_report]
    pattern = r'^(\d+(\.\d+)?)(([,;])(\d+(\.\d+)?))*$'
    for cve in arr:
        my_ver = cve['vul_true'].replace('and below', '').strip()
        my_ver = my_ver.replace('L', '').replace(' ', '').replace(',,', ',').strip()
        if my_ver.endswith(','):
            my_ver = my_ver[:-1]
        if my_ver.startswith(','):
            my_ver = my_ver[1:]

        if re.match(pattern, my_ver):
            try:  
                my_ver = [x for x in my_ver.replace('(', '').replace(')', '').replace(';', ',').split(',') if len(x.strip()) > 0]
                if len(my_ver) == 0:
                    results.append(cve['CVE'])
                else:
                    for element in my_ver:
                        general = int(element.split('.')[0])
                        if general <= ver:
                            results.append(cve['CVE'])
                            break      
            except:
                results.append(cve['CVE'])
        else:
            results.append(cve['CVE'])
    
    final_report = results
    
    analisys = counts.calculate(final_report, common)

    detail = defaultdict()
    for entry in report:
        detail[entry['CVE']].append(entry)
    save = argv2 + '/affected_files.txt'
    with open(save.replace('//', '/'), 'w') as myfile0:
        try:
            for k,v in detail.items():
                for member in v:
                    if member['type'] == 'add':
                        myfile0.write(f"[+] We found traces of a missing patch for {member['CVE']} in: {member['file']}\n")
                    elif member['type'] == 'replace':
                        myfile0.write(f"[+] We found traces of {member['CVE']} in: {member['file']}\n")

        except Exception as e:
            myfile0.write(f'Something went wrong: \n{e}\n If the final report cannot be generated you will find skip files...')
        
    save = argv2 + "/final_report.txt"
    end = datetime.now()
    skip = False
    with open(save.replace('//', '/'), 'w') as myfile:
        try:
            myfile.write(f'REPORT FOR ' + {argv1.split('/')[-1]} + '\nDETECTED CVEs:\n' )
            myfile.write('Elapsed Time = ' + str(end - start) + '\n')
            string = ",".join(final_report)
            myfile.write('WE FOUND TRACES OF = ' + str(len(final_report)) +  'CVEs\nTHE COMPLETE LIST IS:\n' + string + '\nSEVERITY DISTRIBUTION:\n')
            for tag in analisys.keys():
                myfile.write(str(tag).upper() + ':\n\n')
                if type(analisys[tag]) is dict:
                    for key, value in analisys[tag].items():
                        if type(value) is list:
                            value = ','.join(value)
                        myfile.write(str(key) + ' = ' + str(value) + '\n')
                elif type(analisys[tag]) is list:
                    string = ",".join(analisys[tag])
                    myfile.write(string + '\n')
                myfile.write('\n===================================================\n')
        except:
            myfile0.write(f'Something went wrong: \n{e}')
            myfile0.write(f'We created skip files for you to run only Abstraction\nIf you find the same problem again please send us the skip files and the error')
            skip = True
        myfile.close()   
    if skip == True:
        save = argv2 + "/report.json"
        with open(save.replace('//', '/'), 'w') as myfile:
            json.dump(report2, myfile)
        save = argv2 + "/cvereport.json"
        with open(save.replace('//', '/'), 'w') as myfile:
            json.dump(report, myfile) 
        print('We created Skip files.\nTo use them please save them in the output folder and set -s')    
    print('All tasks done, please refer to FinalReport.txt for our resutls\n')
        

if __name__ == '__main__':
    run()