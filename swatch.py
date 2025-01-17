import mysql.connector
import os
from tqdm import tqdm
import json
import multiprocessing
from functools import partial
import tools
import parse_vec
import comp_vec
import counts
import sys
from collections import defaultdict


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

    if len(retval) > 1: #if there are more than one possible file, we test similarity to decicde which one we want to use. 
        val_sim = {}
        for p in retval:
            val_sim[p] = tools.get_similarity_ratio(name , p)
        
        max_value = max(val_sim.values())
        retval = []
        for key, value in val_sim.items():
            if value == max_value or value >= 0.95:
                retval.append(key)
    
    if len(retval) > 0:
        return retval #more than one file may have the same similarity. we return all of those. 
    else:
        return 'error' #no file was found with the name and the structure on it.
  
def task01(item, fol):
    optional_path = False
    f = item['file_add'].strip()[1:] 
    if f == "/dev/null":
        f = item['file_rem'].strip()[1:]
    
    struct = item['struct'].strip()
    if struct == '/':
        struct = ''
    
    tmp0 = fol + struct +f
    tmp_arr = [tmp0]
    
    if not os.path.exists(tmp0):
        optional_path = True
        possible = find_all(tmp0 , fol + item['struct'].strip())
        if possible is None or len(possible) == 0 or possible == 'error':
            return [None, [item['CVE'], tmp0]]
            
        else:
            #print("file found at " + possible)
            tmp_arr = possible
    
        
    plus = tools.clean(item['plus'].split(",+"), 0)
    if len(plus) > 0 and plus[0].startswith("+"):
        plus[0] = plus[0][1:].strip()   
    rem = tools.clean(item['rem'].split(",-"), 0)
    if len(rem) > 0 and rem[0].startswith("-"):
        rem[0] = rem[0][1:].strip()
    bfr = tools.clean_2comm(tools.clean(tools.fixsplit(item['context_bfr']).split("`"), 0))
    aft = tools.clean_2comm(tools.clean(tools.fixsplit(item['context_aft']).split("`"), 0))
      
    
    #prepeare the counts for the file blocks comparisons
    exceptions = {'{','}',' ', ';'}
    plus_strip = [tools.cl(x) for x in plus if x not in exceptions and len(x.strip()) > 0]
    minus_strip = [tools.cl(x) for x in rem if x not in exceptions and len(x.strip()) > 0]
    bfr_strip = [tools.cl(x) for x in bfr if x not in exceptions and len(x.strip()) > 0] 
    aft_strip = [tools.cl(x) for x in aft if x not in exceptions and not x.startswith('Powered by') and len(x.strip()) > 0] 
    tabulation = False
    if minus_strip == plus_strip:
        tabulation = True
    lengths = {
        'before' : len(bfr),
        'plus' : len(plus),
        'minus' : len(rem),
        'after' : len(aft)
    }

        
    my_results = {}
    
    if len(tmp_arr) > 1: #if more than one file is possible, we check if there are files on the correct relative path and use only those
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
                    
        if buffer == "none" or len(buffer) == 0:
            return [None, []]
    

        extension = tmp.split('.')[-1]    
        
        
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

                
        for i in range(len(buffer)):
           
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

            
            if len(minus_strip) > 0 and tempo_line == minus_strip[0].strip() and i != len(buffer) - 1:

                if tools.compare_block(lengths, bfr_strip, plus_strip, minus_strip, aft_strip, buffer, i, used, extension):
                    #print(item[4] + ' block FOUND!!!')
                    import_val = False
                    if all(x.startswith('import') for x in minus_strip):
                        import_val = True
                    reptmp = {
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
                        'tabulation' : tabulation
                    }
                    my_results[file_count] = reptmp
                    #return reptmp
                    
            
            elif i == len(buffer) - 1:
                if len(plus_strip) > 0 and len(minus_strip) == 0: #add only
                    ret_stat = False
                    if all(x.strip().startswith('import') for x in plus_strip):
                        ret_stat = True
                    
                    if len(struct.strip()) == 0: #if the repo directory is empty we cant find the right file 'we need to find a way to check for these CVEs '
                        reptmp = {
                            'CVE': 'patch found'
                        }
                        my_results[file_count] = reptmp
                    elif optional_path == True and 'hardware' not in tmp0:
                        reptmp = {
                            'CVE': 'patch found',
                            'BUG' : 'patch found',
                            'range' : 'patch found',
                            'rem' : 'patch found',
                            'plus' : 'patch found',
                            'context_bfr' : 'patch found',
                            'context_aft' : 'patch found',
                            'file' : 'patch found',
                            'type' : 'patch found',
                            'import' : 'patch found'
                        }
                        my_results[file_count] = reptmp
                    elif tools.test_adding(bfr, aft, buffer, plus_strip, used, bfr_strip, aft_strip, minus_strip, extension ) == False:
                        reptmp = {
                            'CVE': item['CVE'],
                            'BUG' : item['bug'],
                            'range' : item['ind_range'],
                            'rem' : item['rem'],
                            'plus' : item['plus'],
                            'context_bfr' : item['context_bfr'],
                            'context_aft' : item['context_aft'],
                            'file' : tmp,
                            'type' : 'add',
                            'import' : ret_stat,
                            'tabulation' : tabulation
                        }
                        my_results[file_count] = reptmp
                    else:
                        reptmp = {
                            'CVE': 'patch found',
                            'BUG' : 'patch found',
                            'range' : 'patch found',
                            'rem' : 'patch found',
                            'plus' : 'patch found',
                            'context_bfr' : 'patch found',
                            'context_aft' : 'patch found',
                            'file' : 'patch found',
                            'type' : 'patch found',
                            'import' : 'patch found'
                        }
                        my_results[file_count] = reptmp
                else:
                    if len(my_results) == 0:
                        return [None, []]
    if 'hardware' in tmp0:
        for i2 in my_results:
            if 'CVE' in my_results[i2]['CVE']:
                return [my_results[i2], []]
        return [None, []]
                               
    else:
        for i2 in my_results:
            if my_results[i2]['CVE'] == 'patch found':
                return [None, []]
        
    return [my_results[0], []]
   

def run():
    debug = sys.argv[5]
    global report
    report = list()
    global report2
    report2 = list()
    failed = dict()
    
    argv1 = sys.argv[1]
    system = argv1.split('/')[-1].strip()
    argv2 = sys.argv[2]
    argv3 = sys.arg[3]
    if argv3 not in ['ture','false']:
        argv3 = 'false'
    if len(sys.argv) < 5:
        arvg4 = 85.5
    else:
        try:
            argv4 = int(sys.argv[4])
        except:
            argv4 = 85.5
    

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
        link = mysql.connector.connect(user='root', password='',
                              host='127.0.0.1',
                              database='mydata',
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
        print('Nothing to do, please check your database is available')
        sys.exit()
    print('Starting Layer 1...')
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
    
    
    with multiprocessing.Pool() as pool:
        report = []
        with tqdm(total=len(records)) as pbar:
            task00 = partial(task01, fol=sys.argv[1])
            for result in pool.imap(task01, records):
                pbar.update(1)
                result_val, avoid_res = result[0], result[1]
                if result_val is not None:
                    report.append(result_val)
                                
                if len(avoid_res) > 0:
                    my_k = avoid_res[0] 
                    my_v = avoid_res[1]
                    if my_k in failed.keys():
                        failed[my_k].append(my_v)
                    else:
                        failed[my_k] = [my_v]

    savepath = argv2
    if debug == True:
        with open(savepath + "/cvereport.json", 'w') as m:
            json.dump(report, m) 
            m.close()

    for row in blocks:
        consider = False
        ty = 'add'        
        res = [x for x in report if x['CVE'].strip() == row['CVE'] and x['BUG'].strip() == row['bug'].strip()]
        for ind_x, x in enumerate(res):
            if x['tabulation'] == True:
                if x['type'] == 'replace':
                    del res[del_ind] #this check if a resul is a tabulation change only, and remove the bug result
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
            if found > int(row['count'] / 2) and found_rep >= int(row['replace'] / 2):
                consider = True #if we find the bug in a file we consider it vulnerable (when different files are evaluated a file can contain a patch and give an erroneous result)
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
 
    if debug == True:
        with open(savepath + "/report.json", 'w') as myfile:
            json.dump(report2, myfile) 
            myfile.close()

        failed_list = list(failed)
        with open(savepath + "/avoid.json", 'w') as myfile2:
            json.dump(failed_list, myfile2) 
            myfile2.close()
        
    if argv3 == 'true':
       test(report2)

    # ===================================OPEN FOR TESTING========================================== 
    # with open(argv2 +'/report.json', 'r') as f:
    #     report2 = json.load(f)
    #     f.close()
    
    # with open(argv2 + '/cvereport.json', 'r') as f:
    #     report = json.load(f)
    #     f.close()
    #================================================================================================


    print('\nStarting Layer 2...')
    
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
                
                if i['import'] == True: #sometimes import lines are deleted and the same functionality is implemented using another lib. we ignore import lines here, since they dont contain useful patterns anyways
                    continue
                #check the extension
                ext = i['file'].split(".")[-1].strip()
                valid = ['cpp', 'cc', 'c', 'cxx', 'java', 'kt', 'kts', 'ktm']
                if ext in valid:
                    [vector, vecs] = parse_vec.parse(i['plus'], i['context_bfr'], i['context_aft'], i['file'], ext, i['range'])
                    values = []
                    if len(vecs) > 50 or len(vecs) == 0 or vecs[0] == 'Layer_1': #so many vectors means the vars are not enough to detect the right range
                        continue
                    elif vector == 'comments' or vecs[0] == 'checked':
                        values.append(100) #in this case we decide the file fully patched because the patch is a comment and there is no vulnerability on this block
                        continue
                    for v in vecs:
                        values.append(comp_vec.compare_arrays(vector, v))
                    final_vals.append(max(values))
                else:
                    final_vals.append(0) #patterns can only be read from java, c++ or kotlin. anything else is set to 0 similarity - we could try to make rules for other extensions such as xml in the future.
            #if len(final_vals) > 0 and all(x >= argv4 for x in final_vals):
                #detected.append(element)
            if len(final_vals) == 1 and any(x >= argv4 for x in final_vals):
                detected.append(element)
            #some times a patter may be broken in a patch (e.g. not returning) if we have more than one block to check we relax the requirments. 
            elif len(final_vals) > 1 and tools.check_vals(final_vals, argv4) ==  True and sum(final_vals) / len(final_vals) > 80: 
                detected.append(element)
            else:
                final_report.append(element) 
    
      
    ver = 13 #filter by version lower than...
    results = []
    arr = [row for row in common if row['CVE'] in final_report]
    for cve in arr:
        my_ver = cve['vul_true']
        if my_ver.lower() == 'all' or my_ver.lower() == 'android kernel' or len(my_ver.strip()) == 0:
            results.append(cve['CVE'])
            continue
        
        my_ver = [x for x in my_ver.replace('(', '').replace(')', '').split(',') if len(x.strip()) > 0]
        for element in my_ver:
            element = element.replace('L', '').strip()
            general = int(element.split('.')[0])
            if general <= ver:
                results.append(cve['CVE'])
                break
    
    final_report = results
    
    analisys = counts.calculate(final_report, common)
        
    now = "/final_report.txt"
    make_rep_vec = False
    with open(argv2 + now, 'w') as myfile:
        try:
            myfile.write('REPORT FOR ' + str(system) + '\nDETECTED CVEs:\n' )
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
            myfile.write('Something went wrong, please find the CVE traces in report_vec.json' )
            make_rep_vec = True   
        myfile.close()   
            
       
    if debug == True or make_rep_vec == True:
        now = "/report_vec.json"
        with open(argv2 + now, 'w') as myfile:
            json.dump(final_report, myfile) 
            myfile.close()            
    if debug == True:
        now = "/report_vec_detected.json"
        with open(argv2 + now, 'w') as myfile:
            json.dump(detected, myfile) 
            myfile.close()            
        print('==============================\nINTERMIDIATE FILES\n==============================\nAVOID: Contains CVEs related to missing files\nDETECTED_VEC: contains partial results of Layer 2 (only those that where detected during execution)\nREPORT_VEC: contains the CVEs for which we found suspicious traces\nREPORT is an intermidiate report of Layer 1 containing the block counts')
    print('All tasks done, please refer to final report.txt for our resutls\n')

if __name__ == '__main__':
    run()
    
    
