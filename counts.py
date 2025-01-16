import mysql.connector
import json


def load(file):
    with open(file,'r') as f:
        buff = f.read()
        data = buff[:buff.find(']')+1]
        buffer = json.loads(data)
        f.close()
    return buffer
    



def cia(report, dataset):
    
    result = {}
    result['confidentiality'] = {
        'none' : 0,
        'low' : 0,
        'partial' : 0,
        'high' : 0,
        'complete' : 0
    }
    result['integrity'] = {
        'none' : 0,
        'low' : 0,
        'partial' : 0,
        'high' : 0,
        'complete' : 0
    }
    result['availabilty'] = {
        'none' : 0,
        'low' : 0,
        'partial' : 0,
        'high' : 0,
        'complete' : 0
    }
    
    #attack vector, attack complexity, and user req

    result['attack_vector'] = {
        'local' : 0,
        'network' : 0,
        'adjecent_network' : 0,
        'physical' : 0
        
    }
    result['attack_complexity'] = {
        'low' : 0,
        'medium' : 0,
        'high' : 0
                
    }
    result['user_required'] = {
        'required' : 0,
        'not_required' : 0
    }

    result['type'] = {
        'app spec': 0,
        'android': 0,
        'library' : 0,
        'vendor': 0,
        'hardware': 0,
        'kernel' : 0,
        'other': 0
    }

    result['cwe'] = {}

    result['priv_req'] = {
        'none' : 0,
        'low' : 0,
        'medium' : 0,
        'high' : 0
    }

    # ==============================================================


    failed = []

    
    for rec in report:
        found = False       
        for index, value in enumerate(dataset):
            if rec == value['CVE'].strip():
                found = True
                conf_db = value['confid'].strip().upper()
                integ_db = value['integrity'].strip().upper()
                avail_db = value['availability'].strip().upper()
                type_db = value['type'].strip().lower()
                priv_req = value['req_privileges'].strip().upper()
                
                #==========================================
                complexity_db = value['attack_complexity'].strip().upper()
                vector_db = value['attack_vector'].strip().upper()
                user_req_db = value['user_req'].strip().upper()
                #===========================================

                if len(conf_db) < 2 or len(integ_db) < 2 or len(avail_db) < 2:
                    failed.append(value['CVE'].strip())
                    continue

                elif len(complexity_db) < 2 or len(vector_db) < 2 or len(user_req_db) < 2:
                    failed.append(value['CVE'].strip())
                    continue 
                                
                
                else:
                    my_info = [x.strip() for x in value['cwe_info'].split(',') if len(x) > 0]
                    for it_index, it_cwe in enumerate([x.strip() for x in value['cwe'].split(',') if len(x) > 0]):
                        if it_cwe not in result['cwe']:
                            result['cwe'][it_cwe] = {}
                            result['cwe'][it_cwe]['count'] = 1
                            try: 
                                result['cwe'][it_cwe]['detail'] = my_info[it_index]
                            except:
                                result['cwe'][it_cwe]['detail'] = ''   
                        else:
                            result['cwe'][it_cwe]['count'] += 1
                            if  len(result['cwe'][it_cwe]['detail']) == 0:
                                try: 
                                    result['cwe'][it_cwe]['detail'] = my_info[it_index]
                                except:
                                    continue  
                   
                    if conf_db == 'NONE':
                        result['confidentiality']['none'] += 1
                    elif conf_db == 'LOW':
                        result['confidentiality']['low'] += 1
                    elif conf_db == 'PARTIAL':
                        result['confidentiality']['partial'] += 1
                    elif conf_db == 'HIGH':
                        result['confidentiality']['high'] += 1
                    elif conf_db == 'COMPLETE':
                        result['confidentiality']['complete'] += 1
                        
                                    
                    if integ_db == 'NONE':
                        result['integrity']['none'] += 1
                    elif integ_db == 'LOW':
                        result['integrity']['low'] += 1
                    elif integ_db == 'PARTIAL':
                        result['integrity']['partial'] += 1
                    elif integ_db == 'HIGH':
                        result['integrity']['high'] += 1
                    elif integ_db == 'COMPLETE':
                        result['integrity']['complete'] += 1
                    
                    
                    if avail_db == 'NONE':
                        result['availabilty']['none'] += 1
                    elif avail_db == 'LOW':
                        result['availabilty']['low'] += 1
                    elif avail_db == 'PARTIAL':
                        result['availabilty']['partial'] += 1
                    elif avail_db == 'HIGH':
                        result['availabilty']['high'] += 1
                    elif avail_db == 'COMPLETE':
                        result['availabilty']['complete'] += 1
                    
                    if complexity_db == 'LOW':
                        result['attack_complexity']['low'] += 1
                    elif complexity_db == 'MEDIUM':
                        result['attack_complexity']['medium'] += 1
                    elif complexity_db == 'HIGH':
                        result['attack_complexity']['high'] += 1

                    if vector_db == 'LOCAL':
                        result['attack_vector']['local'] += 1
                    elif vector_db == 'NETWORK':
                        result['attack_vector']['network'] += 1
                    elif vector_db == 'ADJACENT_NETWORK':
                        result['attack_vector']['adjecent_network'] += 1
                    elif vector_db == 'PHYSICAL':
                        result['attack_vector']['physical'] += 1
                    
                    if user_req_db == 'FALSE' or user_req_db == 'NONE':
                        result['user_required']['not_required'] += 1
                    elif user_req_db == 'REQUIRED':
                        result['user_required']['required'] += 1

                    if type_db == "app spec":
                        result['type']['app spec'] += 1
                    elif type_db == "android":
                        result['type']['android'] += 1
                    elif type_db == "lib" :
                        result['type']['library'] += 1
                    elif type_db == "vendor":
                        result['type']['vendor'] += 1
                    elif type_db == "component" or type_db == "qualcomm":
                        result['type']['hardware'] += 1
                    elif type_db == "none" or type_db == "other":
                        result['type']['other'] += 1
                    elif type_db == "linux kernel" or type_db == "kernel" :
                        result['type']['kernel'] += 1

                    if priv_req == 'NONE':
                        result['priv_req']['none'] += 1
                    elif priv_req == 'LOW':
                        result['priv_req']['low'] += 1
                    elif priv_req == 'MEDIUM':
                        result['priv_req']['medium'] += 1
                    elif priv_req == 'HIGH':
                        result['priv_req']['high'] += 1
                            
                break
            elif index == len(dataset) - 1 and found == False:    
                failed.append(rec)
    return [result, failed]
                

def counts(report, dataset):
    low = 0
    medium = 0
    high = 0
    critical = 0
    failed = []
    for item in report:
        found = False
        for index, row in enumerate(dataset):
            if item == row['CVE'].strip():
                found = True
                if row['severity'].strip().upper() == 'LOW':
                    low += 1
                    break
                elif row['severity'].strip().upper() == 'MEDIUM':
                    medium += 1
                    break
                elif row['severity'].strip().upper() == 'HIGH':
                    high += 1
                    break
                elif row['severity'].strip().upper() == 'CRITICAL':
                    critical += 1
                    break
                else:
                    failed.append(row)
                    break
        if found == False:
            failed.append(item)
    return [low, medium, high, critical, failed]



def calculate(records, data):
   
    
    [low, medium, high, critical, failed] = counts(records, data)

                            
    tempo = {
        'critical' : critical,
        'high' : high,
        'medium' : medium,
        'low' : low 
    }
    
    arr = []
    result = {}
    result['severity'] = tempo

    [res01, failed01] = cia(records, data)
    failed = [x['CVE'] for x in failed]
    failed.extend(failed01)
    arr = list(set(failed))

    result['confidentiality'] = res01['confidentiality']
    result['integrity'] = res01['integrity']
    result['availabilty'] = res01['availabilty']
    result['attack_complexity'] = res01['attack_complexity']
    result['attack_vector'] = res01['attack_vector']
    result['user_required'] = res01['user_required']
    result['type'] = res01['type']
    result['cwe'] = res01['cwe']
    result['user_privileges'] = res01['priv_req']
    result['Missing_info'] =  list(set(arr))
    return result


