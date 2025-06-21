import copy
import os
import re
from difflib import SequenceMatcher


def fix_used_context(used2, buffer, set_lines=None):
    
    if set_lines is None:
        set_lines = []
    
    set_lines_set = set(set_lines)  
    
    def gen_combos(tokens_arr, buffer):
        buffer_lengths = [len(s) for s in buffer]
        if not buffer_lengths:
            min_len = max_len = 0
        else:
            min_len = min(buffer_lengths)
            max_len = max(buffer_lengths)
        
        buffer_clean = [x.replace(' new ', '').replace(' ', '') for x in buffer]
        buffer_clean_to_orig = {clean: orig for clean, orig in zip(buffer_clean, buffer)}
        buffer_clean_set = set(buffer_clean)
        
        result = {}
        
        for section, value in tokens_arr.items():
            result[section] = {}
            for group, sequence in value.items():
                combinations = set()
                space_checks = []
                
                for t_line in sequence['lines']:
                    t_line_clean = t_line.replace(' new ', '').replace(' ', '').strip()
                    if t_line_clean in buffer_clean_set:
                        space_checks.append({
                            'old': t_line, 
                            'new': buffer_clean_to_orig[t_line_clean]
                        })
                    elif t_line_clean + '{' in buffer_clean_set:
                        space_checks.append({
                            'old': t_line, 
                            'new': buffer_clean_to_orig[t_line_clean + '{']
                        })
                    elif t_line_clean.startswith('if') and 'else' + t_line_clean in buffer_clean_set:
                        space_checks.append({
                            'old': t_line, 
                            'new': buffer_clean_to_orig['else' + t_line_clean]
                        })
                
                tokens = sequence['tokens']
                n = len(tokens)
                
                for i in range(n):
                    combo_parts = []
                    for j in range(i, n):
                        combo_parts.append(tokens[j])
                        combo = ''.join(combo_parts)
                        combo_len = len(combo)
                   
                        if combo_len < min_len:
                            continue
                        if combo_len > max_len:
                            break
                        
                        if combo in buffer_clean_set:
                            combinations.add(combo)
                
                result[section][group] = {
                    'combinations': combinations,
                    'orig_lines': sequence['lines'],
                    'space_match': space_checks
                }
        
        return result
    
    token_pattern = re.compile(r'\s+|\w+|[^\w\s]')
    buffer_set = set(buffer) 
    
    tokens_keys = {}
    for top_key, dict_2 in used2.items():
        tokens_keys[top_key] = {}
        for second_key in dict_2.keys(): 
            if second_key not in buffer_set:
                tokens_keys[top_key][second_key] = {
                    'tokens': token_pattern.findall(second_key),
                    'missing': True
                }
            else:
                tokens_keys[top_key][second_key] = {'missing': False}
    
    
    tokens = {}
    for first_key, dict_3 in tokens_keys.items():
        tokens[first_key] = {}
        counter = 0
        tokens[first_key][counter] = {'tokens': [], 'lines': []}
        
        for second_key, token_info in dict_3.items():
            if token_info['missing']:
                if tokens[first_key][counter]['tokens']:
                    tokens[first_key][counter]['tokens'].append(' ')
                tokens[first_key][counter]['tokens'].extend(token_info['tokens'])
                tokens[first_key][counter]['lines'].append(second_key)
            else:
                counter = len(tokens[first_key])
                tokens[first_key][counter] = {'tokens': [], 'lines': []}
    
    filtered_buffer = [x for x in buffer if x not in set_lines_set]
    combos = gen_combos(tokens, filtered_buffer)
    
    reset = copy.deepcopy(used2)
    
    for key, value in combos.items():
        for key2, val2 in value.items():
            for item in val2['space_match']:
                reset[key][item['old']] -= 1
                reset[key][item['new']] = reset[key].get(item['new'], 0) + 1
            
            combinations_list = list(val2['combinations'])
            if combinations_list:
                test_line = ' '.join(combinations_list)
                
                for line in val2['orig_lines']:
                    if line.strip() in test_line:
                        test_line = test_line.replace(line, '', 1)  
                        reset[key][line] -= 1
                
                for entry in combinations_list:
                    reset[key][entry] = 1
        
        reset[key] = {k: v for k, v in reset[key].items() if v > 0}
    
    return [
        reset,
        [x.strip() for x in reset.get('plus', {}).keys()],
        [x.strip() for x in reset.get('before', {}).keys()],
        [x.strip() for x in reset.get('after', {}).keys()],
        [x.strip() for x in reset.get('minus', {}).keys()]
    ]


def fix_report(report, to_del):
    new_report = []
    for item in report:
        if item['ID'] not in to_del:
            new_report.append(item)
    return new_report




def fix_used_check(used_check, change_indices):
    new_dic = copy.deepcopy(used_check)
    new_dic['plus'] = {}
    changes = change_indices.keys()
    for key, value in used_check['plus'].items():
        if key not in changes:
            new_dic['plus'][key] =  value
        else:
            for lin in change_indices[key]:
                new_dic['plus'][lin] = value
    return new_dic      



def find_patch_comb(buffer, patch, aft_strip, bfr_strip):
    def control(j, aft_strip, bfr_strip):
        lines = [x.strip() for x in buffer[max(j-5, 0):min(j+5, len(buffer)-1)]]
        return any(x in lines for x in aft_strip) and any(x in lines for x in bfr_strip)
    my_neg = {'', '{','}'}
    new_patch = []
    indices = {}
    for line in patch:
        sequence = []
        for start in range(len(buffer)):
            if start == len(buffer) - 1:
                new_patch.append(line)
                continue
            if buffer[start].strip() not in my_neg and buffer[start].strip() in line:
                sequence.append(buffer[start].strip())
                for j in range(start+1, min(start+5, len(buffer)-1), 1):
                    if buffer[j].strip() in my_neg:
                        continue
                    elif buffer[j].strip() in line and control(j,aft_strip, bfr_strip):
                        sequence.append(buffer[j].strip())
                    else:
                        break
            if len(sequence) > 1:
                new_patch += sequence
                indices[line] = sequence
                break
            else:
                sequence = []
    return [new_patch, indices] 



def group_db(data_list):
    
    if not data_list:
        return []
    for item in data_list:
        item['_cve_sort'] = item['CVE'].strip() if isinstance(item['CVE'], str) else str(item['CVE']).strip()
        item['_bug_sort'] = item['bug'].strip() if isinstance(item['bug'], str) else str(item['bug']).strip()
        
    sorted_list = sorted(data_list, key=lambda x: (x['_cve_sort'], x['_bug_sort']))
    for item in sorted_list:
        if '_cve_sort' in item:
            del item['_cve_sort']
        if '_bug_sort' in item:
            del item['_bug_sort']
    
    return sorted_list


def group_indices(indices):
    if len(indices) == 0:
        return []
    groups = []
    current_group = []

    for index in sorted(indices):
        if not current_group or index - current_group[-1] <= 2:
            current_group.append(index)
        else:
            groups.append(current_group)
            current_group = [index]

    if current_group:
        groups.append(current_group)

    return groups

def calc_levels(lines):
    exceptions = {'{','}', ';', '};', '*'}
    comments = ['//', '* ', '/*', '*/']
    level = 0
    levels = {}
    simpletons = []
    for index in range(len(lines)-1):
        line = lines[index].strip()
        # levels[index] = level
        if line.strip().endswith('{') and len(line) > 1:
            level  += 1
        elif lines[index+1].strip() == '{':
            level += 1
        elif line.startswith('if ') and line.endswith(')') and lines[index+1].strip() != '{':
            simpletons.append(index)
            simpletons.append(index + 1)
        elif line == '}' or line.endswith('}'):
            level -= 1
            # levels[index] -= 1
        levels[index] = level
    if len(levels) == 0:
        return []
    last = max(levels.keys()) + 1
    levels[last] = levels[last - 1]
    for ind in simpletons:
        levels[ind] += 1

    
    levels0 = [x for x in levels.values()]
    # result = {}
    # result[0] = []
    # counter = 0
    # for index, input in enumerate(levels0):
    #     if input == 0:
    #         result[0].append(index)
    #     else:
    #         if index == 0 or levels0[index - 1] == 0:
    #             counter += 1
    #             st = index
    #         try:
    #             if levels0[index + 1] == 0:
    #                 result[counter] = [st, index]
    #         except:
    #             result[counter] = [st, index]
    # for key in result.keys():
    #     if key == 0:
    #         for value in result[key]:
    #             levels0[value] == 0
    #     else:
    #         for ind in range(result[key][0], result[key][1]+1):
    #             levels0[ind] = key
    
    for ind, line in enumerate(lines):
        if line.strip() in exceptions or len(line.strip()) < 1 or line.strip().startswith('android_errorWriteLog'):
            levels0[ind] = 'no'

    return [x for x in levels0 if x != 'no']

def clean_2comm(input_list):
    if not isinstance(input_list, list):
        return input_list

    result_list = []

    for item in input_list:
        item = item.replace(',,', ',splitVal')
        if isinstance(item, str):
            result_list.extend(item.split('splitVal'))
        else:
            result_list.append(item)

    return result_list

def check_indices(indices, buffer):
    try:
        bug_ind = indices['bug']
        before_ind = indices['before']
        if len(before_ind) == 0:
            before_ind.append(int(bug_ind[0]) - 5)
        after_ind = indices['after']
        if len(after_ind) == 0:
            after_ind.append(int(bug_ind[-1]) + 5)
        
        st = max(before_ind)
        if st < 0:
            st = 0
        ed = min(after_ind)
        if ed > len(buffer) - 1:
            ed = len(buffer) - 1
        
        test_lines_ind = [st]
        test_lines_ind.extend(bug_ind)
        test_lines_ind.append(ed)
        test_lines_ind = list(set(test_lines_ind))
        ftest = all(int(test_lines_ind[i]) + 1 == int(test_lines_ind[i+1]) for i in range(len(test_lines_ind) - 1))
        if ftest == True:
            return True
        else:
            test_lines = {}
            for k in test_lines_ind:
                if len(buffer[k].strip()) > 0 and not buffer[k].strip().startswith('//'):
                    test_lines[k] = buffer[k].strip()
            extra_lines = {}
            for j in range(st, ed, 1):
                t = [test_lines[h] for h in test_lines.keys()]
                if buffer[j].strip() not in t:
                    if len(buffer[j].strip()) > 0 and not buffer[j].strip().startswith('//'):
                        extra_lines[j] = buffer[j].strip() 
            for line in extra_lines.keys():
                if extra_lines[line].startswith('if ') and extra_lines[line].endswith('{'):
                    ed2 = ed
                    for it in extra_lines.keys():
                        if extra_lines[it] == '}' and it >= line:
                            ed2 = it
                    if any(x > line and x < ed2 for x in bug_ind): #an added conditional encapsulates a bug line... we cant assure the bug will be triggered
                        return False
    except:
        return True               
    
    return True
                
         



def check_vals(final_vals, val):
    counter = 0
    for num in final_vals:
        if num >= val:
            counter += 1
        if num < 60:
            return False
    return counter >= len(final_vals) / 2



def fix_bool_vars(string0):
    ret_val = []
    if '->' in string0:
        ret_0 = string0.split('->')
    else:
        ret_0 = [string0]
    
    for string in ret_0:
            
        if string.strip().startswith('('):
            string = string[string.find('(')+1:] #this is a cast
        if '.' in string and '(' in string:
            sec_par = string[string.find('(')+1:string.rfind(')')]
            sec_ins = string[:string.find('(')]
            if '.' in sec_ins:
                ret_val.append(sec_ins.split('.')[0].strip())
            else:
                ret_val.append(sec_ins.strip())
            if len(sec_par) > 0:
                if ',' in sec_par:
                    ret_val += sec_par.split(',')
                elif '.' in sec_par:
                    ret_val.append(sec_par.split('.')[-1].strip())
                else:
                    ret_val.append(sec_par.strip())
                
        elif '.' in string and '(' not in string:
            ret_val.append(string.split('.')[0].strip())
        
        elif '(' in string and ')' in string:
            sec_par = string[string.find('(')+1:string.rfind(')')]
            if len(sec_par) > 0:
                if ',' in sec_par:
                    ret_val += sec_par.split(',')
                else:
                    ret_val.append(sec_par)
            else:
                ret_val.append(string[:string.find(')')].strip())
        else:
            ret_val.append(string)
    if len(ret_val) > 0:
        for ind, ret in enumerate(ret_val):
            if ret.startswith('!') or ret.startswith('*') or ret.startswith('&'):
                ret_val[ind] = ret[1:]
    return ret_val

def fix_param(param):
    operators = [' < ',' > ',' == ', ' != ', ' <= ', ' >= ']
    operators2 = [' + ',' - ',' * ',' / ']
    
    open_par = 0
    close_par = 0
    for char in param:
        if char == '(':
            open_par += 1
        if char == ')':
            close_par += 1
    if param.startswith('(') and param.endswith(')') and close_par == open_par:
        param = param[1:-1]
    elif param.startswith('(') and open_par > close_par:
        param = param[1:]
    if param.endswith(')') and close_par > open_par:
        param = param[:-1]

    for op in operators:
        if op in param:
            arr = param.split(op)
            for ind, item in enumerate(arr):
                for op2 in operators2:
                    if op2 in item:
                        arr2 = item.split(op2)
                        for j in arr2:
                            if j.strip().endswith('_MAX') or j.strip().endswith('_MIN'):
                                temp = item.replace(j, '')
                                arr[ind] = temp.replace(op2, '').strip()
            
            return op.join(arr)
    return param

def split_blocks(indices):
    blocks = []
    current_block = []

    for i, num in enumerate(indices):
        if i == 0 or num == indices[i - 1] + 1:
            current_block.append(num)
        else:
            blocks.append(current_block)
            current_block = [num]
    
    if current_block:
        if len(current_block) > 1:
            blocks.append(current_block)
    
    return blocks

def get_par_tup(params):
    results = []
    indices = []
    split_vals_res = []
    for ind, char in enumerate(params):
        if char == '(':
            indices.append(ind)
        elif char == ')':
            try:
                results.append([indices[-1], ind])
                indices = indices[:-1]
            except:
                if len(indices) == 0:
                    results.append([0, ind])
            
        elif char in ['&', '|'] and len(indices) == 0:
            if ind < len(params) - 1:
                if params[ind+1] == char and ind-1 not in split_vals_res: #the first character is equal to the second one
                    split_vals_res.append(ind)
        
    return [results, split_vals_res]




def split_cond_pars(params, mode=0):
    [results, split_vals_res] = get_par_tup(params)
    new_params = []
    if len(split_vals_res) > 0:
        last_val = 0
        for v in split_vals_res:
            new_params.append(params[last_val:v].strip())
            last_val = v+2
        new_params.append(params[last_val:].strip())
    else:
        new_params = [params.strip()]
    new_params = [x.strip() for x in new_params if len(x.strip()) > 0]
    operators = [' < ',' > ', ' != ', ' <= ', ' >= ']
    my_result = {}
    for param in new_params:
        
        #sometimes a parenthesizes condition may have different comparisons inside, we still take the type form the "outermost" condition we got in the first step
        test = copy.deepcopy(param)
        if '(' in param and ')' in param:
            [res_par_param, split_param] = get_par_tup(param)
            for parind, par in enumerate(res_par_param): #clean outermost parenthesis if they are a related pair. 
                if par[0] == 0 and par[1] == len(param) - 1:
                    param = param[1:-1]
                    del res_par_param[parind]
                    if len(res_par_param) > 0:
                        for indp, pair in enumerate(res_par_param):
                            res_par_param[indp][0] = res_par_param[indp][0] - 1
                    break

            for par in res_par_param:
                test = test.replace(test[par[0]:par[1]+1], '')
            #here I extract the variables from param (test was used only for geting the type)
            tmp_arr = []
            st = 0
            for start, end in res_par_param:
                test_par = param[st:start].strip()
                if test_par.strip().split(' ')[0].strip() in ['==', '<','>', '!=', '<=', '>=']:
                    test_par = test_par[2:].strip() #the number of char
                tmp_arr.append(test_par)
                tmp_arr.append(param[start+1:end].strip())
                st = end + 1

            test_par = param[st:].strip()
            if test_par.strip().split(' ')[0].strip() in ['==', '<','>', '!=', '<=', '>=']:
                test_par = test_par[2:].strip() 
            tmp_arr.append(test_par)
            #a patch may contain a partial conditional as context, if the last entry is a split sign it will add an empty param,0 which will give an error (empty var-class in split_struct)
            tmp_arr = [x.strip() for x in tmp_arr if len(x.strip()) > 0 and x.strip() != '(' and x.strip() != ')']
        else:
            tmp_arr = [param]


        if ' == ' in test:
            cond_type = 'e'
        elif any(x in test for x in operators):
            cond_type = 'c'
        else:
            cond_type = 'b'
        
        cond_vars = []
        #here I work with each para to take the vars, first check there is no && or || sign in a parenthesized section.
        arr = []
        for p in tmp_arr:
            if '&&' in p and '||' not in p:
                    arr0 = [x.strip() for x in p.split('&&')]
                    for x in arr0:
                        arr.append(x)
            elif '||' in p and '&&' not in p:
                arr0 = [x.strip() for x in p.split('||')]
                for x in arr0:
                    arr.append(x)
            elif '&&' in p and '||' in p:
                arr = []
                arr0 = [x.strip() for x in p.split('&&')]
                for j in arr0:
                    if '||' in j:
                        t = j.split('||')
                        for k in t:
                            arr.append(k.strip())
                    else:
                        arr.append(j.strip())
            else:
                arr.append(p) 
        
        arr3 = [] #trying to carefully select parts of methods and variables lists.
        pattern = r"(?=.*[A-Z_])[A-Z_]+"
        for idx, a in enumerate(arr):
            if '(' in a and ')' in a:
                one = a[:a.find('(')]
                two = a[a.find('(')+1: a.rfind(')')]
                if len(two.strip()) > 0:
                    if ',' in two:
                        tmp_arr_com = two.split(',')
                        for element in tmp_arr_com:
                            if '.' in element:
                                ele2 = [x.strip() for x in element.split('.') if len(x.strip()) > 0]
                                if re.match(pattern, ele2[-1]):
                                    arr3.append(ele2[-1])
                                else:
                                    arr3.append(ele2[0])
                            else:
                                arr3.append(element)
                if '.' in one:
                    ele2 = [x.strip() for x in one.split('.') if len(x.strip()) > 0]
                    if re.match(pattern, ele2[-1]):
                        arr3.append(ele2[-1])
                    else:
                        arr3.append(ele2[0])
                else:
                    arr3.append(one)
            else:
                arr3.append(a)
        
        arr2 = []
        for a in arr3:
            done = False
            for spl_val in [' == ',' != ',' > ',' < ',' >= ', ' <= ', ' &= ', ' |= ', ' += ',' -= ',' *= ', ' /= ']:
                if spl_val in a:
                    done = True
                    for el in [x.strip() for x in a.split(spl_val)]:
                        arr2.append(el)
            if done == False:
                arr2.append(a)

        arr3 = []
        for a in arr2:
            if ',' in a:
                tmp_arr_com = a.split(',')
                for element in tmp_arr_com:
                    if '.' in element:
                        ele2 = [x.strip() for x in element.split('.') if len(x.strip()) > 0]
                        if re.match(pattern, ele2[-1]):
                            arr3.append(ele2[-1])
                        else:
                            arr3.append(ele2[0])
                    else:
                        arr3.append(element)
            elif '.' in a:
                ele2 = [x.strip() for x in a.split('.') if len(x.strip()) > 0]
                if re.match(pattern, ele2[-1]):
                    arr3.append(ele2[-1])
                else:
                    arr3.append(ele2[0])
            else:
                arr3.append(a)

        for idx, a in enumerate(arr3): #remove any external parenthesis that may have survived the previous step ... should never happen but we want to make sure
            if a.startswith('(') and a.endswith(')'):
                arr[idx] = a[1:-1]
            a = fix_param(a)
            if cond_type == 'b':
                if a.endswith(";"):
                    a = a[:-1]
                if any(a.startswith(o) for o in ['*', '&', '!']):
                    a = a[1:] #avoid pointer markers
                bool_vars = fix_bool_vars(a)
                for v1 in bool_vars:
                    if v1.startswith('!'): #avoid not signs to keep relationships alive
                        v1 = v1[1:]
                    if '.' in v1 and v1.split('.')[0].strip() == 'this':
                        v1 = v1[v1.find('.')+1:].strip()
                    if "instanceof" in v1:
                        v1 = v1.strip().split(" ")[0]        
                    cond_vars.append(v1)
            else:
              
                vars_t = a
                operators2 = [' + ',' - ',' * ',' / ']
                vars2 = []
                vars02 = []
                vars_t = split2_param(vars_t)
                for var0 in vars_t:
                        counter_t = 0
                        for ch in var0:
                            if ch == '(':
                                counter_t += 1
                            elif ch == ')':
                                counter_t -= 1
                        if counter_t == 0 and var0.startswith('(') and var0.endswith(')'):
                            var0 = var0[1:-1]
                        if all(x not in var0 for x in operators2):
                            if '.' in var0:
                                 
                                vars02 += [x for x in fix_vars(['', var0]) if x.lower() != 'context']
                                
                            else:
                                vars02.append(var0.strip())        
                        else:
                            for oper in operators2:
                                if oper in var0:
                                    tv = var0.split(oper)
                                    for i in tv:
                                        vars02.append(i)
                    
                for var in vars02:
                    p01 = var[var.find('(') + 1: var.rfind(')')]
                    if '(' in var and ')' in var and len(p01) > 1:
                        if p01.endswith('*'):
                            p01 = p01[:-1].strip()
                        if var[:var.find('(')] != 'sizeof':
                            vars2.append(var[:var.find('(')])
                        if ',' in p01:
                            vars2 += [x.strip() for x in p01.split(',')]
                        else:
                            if '(' in p01 and ')' in p01:
                                t10 = p01[p01.find('(')+1:p01.rfind(')')].strip()
                                if len(t10) > 0:
                                    if ',' in t10:
                                        vars2 += [x.strip() for x in t10.split(',')]
                                    else:
                                        vars2.append(t10)
                                else:
                                    vars2.append(p01)
                            else:
                                vars2.append(p01)
                    else:
                        if var.endswith('*'):
                            var = var[:-1].strip()
                        vars2.append(var)
                
                for var in vars2:
                        if len(var.strip()) == 0:
                            continue
                        if var.startswith('!'):
                            var = var[1:] 
                        if '.' in var and var.split('.')[0].strip() == 'this':
                            var = var[var.find('.')+1:].strip()
                        if var.strip().endswith(";"):
                            var = var.strip()[:len(var.strip())-1]
                        if var.startswith('&') or var.startswith('*'):
                            var = var[1:] #avoid pointer markers    
                        cond_vars.append(var)
        cond_vars = [x for x in cond_vars if len(x.strip()) > 0]
        my_result[param] = {
            'type' : cond_type,
            'vars' : cond_vars
        }
    if mode == 0:    
        return my_result
    else:
        alt_ret = []
        for p in my_result:
            alt_ret.extend([x.strip() for x in my_result[p]['vars']])
        


def check_equality(lines, prev_lines): #this checks if an instruction is assigned to a variable making it an assignment line. if it does, it fixes the issue. 
    res = False
    for lin_ind, lin in enumerate(lines):
        for lin_p in prev_lines:
            if (' = ' in lin) ^ (' = ' in lin_p):
                if ' = ' in lin:
                    cmp2 = lin.split(' = ')[1].strip()
                    cmp1 = lin_p
                else:
                    cmp2 = lin_p.split(' = ')[1].strip()
                    cmp1 = lin
                if get_similarity_ratio(cmp1, cmp2) >= 0.85:
                    lines[lin_ind] = lin_p
                    res = True
                    break
            
            # elif lin.startswith('if') and lin_p.startswith('if'):
            #     cond_lin = lin[lin.find('(') + 1:lin.rfind(')')].strip()
            #     cond_lin_p = lin_p[lin_p.find('(') + 1:lin_p.rfind(')')].strip()
            #     if cond_lin.startswith('0 ==') and cond_lin_p.startswith('!'):
            #         if get_similarity_ratio(cond_lin.replace('0 ==', '').strip(), cond_lin_p.replace('!', '').strip()) == 1:
            #             lines[lin_ind] = lin_p
            #             break
            #     elif cond_lin_p.startswith('0 ==') and cond_lin.startswith('!'):
            #         if get_similarity_ratio(cond_lin.replace('!', '').strip(), cond_lin_p.replace('0 ==', '').strip()) >= 0.9:
            #             lines[lin_ind] = lin_p
            #             break
                
    return [lines, res]



def test_diff_par(string_arr):
    result = []
    signs = ['+','-','/','*']
    for string in string_arr:
        string = string.strip()
        if string.endswith(');'):
            string = string[:-1]
        
        my_chuncks = [string]
        inf_loop_guard = 0
        while any(')' in x and '(' in x for x in my_chuncks):
            inf_loop_guard += 1
            temporal = []
            for c in my_chuncks:
                if not any(x in c for x in ['(',')']) or (')' in c and '(' not in c) or ('(' in c and ')' not in c):
                    temporal.append(c)
                else:
                    [tempo, spl_values] = get_par_tup(c)
                    for ind_pair, pair in enumerate(tempo):
                        if pair[0] == 0 and pair[1] == len(c) - 1:
                            c = c[1:-1]
                            del tempo[ind_pair]
                            if len(tempo) > 0:
                                for ind, p in enumerate(tempo):
                                    tempo[ind][0] = tempo[ind][0] - 1 
                            break 
                    if len(tempo) > 0:
                        st = 0
                        for start, end in tempo:
                            temporal.append(c[st:start])
                            temporal.append(c[start+1:end].strip())
                            st = end + 1
                        if st < len(c) - 1:
                            temporal.append(c[st:].strip())
            my_chuncks = [x.strip() for x in temporal if len(x.strip()) > 0 and x.strip() != '(' and x.strip() != ')']
            if inf_loop_guard == 10: #there is no reason to get stuck in an infinite loop, but just in case....
                break

        signs = [' + ','-',' * ',' / ']
        for one in my_chuncks:
            if one.startswith('('): #in case a starting or endin parenthesis survived and got attahced to our param
                one = one[1:]
            if one.endswith(')'):
                one = one[:-1]
            #here are no parenthesis but it may be []
            arr0 = []

            open = 0
            dont_do_it = []
            indices = []
            for index, char in enumerate(one):
                if char == '[':
                    open += 1
                    indices.append(index)
                elif char == ']':
                    open -= 1
                    if open == 0:
                        dont_do_it.append([indices[-1], index])
                        indices = indices[:-1]
            
            indices = [] #this have the split indices
            for sign in signs:
                for index, char in enumerate(one):
                    if char == sign:
                        if len(dont_do_it) > 0:
                            add = True
                            for st, ed in dont_do_it:
                                if index > st and index < ed:
                                    add = False
                            if add == True:
                                indices.append(index)
                        else:
                            indices.append(index)
                           
            if len(indices) > 0:
                st = 0
                for ind in indices:
                    arr0.append(one[st:ind].strip())
                    st = ind+2
                arr0.append(one[st:].strip())
            else:
                arr0.append(one.strip())
            
            elements = []
            for item in arr0:
                if '[' in item and ']' in item:
                    arr_tmp = [item[:item.find('[')], item[item.find('[')+1:item.find(']')], item[item.find(']'):]]
                    for k in arr_tmp:
                        if '->' in k:
                            elements.extend([x.strip() for x in k.split('->')])
                        else:
                            elements.append(k)
                elif '->' in item:
                    elements.extend([x.strip() for x in item.split('->')])
                else:
                    elements.append(item)
            
            result2 = []
            for el in elements:
                done = False
                for sign in signs:
                    if sign in el:
                        done = True
                        result2.extend([x.strip() for x in el.split(sign)])
                        break
                if done == False:
                    result2.append(el)
            
            for res in result2:
                if res.strip().startswith('>'): #we think some > signs may have stayed in the individual variables.
                    res = res.strip()[1:].strip()
                if ',' in res:
                    result.extend([x.strip() for x in res.split(',')])
                else:
                    result.append(res)
     
    ret_v = [x.strip() for x in result if len(x.strip()) > 0 and x.strip() not in ['>',';',')', '&', ']', '];']]
    return [x.strip() for x in ret_v if not any(x.startswith(k) for k in ['get','set'])]
        
def check_open_par(string, x):
    indices = []
    if '(' not in string:
        return [True, []]
    open = 0
    for index, char in enumerate(string):
        if char == '(':
            open += 1
        elif char == ')':
            open -= 1
        elif char == x and open == 0 and string[index+1] != '>':
            indices.append(index)
    if len(indices) == 0:
        return [False, []]
    else:
        return [True, indices]

def check_null(values, present_value, line, bfr_strip, plus_strip, minus_strip, aft_strip, mode, used_check={}):
    used_check = {
        key: used_check.get(key, {}) for key in ['before', 'plus', 'minus', 'after']
    }

    strips = {
        'before': bfr_strip,
        'plus': plus_strip,
        'minus': minus_strip,
        'after': aft_strip,
    }
    other_values = [v for v in values if v != present_value]
    for val in other_values:
        ext_line = copy.deepcopy(line).replace(present_value, val)
        if mode == 0:
            for key in strips:
                if ext_line in strips[key] and line not in strips[key] and used_check[key].get(ext_line, 0) > 0:
                    return ext_line
        elif mode == 1:
            if ext_line in plus_strip and line not in plus_strip:
                return ext_line

    return line

# def check_null(values, present_value, line, bfr_strip, plus_strip, minus_strip, aft_strip, mode, used_check = {}):
#     my_values = [x for x in values if x != present_value]
#     for val in my_values:
#         ext_line = copy.deepcopy(line).replace(present_value, val) 
#         if mode == 0:
#             if ext_line in bfr_strip and line not in bfr_strip and used_check['before'][ext_line] > 0:
#                 return ext_line
#             elif ext_line in plus_strip and line not in plus_strip and used_check['plus'][ext_line] > 0:
#                 return ext_line
#             elif ext_line in minus_strip and line not in minus_strip and used_check['minus'][ext_line] > 0:
#                 return ext_line
#             elif ext_line in aft_strip and line not in aft_strip and used_check['after'][ext_line] > 0:
#                 return ext_line
#         elif mode == 1:
#             if ext_line in plus_strip and line not in plus_strip:
#                 return ext_line
#     return line

    
  

def check_combinations_and_match(t_line, line, t_line_subs, line_subs):
    line_subs2 = copy.deepcopy(line_subs)
    if not line_subs2:
        modified_line = line
        for t_sub, l_sub in zip(t_line_subs, line_subs2):
            modified_line = modified_line.replace(l_sub, t_sub)
        return get_similarity_ratio(modified_line, t_line) > 0.8

    l_sub = line_subs2.pop()
    for t_sub in t_line_subs:
        if check_combinations_and_match(t_line, line.replace(l_sub, t_sub), t_line_subs, line_subs2.copy()):
            return True

    return False


def placeholder_check(line, plus_strip):
    pattern = r"(?=.*[A-Z_])[A-Z_]+"
    line_subs = re.findall(pattern, line)
    line_subs = [x.strip() for x in line_subs if len(x) > 3 and '_' in x]
    if len(line_subs) > 0 and '_FLAG' in line: #this function only tries to fix imported flags (is common to see these particular changes in the patch over time) any other op will be treated normally. 
        for t_line in plus_strip:
            t_line_subs = re.findall(pattern, t_line)
            t_line_subs = [x.strip() for x in t_line_subs if len(x) > 0 and '_' in x]
            if check_combinations_and_match(t_line, line, t_line_subs, line_subs):
                return [line, t_line]

   
    elif 'mutex' in line.lower() and ' ' in line.strip():
        for t_line in plus_strip:
            if 'mutex' in t_line.lower() and ' ' in t_line.strip():
                t_x = t_line.split(' ')
                t_ar = line.split(' ')
                if t_x[1].strip() == t_ar[1].strip():
                    return [line, t_line]
   
    else:
        
        return ['placeholder', line]
    
    
    
def get_similarity_ratio(path, path_arr):
    return SequenceMatcher(None, path, path_arr).ratio()

def is_line_complete(line): #this needs a better implementation, is messy and can lead to a wrongly reconstructed intruction.
    is_log = False
    if '(' in line and 'LOG' in line.strip()[:line.find('(')]:
        is_log = True
    test_val = 0
    for ch in line:
        if ch == '(':
            test_val += 1
        if ch == ')':
            test_val -= 1
    
    if ' << ' in line and ';' not in line and is_log == True:
        test_val = 1
    elif ' << ' and ';' in line:
        test_val = 0
    if line.strip().endswith(',') and test_val == 0:
        test_val += 1
    return test_val

def fix_segmented(lines):
    block = []
    skip = False
    for index in range(len(lines)):
                
        if index == len(lines) -1 : #this closes any open parenthesis so we can extract variables. 
            if skip == False:
                count = is_line_complete(lines[index])
                if count > 0:
                    for i in range(count):
                        if lines[index].strip().startswith('if') and ')' in lines[index] and not lines[index].strip().endswith(')'):
                            lines[index] += ');'
                        else:
                            lines[index] += ')'
                block.append(lines[index].strip())
            continue
        
        if skip == True: #this skips the lines joined together. 
            counter -= 1
            if counter == 1:
                skip = False
            continue
        
        status = is_line_complete(lines[index])
        if status > 0 or lines[index].strip().endswith(' ='):
            new_line = lines[index].strip()
            counter = 1
            skip = True
            while (status > 0 or new_line.endswith(' =')) and index+counter < len(lines):
                new_line += " " +lines[index+counter].strip()
                counter += 1
                status = is_line_complete(new_line)
            
            if index+counter == len(lines):
                count = is_line_complete(new_line)
                if count > 0:
                    for i in range(count):
                        new_line += ')'
            
            block.append(new_line)
            continue
                      
        elif ' = ' in lines[index]: #this fixes double assignments in one line
            test_double = lines[index].split(' = ')
            if len(test_double) == 3:
                block.append(test_double[0].strip() + ' = ' + test_double[2].strip())
                block.append(test_double[1].strip() + ' = ' + test_double[2].strip())
                continue 

        block.append(lines[index].strip())

    #here all the intruction are reconstructed. we check for simple conditionals containing an instruction that need to be splitted
    block2 = []
    for item in block:
        end_par = find_end_par(item)
        if end_par < len(item) - 1:
            end_par += 1
        
        if item.startswith('if '):
            if '{' in item and not item.endswith('{'): #some coders may have wrote intructions in the same line between {}
                if item.endswith('}'):
                    end_stat = item.rfind('}')
                else:
                    end_stat = len(item) - 1
                block2.append(item[:item.find('{')+1])
                if ';' in item[item.find('{') + 1: end_stat]:
                    block2 += [x.strip() + ';' for x in item[item.find('{') + 1: end_stat].split(';') if len(x.strip()) > 0]
                else:
                    block2.append(item[item.find('{') + 1: end_stat])
            elif '{' not in item and not item.strip().endswith(')'):
                block2.append(item[:item.find(')')+1])
                if ';' in item[end_par:]:
                    block2 += [x.strip() + ';' for x in item[end_par:].split(';') if len(x.strip()) > 0]
                else:
                    block2.append(item[end_par:])
            else:
                block2.append(item)
        else:
            block2.append(item)

    block3 = []
    avoid = []
    for ind_b2, b2_el in enumerate(block2):
        if ind_b2 == len(block2) - 1 and ind_b2 not in avoid:
            block3.append(b2_el)
        else:
            if ind_b2 in avoid:
                continue 
            elif block2[ind_b2 + 1].strip().startswith('.'):
                block3.append(b2_el + block2[ind_b2 + 1])
                avoid.append(ind_b2 + 1)
            else:
                block3.append(b2_el)
    
    return block3


def adjust_lines(lines, bfr_s, aft_s, plus_s, extension):
    comments = ['//', '* ', '/*', '*/', '{', '}', 'Powered by']
    valid_c = ['c', 'cpp', 'cc', 'cxx', 'h']
    if extension.strip() not in valid_c:
        comments.append('#') 
    plus = clean(plus_s.split(",+"))
    if len(plus) > 0 and plus[0].strip().startswith("+"):
        if plus[0].strip() == "+":
            del plus[0]
        else:
            plus[0] = plus[0][1:].strip()   
    bfr = [x.strip() for x in  clean(fixsplit(bfr_s).split("`"), 0) if not any(x.strip().startswith(k) for k in comments) and len(x.strip()) > 0]
    aft = [x.strip() for x in  clean(fixsplit(aft_s).split("`"), 0) if not any(x.strip().startswith(k) for k in comments) and len(x.strip()) > 0]
    for linef_ind, linef in enumerate(aft):
        if 'Powered by' in linef:
            linef = linef[:linef.find('Powered by')]
        if linef.endswith(','):
            linef = linef[:-1]
        aft[linef_ind] = linef
    

    st_ind = 0
    ed_ind = len(lines) - 1
    for ind, l in enumerate(lines):
        if any(x in l or get_similarity_ratio(x.strip(), l.strip()) > 0.8 for x in bfr):
            st_ind = ind
            break
    for ind in range(len(lines) -1, st_ind, -1):
        if any(x in lines[ind] or get_similarity_ratio(x.strip(), lines[ind].strip()) > 0.8  and x not in ['{','}', ' '] for x in plus): 
            ed_ind = ind 
            break
        if any(x in lines[ind] or get_similarity_ratio(x.strip(), lines[ind].strip()) > 0.8 for x in aft):
            ed_ind = ind + len(aft) - 1
            break
    if ed_ind > len(lines) - 1:
        ed_ind = len(lines) - 1
    return [x.strip() for i, x in enumerate(lines) if i >= st_ind and i <= ed_ind and len(x.strip()) > 0]

def test_param_struc(line): #this checks if we need to split with , or  not
    open_par = False
    open_quotes = False
    counter = 0
    indices = []
    ret_val = False
    for ind, ch in enumerate(line):
        if ch == '"':
            if open_quotes == True:
                open_quotes = False
            else:
                open_quotes = True
        if ch == '(':
            counter += 1
            open_par = True
        elif ch == ')':
            counter -= 1
            if counter == 0: 
                open_par = False
        if ch == ',' and open_par == False and open_quotes == False:
            indices.append(ind)
    if len(indices) > 0:
        ret_val = True
    return [ret_val, indices]

def get_points_out(var0):
    final = []
    quote_open = False
    check_counter = 0
    check_opened = False
    for char_index, char_par in enumerate(var0):
        if char_par == '"':
            if quote_open == False:
                quote_open = True
            else:
                quote_open = False
        if char_par == '(':
            if check_opened == False:
                check_opened = True
            elif check_opened == True:
                check_counter += 1
        elif char_par == ')' and check_opened == True:
            if check_counter > 0:
                check_counter -= 1
            elif check_counter == 0:
                check_opened = False
        if check_opened == False and char_par == '.' and quote_open == False:
            final.append(char_index)
    
    if len(final) == 0:
        return [var0.strip()]
    else:
        points = []
        for io, o in enumerate(var0):
            if o == '.' and io in final:
                points.append(io)
        if len(points) == 0:
            return var0.strip() 
        else:
            substrings = []
            start_index = 0
            for index in points:
                substrings.append(var0[start_index:index])
                start_index = index+1
            substrings.append(var0[start_index:])
            return substrings 




def empty_par(line):
    for x in range(len(line) - 1):
        if line[x] == '(':
            line2 = line[x+1:]
            if len(line2[:line2.find(')')].strip()) > 0: 
                return False
    return True

def find_end_par(line):
    indices = []
    for ind, ch in enumerate(line):
        if ch == '(':
            indices.append(ind)
        elif ch == ')':
            if len(indices) == 1:
                return ind
            else:
                indices = indices[:-1]
    return len(line)-1 #if we cant find it it may be in the last index, so we return the end of the string

def get_params(line):
    par = line[line.find('(')+1:line.rfind(')')]
    if len(par) == 0:
        test_arr = []
    elif ',' in line[line.find('(')+1:line.rfind(')')]:
        test_arr =  [j.strip() for j in par.split(',') if len(j) > 1]
    else: 
        test_arr =  [j.strip() for j in par.split(' ') if len(j) > 1]
    return test_arr

def check_substinrgs(test, test_arr):
    counter = 0
    used = []
    for element in test:
        for arr_element in test_arr:
            if element in arr_element or arr_element in element:
                if arr_element not in used:
                    counter += 1
                    used.append(arr_element)
                    break
    return counter == len(test)

   
def loop_vars_check(params):
    result = []
    for param in params:
        if any(param.strip().endswith(x) for x in ['--', '++']):
            param = param[:-2]
        split_val = 'none'
        for split_val in [' > ',' >= ',' < ', ' <= ',' == ', ' = ']:
            if split_val in param:
                tmp = param.split(split_val)
                for a in tmp:
                    if '->' in a:
                        tmp2 = a.split('->')
                        for w in tmp2:
                            result.append(w)
                    else:
                        result.append(a)
        if split_val == 'none':
            result.append(param)
    for ind_t, t in enumerate(result):
        if len(t.split(" ")) > 1:
            result[ind_t] = t.split(" ")[-1]
    return result

def split2_param(params, mode=0):

    if type(params) == str:
        params = [params]
    result = []
    for line in params:
        split = 'n'
        if '- >' in line:
            split = '- >'
        elif '->' in line:
            split = '->'
        
        if '(' in line and ')' in line and len(split) > 1:
            i0 = line.find(split)
            i1 = line.find('(')
            i2 = line.rfind(')')
            if i0 < i1 or i0 > i2:
                result += [x.strip() for x in line.strip().split(split)]
            else:
                result.append(line.replace(split, ','))
        elif split != 'n':
            for l2 in line.split(split):
                if '[' in l2 and l2.endswith(']'):
                    var_in = l2[l2.find('[')+1:l2.rfind(']')]
                    var_out = l2.replace('[' + var_in + ']', '')
                    result.append(var_in)
                    result.append(var_out)
                else:
                    result.append(l2)


        if split == 'n':
            result.append(line)
    result2 = {}
    if mode == 1:
        for ind, res in enumerate(result):
            fin = []
            if ' + ' in res:
                fin.extend([x.strip() for x in res.split(' + ')])
            else:
                fin.append(res)
            fin = [x.strip() for x in fin if len(x.strip()) > 1]
            if len(fin) > 0:
                result2[ind] = fin
                result[ind] = ''
    if len(result2) > 0:
        for r in result2.keys():
            result[r] = result2[r][0]
            if len(result[r]) > 1:
                result.extend(result2[r][1:])
    return result



def cl(line):
    line = line.replace('(Locale.ROOT)','()').replace('(Locale.ENGLISH)','()').strip()
    return line

def combine_ifs(arr):
    try:
        if arr[len(arr) - 1].strip().startswith('if'): #this white line is to avoid out of index errors
            arr.append(' ')
    except:
        return arr #sometimes a block in the source file can be only white lines and commented lines. That would throw an exception
    ranges = {}
    skip = -1
    for index in range(len(arr)):
        if index <= skip:
            continue
        #these conditions help avoid single instruction conditionals (which will not nest anything)
        if arr[index].strip().startswith('if') and (arr[index].strip().endswith('{') or arr[index + 1].strip() == '{'): 
            range0 = index
            done = 0
            indices = []
            li = index
            finish = index
            nested = []
            while li <= len(arr) - 1:
                if '{' in arr[li]:
                    indices.append(li)
                    done += 1
                if '}' in arr[li]:
                    indices = indices[:-1]
                if arr[li].strip().startswith('if') and li > range0:
                    nested.append(li)
                if (len(indices) == 0 or li == len(arr) -1) and done > 0: 
                    if len(nested) > 0: #done helps avoid the first 2 lines where indices is still 0.
                        finish = li
                        ranges[index] = {
                            'start' : range0,
                            'end' : finish,
                            'nested' : nested
                        }
                    break
                                              
                li += 1
            skip = finish
    if len(ranges) > 0:
        for ran in ranges:
            
            line = arr[ranges[ran]['start']]
            params = line[line.find('(')+1:line.rfind(')')]
            for ind in ranges[ran]['nested']:
                arr[ind] = arr[ind][:arr[ind].find('(')] + '(' + params + ' && ' +arr[ind][arr[ind].find('(') + 1:]
            if arr[ranges[ran]['start']].startswith('if'):
                arr[ranges[ran]['start']] = ''
            if arr[ranges[ran]['start'] + 1].strip() == '{':
                arr[ranges[ran]['start']+1] = ''
            if arr[ranges[ran]['end']].strip() == '}':
                arr[ranges[ran]['end']] = ''
           
    return arr  


def is_assign(line):
    
    test = 0
    for ic, ch in enumerate(line):
        if ch == '(':
            test += 1
        if ch == ')':
            test -= 1
        if ch == '=' and line[ic+1] != '=' and line[ic-1] != '=': #is an '=' there is no adjecent '=' and is not inside parenthesis.
            return True
    return False


def fix_vars(params, mode=0):
    poss_op = [' + ', ' - ', ' * ', ' / ']
    substrings = []
    extra = []
    one = params[0]
    two = params[1].strip()
    if mode == 1:
        if params[1].strip().endswith('='):
            params[1] = params[1][:-1]
        if is_assign(params[1]):
            tmp_m1 = [x.strip() for x in params[1].split('=')]
            one = tmp_m1[0]
            two = tmp_m1[1] 
    
    test = two.split(' ')[0].strip()
    
    if '->' in one:
        one = one.split('->')
    else:
        one = [one]
    for el_one in one:
        if '(' not in el_one and len(el_one.split(" ")) > 1: #this means there is a type or a flag and a name to decleare a new variable. (since this only runs for assignment lines)
            el_one = el_one.split(" ")[-1].strip()
        if '[' in el_one and ']' in el_one:
            extra.append(el_one[el_one.find('[') + 1: el_one.rfind(']')])
            extra.append(el_one[:el_one.find('[')])
        elif len(el_one.strip()) > 0:
            extra.append(el_one)
        
        
    
    if test.startswith('(') and test.endswith(')') and not any(x in test for x in poss_op) and not '->' in test: #this is a cast
        two = (" ").join(two.split(" ")[1:])
    
    pattern = r'([&*])\([^)]*\)(?:;|\))'
    if re.match(pattern, two):
        two = two[two.find('(') + 1 : two.rfind(')')]
        if '->' in two:
            two = [x.strip() for x in two.split('->')]
    else:
        split_v = 'none'
        for x in poss_op:
            permit_spl = check_open_par(two, x)
            if permit_spl[0] ==  True:
                split_v = x
                split_arr = permit_spl[1]
        if split_v != 'none':
            if len(split_arr) > 0:
                start_i = 0
                spl_arr = []
                for i in split_arr:
                    tmp = two[start_i:i]
                    start_i = i + 1
                    spl_arr.append(tmp)
                two = spl_arr
            else:
                two = two.split(split_v)
        else:
            two = [two]
        

    two = test_diff_par(two)        
    for el_two in two:
        if el_two.startswith('new '):
            el_two = el_two[3:].strip()
            if el_two[0].isupper() and el_two[1].islower():
                continue
        if el_two.strip().isdigit() and len(el_two) < 4:
            continue
            
        if '(' in el_two and ')' in el_two and empty_par(el_two):
            
            if '.' in el_two:
                extra.append(el_two.split('.')[0])
            elif ' ' in el_two.strip():
                extra.append(el_two.split(' ')[-1])
            elif ',' in el_two.strip():
                extra += [x.strip() for x in el_two.split(',')]
            else:
                extra.append(el_two)

        elif '(' in el_two and ')' in el_two and len(el_two[el_two.find('(')+1:el_two.rfind(')')].strip()) > 0:
            test_append = el_two[:el_two.find('(')]
            if not any(x in test_append for x in ['.', ',', ' * ', ' + ', ' - ', ' / ']):
                extra.append(test_append)
                el_two = el_two[el_two.find('(') + 1: el_two.rfind(')')]

            if '.' in el_two:
                test_spl = False
                [permit, indi] = test_param_struc(el_two)
                while test_spl == False and '.' in el_two and permit == False:
                    add_test = True
                    test_spl = True
                    if '(' not in el_two:
                        break
                    else:
                        for sec in get_points_out(el_two):
                            [permit, indices] = test_param_struc(sec)
                            if permit == False:
                                if '(' not in sec:
                                    if add_test == True:
                                        extra.append(sec)
                                        add_test = False     #empty_par(sec):
                                    test_spl = False
                                    el_two = el_two.replace(sec + '.', '')
                                    el_two = el_two[el_two.find('(')+1:el_two.rfind(')')]
                            if permit == True:
                                substrings = []
                                start_index = 0
                                for index in indices:
                                    substrings.append(sec[start_index:index])
                                    start_index = index+1
                                substrings.append(sec[start_index:])
                                for p in substrings:
                                    if '(' not in p:
                                        if ',' in p:
                                            extra += [x for x in p.stplit(',') if len(x) > 0]
                                            el_two.replace(p, '')
                                        elif '.' in p:
                                            extra.append(p.stplit('.')[-1])
                                            el_two.replace(p, '')
                                    elif empty_par(sec):
                                        if '.' in p:
                                            extra += [x for x in p.split('.') if len(x) > 0 and '(' not in sec]
                                            el_two = el_two.replace(p, '')
                                        else:
                                            extra.append(p)
                                            el_two = el_two.replace(p, '')
            if '.' in el_two and '(' not in el_two and ',' not in el_two:
                extra.append(el_two.split('.')[-1])
                
            elif '.' in el_two and ',' in el_two and '(' not in el_two:
                tmp_arr = el_two.split(',')
                for t in tmp_arr:
                    if '.' in el_two:
                        extra.append(t.split('.')[-1])
                    else:
                        extra.append(t)
            elif '.' in el_two and ',' not in el_two and '(' in el_two and empty_par(el_two):
                extra += [x for x in el_two.split('.') if '(' not in x]
            
            elif ','  in el_two and '(' in el_two and not empty_par(el_two):
                [spl_permit, indices] = test_param_struc(el_two)
                if spl_permit == True:
                    start_index = 0
                    for index in indices:
                        substrings.append(el_two[start_index:index])
                        start_index = index+1
                    substrings.append(el_two[start_index:])
                else:
                    substrings = el_two.split('.')
            elif '.' in el_two and '(' in el_two and not empty_par(el_two):
                par = el_two[el_two.rfind('(') + 1 : el_two.rfind(')')].strip()
                if par.startswith('"') and par.endswith('"'):
                    extra.append(par)
                elif '.' in par and ',' not in par:
                    extra.append(par.split('.')[-1])
                elif ',' in par:
                    for item in [x.strip() for x in par.split(',')]:
                        extra.append(item.split('.')[-1])          #LAST CHANGE!       
            if len(substrings) > 0:
                for item_2 in substrings:
                    if '(' in item_2 and ')' in item_2:
                        section_par = item_2[item_2.find('(') + 1:item_2.rfind(')')]
                        section_inst = item_2[:item_2.find('(')].strip()
                        if '.' in section_inst:
                            extra.append(section_inst.split('.')[0].strip())
                        if len(section_par) > 0:
                            if '(' not in section_par:
                                if ',' in section_par and '.' not in section_par:
                                    extra += [x.strip() for x in section_par.split(',')]
                                elif '.' in section_par and ',' not in section_par:
                                    extra.append(section_par.split('.')[-1])
                                elif '.' not in section_par and ',' not in section_par:
                                    extra.append(section_par.strip())
                                else: #both are there
                                    arr = [x.strip() for x in section_par.split(',')]
                                    for item in arr:
                                        if '.' not in item:
                                            extra.append(item)
                                        else:
                                            tmp = item.split('.')[-1]
                                            if tmp.endswith('()') or tmp.startswith('get') or tmp.startswith('set'):
                                                extra.appned(item.split(".")[len(item.split(".")) - 2])
                                            else:       
                                                extra.append(item.split(".")[-1].strip())
                            else:
                                section_par2 = section_par[section_par.find('(') + 1:section_par.rfind(')')]
                                section_inst2 = section_par[:section_par.find('(')].strip()
                                if '.' in section_inst2:
                                    extra.append(section_inst2.split('.')[0].strip())
                                if len(section_par2) > 0:
                                    if '(' not in section_par2:
                                        if ',' in section_par2 and '.' not in section_par2:
                                            extra += [x.strip() for x in section_par2.split(',')]
                                        elif '.' in section_par2 and ',' not in section_par2:
                                            extra.append(section_par2.split('.')[-1])
                                        elif '.' not in section_par2 and ',' not in section_par2:
                                            extra.append(section_par2.strip())
                                        else: #both are there
                                            arr2 = [x.strip() for x in section_par2.split(',')]
                                            for item2 in arr2:
                                                if '.' not in item2:
                                                    extra.append(item2)
                                                else:
                                                    tmp2 = item2.split('.')[-1]
                                                    if tmp2.endswith('()') or tmp2.startswith('get') or tmp2.startswith('set'):
                                                        extra.appned(item2.split(".")[len(item2.split(".")) - 2])
                                                    else:       
                                                        extra.append(item2.split(".")[-1].strip())
                    else:
                        extra.append(item_2)
            elif ',' in el_two:
                extra += [x.strip().split('.')[-1] for x in el_two.split(',')]
            elif '.' not in el_two:
                extra.append(el_two)
        elif '(' in el_two and ')' in el_two and len(el_two[el_two.find('(')+1:el_two.rfind(')')].strip()) == 0:
            if '.' in el_two:
                extra.append(el_two.split('.')[0].strip())
            else:
                extra.append(el_two.split('(')[0].strip())
        
        elif '.' in el_two and '(' not in el_two:
            ti = [x.strip() for x in el_two.split('.') if len(x.strip()) > 0]
            if len(ti) == 0:
                continue
            else:
                ti = ti[0]
            if len(ti) > 1 and ti[0].isupper() and ti[1].islower():
                te = el_two.split('.')[-1].strip()
                if ',' in te:
                    for te_el in te.split(','):
                        extra.append(te_el)
                else:
                    extra.append(el_two.split('.')[-1].strip())
            else:
                te = el_two.split('.')[0].strip()
                if ',' in te:
                    for te_el in te.split(','):
                        extra.append(te_el)
                else:
                    extra.append(el_two.split('.')[0].strip())
        

        elif '.' not in el_two and '(' not in el_two and ',' not in el_two:
            extra.append(el_two)
        for index, item in enumerate(extra):
            if item.endswith(';'):
                extra[index] = item[:-1]
            if item.startswith('!') or item.startswith('*') or item.startswith('&'):
                extra[index] = item[1:]
    last_check = list(set([x.strip() for x in extra if len(x.strip()) > 0 and x.strip() != 'sizeof']))
    my_result = []
    operators = [' * ', ' + ', ' - ', ' / ']
    for var in last_check:
        if '->' in var:
            tempo = var.split('->')
            for item in tempo:
                done = False
                for op in operators:
                    if op in item:
                        my_result.extend([x.strip() for x in item.split(op)])
                        done = True
                        break
                if done == False:
                    my_result.append(item)
        else:
            insert = True
            for op in operators:
                if op in var:
                    my_result.extend([x.strip() for x in var.split(op)])
                    insert = False
                    break
            if insert == True:
                my_result.append(var)


    return my_result
        
         
        

def clean_params(line): #fixing double commas and empty spaces intside parenthesis (allowed up to this point since they are part of parameters)
    if '(' in line and ')' in line:
        pattern = r',+\s+'  
        replacement = ','    
        result = re.sub(pattern, replacement, line)
        if '(,' in result:
            result = result.replace('(,', '(') 
        if result.endswith(',)'):
            result = result[:-2] + ')'
        return result
    else:
        return line

def test_vec(vec, vec2):
    struct1 = [x.strip()[0] for x in vec.split('::')]
    struct2 = [x.strip()[0] for x in vec2.split('::')]
    if struct2[0].strip() == struct1[0].strip() and all(x in struct2 for x in struct1):
        return True            
    return False
    

def check_optional_syntax(line, array): #optional semicolon at the end of a class definition can reult in a miss-match
    if line.strip().endswith(';'):
        test_line = line.strip()[:-1]
    else:
        test_line = line.strip() + ";"
    if test_line in array and line not in array:
        return [test_line, True]
    else:
        return [line, False]


def fix_range(start, end, bfr_strip, aft_strip, minus_strip, buffer):
    s = start
    e = end
    st = start - len(bfr_strip) - 5
    if start - len(bfr_strip) - 5 < 0:
        st = 0
    
    for i in range(st, start):
        line = check_(cl(buffer[i]).strip(), bfr_strip)
        if line.startswith("double_rule"):
            line = line.split("dr_check")[1].strip()
        if any(get_similarity_ratio(line.strip(), x.strip()) >= 0.89 for x in bfr_strip):
            s = i
            break
    
    ed = 0
    test_arr = copy.deepcopy(bfr_strip)
    test_arr.extend(minus_strip) #we only take in count minus because we are interested in avoiding similar bug lines too close to eachother generating a false possitive
    end2 = end+20
    if end2 > len(buffer) - 1:
        end2 = len(buffer) - 1
    for test_index in range(end, end2):
        if any(get_similarity_ratio(buffer[test_index].strip(), x.strip()) >= 0.89 for x in test_arr):
           ed = test_index - 5 #the range will be augmented by 4 at the end, if there is an overlapping block we want to avoid it.
           e = ed
           break

    if ed == 0: #our test did not found any similar block overlapping with the analyzed one, we are fine @_@.
        ed = end + 20
    if ed > len(buffer) - 1:
        ed = len(buffer) - 1
    
    for j in range(ed, start, -1):
        line = check_(cl(buffer[j]).strip(), aft_strip) 
        if line.startswith("double_rule"):
            line = line.split("dr_check")[1].strip()

        if line.strip() in aft_strip or line.strip() in minus_strip :
            e = j
            break
    
    if e+4 < len(buffer) - 1: #just make the range a bit wider to make sure we catch all the lines (empty lines may still affect the fixed range)
        e += 4
    if s-3 > 0:
        s -= 3
    return [s,e]

 
def check_for_patch(buffer, plus_strip, minus_strip, aft_strip, bfr_strip, used2):
    
    conditions = {} 
    testarr = []
    for item in plus_strip:
        if item.strip().startswith('if '):
            if ')' in item:
                final2 = item.rfind(')')
            else:
                final2 = len(item) - 1
            testline = item[4:final2]
            if "&&" in testline:
                testarr = testline.split("&&")
            elif "||" in testline:
                testarr = testline.split("||")
            else:
                testarr = [testline]
            for i, x in enumerate(testarr):
                testarr[i] = x.strip()
            conditions[item.strip()] = testarr  

    for index, line in enumerate(buffer):
        used3 = copy.deepcopy(used2)
        line = check_(line.strip(), plus_strip)
        if line.startswith("double_rule"):
            line = line.split("dr_check")[1].strip()

        if line.startswith('if '):
            [result, key] = check_conditional(conditions, line, used3)
            if result == True and key in plus_strip:
                if line not in plus_strip:
                    line = key.strip()


        if line.strip() in plus_strip:
            context_bfr = 0
            plus_count = 0
            minus_count = 0
            aft_count = 0
            st = index - len(bfr_strip) - 5
            if st < 0:
                st = 0
            ed = index + len(aft_strip) + len(plus_strip) + 5
            if ed > len(buffer) - 1:
                ed = len(buffer) - 1
            [s,e] = fix_range(st, ed, bfr_strip, aft_strip, plus_strip, buffer)
            
            for lnm in range(s, e):
                line2 = buffer[lnm].strip()
                for group_index, group in enumerate([bfr_strip, aft_strip, plus_strip]):
                    line2 = check_(buffer[lnm].strip(), group) #this will probably never run, redundant now (example code to build the token function).... needs to be removed carefully to impove runtime.
                    if line2.startswith("double_rule"):
                        line1 = line2.split("dr_check")[1].strip()
                        line20 = line2.split("dr_check")[2].strip()
                        if line1 in group and line20 in group:
                            if group_index == 0:
                                g = 'before'
                            elif group_index == 1:
                                g = 'after'
                            else:
                                g = 'plus'
                        if used3[g][line1] > 0 and used3[g][line20] > 0:
                            if g == 'before':
                                context_bfr += 2
                            elif g == 'after':
                                aft_count += 2
                            else:
                                plus_count += 2
                            used3[g][line1] = used3[g][line1] - 1
                            used3[g][line20] = used3[g][line20] - 1
                            continue
                        else:
                            line2 = buffer[lnm]
                        
                line2 = check_(buffer[lnm].strip(), plus_strip)
                if line2.startswith("double_rule"):
                    line1 = line2.split("dr_check")[1].strip()
                    line20 = line2.split("dr_check")[2].strip()
                    if line1 in bfr_strip and line20 in bfr_strip:
                        if used3["plus"][line1] > 0 and used3["plus"][line20] > 0:
                            plus_count += 2
                            used3["plus"][line1] = used3["plus"][line1] - 1
                            used3["plus"][line20] = used3["plus"][line20] - 1
                            continue
                        else:
                            line2 = buffer[lnm]

                if line2.startswith('if '):
                    [result2, key] = check_conditional(conditions, line2, used3)
                    if result2 == True and key in plus_strip:
                        if buffer[lnm].strip() not in plus_strip:
                            line2 = key.strip()

                if line2.strip() in bfr_strip and used3["before"][line2.strip()] > 0:
                    context_bfr += 1
                    used3["before"][line2.strip()] = used3["before"][line2.strip()] - 1
                elif line2.strip() in plus_strip and used3["plus"][line2.strip()] > 0:
                    plus_count += 1
                    used3["plus"][line2.strip()] = used3["plus"][line2.strip()] - 1
                elif line2.strip() in minus_strip and used3["minus"][line2.strip()] > 0:
                    minus_count += 1
                    used3["minus"][line2.strip()] = used3["minus"][line2.strip()] - 1
                elif line2.strip() in aft_strip and used3["after"][line2.strip()] > 0:
                    aft_count += 1
                    used3["after"][line2.strip()] = used3["after"][line2.strip()] - 1
            #this may disbalance the function, need to test it!!
            difference = min(len([x for x in minus_strip if x.strip().startswith('} catch')]),len([x for x in plus_strip if x.strip().startswith('} catch')]))
            if difference > 0:
                for key, value in used3['plus'].items():
                    if key.strip().startswith('} catch') and used3['plus'][key] > 0:
                        minus_count -= difference
                        plus_count += difference #hese lines are to account for catch lines that had the same meaning but a parameter changed and is a replaced line (No layer 2).
                        break
            if plus_count == len(plus_strip) and minus_count <= 0:
                if context_bfr + aft_count >= (len(used3["after"]) + len(bfr_strip)) / 2: #the len(after) was replaced to avoid mistakes in the database cleaned during runtime (such as lines starting with Powered by.)
                    return True
            
    return False


def check_conditional(plus_conditions, line, used):
    add_at_end = []    
    testarr_2 = []
    if ')' in line:
        f2 = line.rfind(')')
    else:
        f2 = len(line)
    testline_2 = line[line.find('(')+1:f2]
    if "&&" in testline_2:
        testarr_2 = testline_2.split("&&")
    elif "||" in testline_2:
        testarr_2 = testline_2.split("||")
    else:
        testarr_2 = [testline_2]
    for j, element in enumerate(testarr_2):
        if element == '':
            testarr_2.remove(testarr_2[j])
        else:
            if element.strip().startswith('(') and element.strip().endswith(')'): 
                testarr_2[j] = element.strip()[1:len(element)-2].strip()
                add_at_end.append(element.strip()) 
            else:    
                testarr_2[j] = element.strip()
            
            if element.strip().startswith("static_cast<") or element.strip()[1:len(element.strip())-1].strip().startswith("static_cast<"):
                new_line = element[element.index(">")+ 1:].strip()
                if new_line.strip().startswith('('):
                    new_line = new_line[1:new_line.find(")")] + new_line[new_line.find(")") + 1:] 
                    add_at_end.append(new_line)
            elif 'static_cast<' in element:
                indices = []
                length = len('static_cast<')
                el = copy.deepcopy(element)
                while 'static_cast<' in el:
                    start = el.find('static_cast<')
                    end = el[start:].find('>') + start
                    if el[end+1] == '(' or el[end+2] == '(':
                        op_par = el.index('(', end)
                        try:
                            close_p = el.index(')', end)
                        except:
                            close_p = len(el) 
                        el  = el[:op_par] + el[op_par+1: close_p] 
                    el = el[:start] + el[end+1:]

                add_at_end.append(el)


    for it in add_at_end:
        testarr_2.append(it.strip())
    
    
    keys = plus_conditions.keys()
    for key in keys:
        conditions = plus_conditions[key]
        if all(x in testarr_2 for x in conditions) and used["plus"][key] > 0:
            return [True, key]
    return [False, ""]

def check_(line, list): #the entire function is covered by the tokenization function, needs to be deleted to improve runtime ---- CAREFULLY!!! no time rn...
    v2 = copy.deepcopy(line)
    lines_present = []
    t_line = copy.deepcopy(line)
    for ind, i2 in enumerate(list):
        if ind <= len(list) - 2:
            test_line = i2.strip() + " " + list[ind+1].strip()
            if test_line.strip() == line.strip():
                if len(i2) > 4 and len(list[ind+1]) > 4 and not i2.startswith("*"): 
                    return "double_rule dr_check " + i2 + "  dr_check " + list[ind+1]
        if i2 in t_line:
            lines_present.append(i2)
            t_line = t_line.replace(i2, '')
    if len(lines_present) == 2:
        return "double_rule dr_check " + lines_present[0] + "  dr_check " + lines_present[1] #separate lines in one line - ignores { - this was an added section I need to decide and leave only one
        
    if ' = ' in v2: #here we check assignments to see if any new statement is there making a missmatch
      for item in list:
          arr = item.split(" ")
          if all(x in v2 for x in arr) and 'new ' in v2:
              if len(v2.split(" ")) - len(arr) <= 2:
                  return item.strip()
    
    elif line.startswith("else if"):
        v3 = line[4:].strip()
        if v3 in list and v2 not in list:
            return v3

    elif line.startswith("if "):
        if line.endswith(")"):
            v3 = v2 + "{"
            if v3 in list:
                return v3
        elif line.endswith("{"):
            v3 = v2.replace("{", "").strip()
            if v3 in list:
                return v3
        
        else:
            return line

    t = ('').join(line.split(' ')[1:])
    if t in list:
        return t
    #here is the case of a patch line that contains more than one code line (the iverse of the frist case)
        
    return line

def test_adding(bfr, aft, buffer, plus_strip, used2, bfr_strip, aft_strip, minus_strip, extension='', mode = 0):
    #here we check for memset patches, we need a more elegant way to do it... for now this is effective enough
    #we only check if the variable is decleared directly in the stack. otherwise the rest of test_adding will run normally 
    values = [' null ', ' nullptr ', ' 0 ', ' null,', ' nullptr,', ' NULL ', ' NULL,']
    
    if len(plus_strip) == 1 and plus_strip[0].startswith('memset'):
        poss = ['if', 'else if', 'elseif', 'while', 'do', 'for']
        my_var = plus_strip[0][plus_strip[0].find('(') + 1: plus_strip[0].find(',')] #leverage the memset() syntax to read the variable
        poss_ids = [my_var + ';', my_var + '= '] #the var may be used in any other line, we want to chck assignnments and declarations only
        for index, line in enumerate(buffer):
            if any(s in line for s in poss_ids) and not any(line.startswith(x) for x in poss):
                counter = 0
                st = index - len(bfr_strip) - 3
                ed = index + len(aft_strip) + 3
                test = bfr_strip + aft_strip
                for j in range (st, ed):
                    if buffer[j].strip() in test:
                        counter += 1
                if line.strip().endswith(my_var + ';') and '= ' not in line and '* ' not in line: 
                    if counter > 0:
                        return True
                elif '= ' in line: #assingning a value to my_var
                    if '* ' not in line.strip().split('=')[0]: 
                        if counter > 0:
                            return True
                  
                    

    conditions = {}
    testarr = []
    for item in plus_strip:
        if item.strip().startswith('if '):
            if ')' in item:
                final2 = item.rfind(')')
            else:
                final2 = len(item) - 1
            testline = item[4:final2]
            if "&&" in testline:
                testarr = testline.split("&&")
            elif "||" in testline:
                testarr = testline.split("||")
            else:
                testarr = [testline]
            for i, x in enumerate(testarr):
                testarr[i] = x.strip()
            conditions[item.strip()] = testarr

    
    exceptions = {'{','}',' ', ';'}
    valid = ['cpp', 'cc', 'c', 'cxx', 'java', 'kt', 'kts', 'ktm', 'h']
    comments = ['*', '//', '/*']
    if extension not in ['cpp', 'cc', 'c', 'cxx', 'h']:
        comments.append('#')
    counter_context = 0
    
    if extension.strip() not in valid: # files like .rc cannot be analyzed using context because they may contain simple line instructions. So even if there is no context the missing inst. should be marked.
        counter_context += 1
    t_lines = plus_strip + bfr_strip + aft_strip
    for index, line in enumerate(buffer):
     
        line = cl(line)                
        if (line.strip() in used2["before"] or line.strip() in used2["after"]) and line.strip() != '@Override': #this is too common of a line, it may lead to false positives.
            counter_context += 1
            
        if index == len(buffer) - 1: #reached the last line! the patch was not found or its only partially there
            if mode == 0 and any(line.strip().startswith(tuple(comments)) for line in plus_strip):
                plus_strip = [x.strip() for x in plus_strip if not any(x.strip().startswith(k) for k in ['/*', '*'])]
                used2['plus'] = {k:v for k,v in used2['plus'].items() if k.strip() in plus_strip}
                try:
                    return test_adding(bfr, aft, buffer, plus_strip, used2, bfr_strip, aft_strip, minus_strip, extension, 1)
                except:
                    if counter_context > 0:
                        return False
                    else:
                        return True                     
            else:
                if counter_context > 0:
                    return False
                else:
                    return True
                    
        
        if extension == "rc":
            for element in plus_strip:
                if element in line.strip():
                    ext_text = line.replace(element.strip(), "")
                    if "=" in ext_text and len(ext_text.split("=")[-1].strip().split(" ") ) == 1:
                        line = element
                    elif "-" in ext_text and len(ext_text.split("-")[-1].strip().split(" ") ) == 1:
                        line = element  

        line = check_(line, plus_strip)
        if line.startswith("double_rule"):
            line = line.split("dr_check")[1].strip()

        [line, test_result] =  check_optional_syntax(line, plus_strip)
        
        old_line = 'Placeholder'
        if len(plus_strip) <= 3:
            try:
                [old_line, line] = placeholder_check(line, plus_strip)  
            except:
                old_line = 'Placeholder'                            
        
        if line.strip() in plus_strip or line.strip().startswith('if '): #added the or condition for the modified if conditional statements
            
            plus_count = 0
            only_import = all(x.startswith('import') for x in plus_strip)
                        
            con_counter = 0
            final = index + len(plus_strip) + len(aft) + 1
            if final > len(buffer) - 1:
                final = len(buffer) - 1
            
            [s,e] = fix_range(index - len(bfr), final, bfr_strip, aft_strip, minus_strip, buffer)
            reset = copy.deepcopy(used2)
            en = e
            if e < len(buffer) - 1:
                en += 1
            
            if line.startswith('import') and reset["plus"][line] > 0:
                reset["plus"][line] -= 1
                plus_count += 1

            range_indices = []
            checked = []

            for lnm in range(s,e):
                
                [blnm, test_result] =  check_optional_syntax(cl(buffer[lnm]).strip(), plus_strip)
                myline = check_(blnm.strip(), plus_strip) #this and the souble_rule are now redundant and never should run. They should be eliminated in next versions.
                if myline.strip() == old_line.strip():
                    myline = line

                if myline.startswith("double_rule"):
                    line1 = myline.split("dr_check")[1].strip()
                    line2 = myline.split("dr_check")[2].strip()
                    if line1 in plus_strip and line2 in plus_strip:
                        if reset["plus"][line1] > 0 and reset["plus"][line2] > 0:
                            plus_count += 2
                            reset["plus"][line1] = reset["plus"][line1] - 1
                            reset["plus"][line2] = reset["plus"][line2] - 1
                            continue
                        else:
                            line = blnm.strip()


                if extension == "rc":
                    for element in plus_strip:
                        if element in myline.strip():
                            ext_text = myline.replace(element.strip(), "")
                            if "=" in ext_text and len(ext_text.split("=")[-1].strip().split(" ") ) == 1:
                                myline = element
                            elif "-" in ext_text and len(ext_text.split("-")[-1].strip().split(" ") ) == 1:
                                myline = element 
                
                if blnm in exceptions:
                    continue
                else:
                    
                    for present_value in values:
                        if present_value in myline.lower():
                            myline = check_null(values, present_value, myline, bfr_strip, plus_strip, minus_strip, aft_strip, 1)
                    

                    if not any(myline.startswith(x) for x in ['if ', 'while', 'for ']): #this is to take in count lines that have some changes in variables, we dont do this in the first part (bugs) because the change may be part of the bug fix. Its the closest thing to the hash approach but without discarting changes 
                        if '(' in myline and ')' in myline and myline not in t_lines:
                            test = myline[:myline.find('(')]
                            test_par_params = get_params(myline)
                            for item in plus_strip:
                                if '(' in item and ')' in item and test in item[:item.find('(')]:
                                    test_arr = get_params(item)
                                    if len(test_arr) > 0:
                                        if check_substinrgs(test_arr, test_par_params):
                                            myline = item

                    
                    if myline in plus_strip and reset["plus"][myline] > 0:
                        plus_count += 1
                        checked.append(lnm)
                        reset["plus"][myline] = reset["plus"][myline] - 1
                    elif myline in bfr_strip  and reset["before"][myline] > 0:
                        con_counter += 1
                        range_indices.append(lnm)
                        reset["before"][myline] = reset["before"][myline] - 1
                    elif myline in aft_strip  and reset["after"][myline] > 0:
                        con_counter += 1
                        range_indices.append(lnm)
                        reset["after"][myline] = reset["after"][myline] - 1
                    
                    elif myline.startswith("if "): #and ("&&" in myline or "||" in myline):
                        [result, key] = check_conditional(conditions, myline, reset)
                        if result == True and reset["plus"][key] > 0:
                            plus_count += 1
                            checked.append(lnm)
                            reset["plus"][key] -= 1
                       
            if old_line != 'Placeholder' and 'FLAG' in old_line: #some scattered FLAGS instructions will produce false possitive, this takes care of it. Of course, changing the file to instructions will solve it and is more elegant, but it will be costly. 
                for key in reset['plus'].keys():
                    if str(key).strip().startswith('getWindow') and reset['plus'][key] > 0:
                        plus_count += 1
                        reset['plus'][key] -= 1
            
            
            #this function tries to make sure small variations are not being ignored, we allow a 25% difference in missing lines IF half of the patch and all of the context lines are detected.
            #this will work only with relativley long pathces (more than 3 lines) so we can have some assurance that we are looking at the right change site
            tot = len(reset['plus'])
            if tot >= 3 and len(range_indices) > 1 and plus_count < len(plus_strip): #at least two indices to limit, and at least one missing line 
                if plus_count >= tot / 2 and con_counter >= (len(reset['before']) + len(reset['after'])) / 2:
                        check_range = [x for x in range(range_indices[0], range_indices[-1]+1) if x not in checked and x not in range_indices]
                        missing_lines = [x.strip() for x in reset['plus'].keys() if reset['plus'][x] > 0]
                        done = set()
                        for ind in check_range:
                            for lin in missing_lines:
                                if buffer[ind].strip() in lin.strip() or lin.strip() in buffer[ind].strip():
                                    done.add(lin)
                                    break
                                elif len(lin.strip()) > 30 and get_similarity_ratio(buffer[ind].strip(), lin.strip()) >= 0.75 and lin not in done:
                                    done.add(lin)
                                    break   
                        plus_count += len(done)
                            
            
            if only_import == True and len(plus_strip) == plus_count:
                return True #imports order dont make a difference.
            len_patch = len(plus_strip)
            if extension == 'xml':
                comm_val = len([x for x in reset['plus'] if not x.strip().startswith('<!--')]) #avoiding comments
                if len_patch > 1 and plus_count - comm_val >= (len_patch - comm_val) / 2:
                    return True
           
            t_val = 0.75
            if len_patch >= 20:
                t_val = 0.6           
            if plus_count == len_patch or (len_patch > 3 and plus_count >= int(len_patch*t_val)): #found all of the added files, the patch is present. (we allow a 75% of the patch if the patch is at leas 4 lines.)
                if len(plus_strip) == 1:
                    if (extension in valid and con_counter > 0) or extension not in valid:
                        return True
                else:
                    return True
            elif len(plus_strip) > 10 and plus_count >= (len(plus_strip) * 7 / 10): #we saw some changes hard to discard and that may affect the second layer too. In large patches the 70% of the patch is enough to assure the file is not vulnerable.
                return True
            else:
                continue
    
    return False

        

def calculate_blocks(arr):
    sel_check = []
    cve = arr[0]['CVE']
    bug = arr[0]['bug']
    bugcounter = 0
    replace_count = 0
    results = list()
    test = 0
    for index, record in enumerate(arr):
        check = [record['CVE'].strip(),record['bug'].strip()]
        if cve.strip() == record['CVE'].strip() and bug.strip() == record['bug'].strip():
            bugcounter += 1
            if len(record['rem'].strip()) > 0:
                replace_count += 1
        elif cve.strip() == record['CVE'].strip() and bug.strip() != record['bug'].strip():
            tmp = {
                'CVE': cve,
                'bug' : bug,
                'count' : bugcounter,
                'replace' : replace_count
            }
            if check not in sel_check:
                results.append(tmp)
                sel_check.append(check)
            
            bug = record['bug']
            bugcounter = 1
            if len(record['rem'].strip()) > 0:
                replace_count = 1
        elif cve.strip() != record['CVE'].strip() and test > 0:
            tmp = {
                'CVE': cve,
                'bug' : bug,
                'count' : bugcounter,
                'replace' : replace_count
            }
            if check not in sel_check:
                results.append(tmp)
                sel_check.append(check)
            
            bugcounter = 1
            if len(record['rem'].strip()) > 0:
                replace_count = 1
            else:
                replace_count = 0
            cve = record['CVE']
            bug = record['bug']
        if index == len(arr) - 1:
           tmp = {
                'CVE': cve,
                'bug': bug,
                'count': bugcounter,
                'replace' : replace_count
           }
           results.append(tmp)                     
        test = 1
    return results

def walk_folder(folder):
    files0 = []
    for root, dirs, files in os.walk(folder, topdown = True):
        if len(files) > 0:
            for file in files:
                files0.append(os.path.join(root, file))
    return files0

def str_replace(string, char, index):
    return string[:index] + char + string[index+1:]
def clean(context, mode=0):
    arr = []
    for line in context:
        if len(line.strip()) > 0:
            #this replace the html special characters read by the scrapper
            line = line.replace("&lt;", "<")
            line = line.replace("&gt;", ">")
            line = line.replace("&amp;", "&")
            line = line.replace("&quot;", '"')

            if mode == 0:
                arr.append(line.strip())
            elif mode == 1:
                arr.append(str_replace(line, "", 0).strip())
    return arr

def fixsplit(text):
    test = 0
    text = text.strip()
    first_close = text.find(")")
    first_open = text.find("(")
    if first_close > 0 and (first_open == len(text)-1 or first_open == 0):
        for index in range(first_close, len(text)):
            if text[index] == "(":
                test += 1
            elif text[index] == ")":
                if test > 0:
                    test -= 1
            elif text[index] == "," and test == 0:
                text = str_replace(text, "`", index)
        if '(,' in text:
            text = text.replace('(,', '(`')        
        return text
    
    else:
     
        for index in range(len(text)):
            if text[index] == "(":
                test += 1
            elif text[index] == ")":
                if test > 0:
                    test -= 1
            elif text[index] == "," and test == 0:
                text = str_replace(text, "`", index)
        if '(,' in text:
            text = text.replace('(,', '(`')   
        return text

def test_aft(arr, start, end):
    counter = 0
    for line in arr:
        for i in range(start, end):
            if line in arr:
                counter += 1


def compare_block(lengths, bfr_strip, plus_strip, minus_strip, aft_strip, buffer, index, used, extension=''):
    valid = ['cpp', 'cc', 'c', 'cxx', 'java', 'kt', 'kts', 'ktm']
    values = [' null ',' nullptr ',' 0 ', ' null,',' nullptr,', ' NULL ', ' NULL,']
    used_check = copy.deepcopy(used)
    used_count = copy.deepcopy(used) 
    final = lengths['plus'] + lengths['minus'] + lengths['after'] + index + 3
    if final > len(buffer) - 1:
        final = len(buffer) - 1
    start = index - lengths['before'] - 3
    if start < 0:
        start = 0
         
    exceptions = {'{','}',' ', ';', ''}
    
    context_bfr = 0
    plus_count = 0
    minus_count = 0
    aft_count = 0
    
    #setting a limit equal to the rounded half of the context, but making sure is at least 1.
    lim_aft = max(1, round(len(aft_strip) / 2.0))
    lim_bfr = max(1, round(len(bfr_strip) / 2.0))
    if len(bfr_strip) == 0:
        lim_bfr = 0
    if len(aft_strip) == 0:
        lim_aft = 0
    
    [s,e] = fix_range(index, final, bfr_strip, aft_strip, minus_strip, buffer)
        
    my_indices = {
        'before' : [],
        'plus' : [],
        'bug': [],
        'after' : []
    }
    for lnum in range (s, e):
        line = cl(buffer[lnum]).strip()
        if line in exceptions:
            continue

        if extension == "rc":
            for element in plus_strip:
                if element in line.strip():
                    ext_text = line.replace(element.strip(), "")
                    if "=" in ext_text and len(ext_text.spLit("=")[-1].strip().split(" ") ) == 1:
                        line = element
                    elif "-" in ext_text and len(ext_text.split("-")[-1].strip().split(" ") ) == 1:
                        line = element
            for element in minus_strip:
                if element in line.strip():
                    ext_text = line.replace(element.strip(), "")
                    if "=" in ext_text and len(ext_text.spLit("=")[-1].strip().split(" ") ) == 1:
                        line = element
                    elif "-" in ext_text and len(ext_text.split("-")[-1].strip().split(" ") ) == 1:
                        line = element

        backup = copy.deepcopy(line)
        line = check_(line.strip(), bfr_strip)
        if line.startswith("double_rule"):  #this is for the compunded lines... 
            line1 = line.split("dr_check")[1].strip()
            line2 = line.split("dr_check")[2].strip()
            if line1 in bfr_strip and line2 in bfr_strip:
                if used_count["before"][line1] > 0 and used_count["before"][line2] > 0:
                    context_bfr += 2
                    used_count["before"][line1] = used_count["before"][line1] - 1
                    used_count["before"][line2] = used_count["before"][line2] - 1
                    continue
                else:
                    line = backup


        line = check_(line.strip(), plus_strip)
        if line.startswith("double_rule"):
            line1 = line.split("dr_check")[1].strip()
            line2 = line.split("dr_check")[2].strip()
            if line1 in plus_strip and line2 in plus_strip:
                if used_count["plus"][line1] > 0 and used_count["plus"][line2] > 0:
                    plus_count += 2
                    used_count["plus"][line1] = used_count["plus"][line1] - 1
                    used_count["plus"][line2] = used_count["plus"][line2] - 1
                    continue
                else:
                    line = backup

        line = check_(line.strip(), minus_strip)
        if line.startswith("double_rule"):   
            line1 = line.split("dr_check")[1].strip()
            line2 = line.split("dr_check")[2].strip()
            if line1 in minus_strip and line2 in minus_strip:
                if used_count["minus"][line1] > 0 and used_count["minus"][line2] > 0:
                    minus_count += 2
                    used_count["minus"][line1] = used_count["minus"][line1] - 1
                    used_count["minus"][line2] = used_count["minus"][line2] - 1
                    continue
                else:
                    line = backup

        
        line = check_(line.strip(), aft_strip)
        if line.startswith("double_rule"): 
            line1 = line.split("dr_check")[1].strip()
            line2 = line.split("dr_check")[2].strip()
            if line1 in aft_strip and line2 in aft_strip:
                if used_count["after"][line1] > 0 and used_count["after"][line2] > 0:
                    aft_count += 2
                    used_count["after"][line1] = used_count["after"][line1] - 1
                    used_count["after"][line2] = used_count["after"][line2] - 1
                    continue
                else:
                    line = backup
        
        for present_val in values:
            if present_val in line:
                line = check_null(values, present_val, line, bfr_strip, plus_strip, minus_strip, aft_strip, 0, used_count)

                        
        
        if line in bfr_strip and used_count["before"][line] > 0:
            context_bfr += 1
            used_count["before"][line] = used_count["before"][line] - 1
            my_indices['before'].append(lnum)
        elif line in plus_strip and used_count["plus"][line] > 0:
            plus_count += 1
            used_count["plus"][line] = used_count["plus"][line] - 1
            my_indices['plus'].append(lnum)
        elif line in minus_strip and used_count["minus"][line] > 0:
            minus_count += 1
            used_count["minus"][line] = used_count["minus"][line] - 1
            my_indices['bug'].append(lnum)
        elif line in aft_strip and used_count["after"][line] > 0:
            aft_count += 1
            used_count["after"][line] = used_count["after"][line] - 1
            my_indices['after'].append(lnum)

    

    if minus_count == len(minus_strip):
        if extension == 'xml':
            if aft_count == len(aft_strip) and plus_count == 0: #xml  files dont follow the same rules, so if the removed instruction is there is enough 
                return True
        else:
            if (aft_count >= lim_aft and context_bfr >= lim_bfr) and (plus_count < len(plus_strip) / 2 or plus_count == 0) : #this is because sometime a bug line may still be there but it does not affect the patch (e.g. 2022-20219 - catch line)
                
                patch_precence = check_for_patch(buffer, plus_strip, minus_strip, aft_strip, bfr_strip, used_check)
                if not patch_precence:
                    reset, plus, before, after, minus = fix_used_context(used_check, buffer, bfr_strip + plus_strip + minus_strip + aft_strip )
                    patch_precence = check_for_patch(buffer, plus, minus, after, before, reset)
                    # new_patch, change_indices = find_patch_comb(buffer, plus_strip, aft_strip, bfr_strip)
                    # if len(new_patch) > len(plus_strip):
                    #     used_check_2 = fix_used_check(used_check, change_indices)
                    #     patch_precence = check_for_patch(buffer, new_patch, minus_strip, aft_strip, bfr_strip, used_check_2)
                    
                if patch_precence == False:
                    if check_indices(my_indices, buffer) == True:
                        return True
                    else:
                        return False
            else:
                return False
    else:
        return False

        #========================================================================================================================
        # TODO: use teh parent function to check the change-site but it may affect runtime. 
        # we dont know how the context was modified... we need a better way to decide, 
        # but our set of transofrmations will normally be enough. (the find parent in thi file is a place holder, do not work!!)
        # the real find_parent is long (465 lines) and makes the runtime considerable slower...
        #========================================================================================================================
        
   
def unique (array):
    total = []
    cve = []
    bug = []
    for item in array:
        if item['CVE'].strip() not in cve:
            cve.append(item['CVE'].strip())
            total.append(item)
        if item['bug'].strip() not in bug:
            bug.append(item['bug'].strip())
    return [total, cve, bug]


