import json
from collections import Counter
import copy
import re
import tools

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


#we laxed this requirement because we found it performs better without it. we may improve it and re-apply to reduce chances of false results
def check_vec_struct(vector, vec):
    if len(vector.strip()) > 0 and len(vec.strip()) > 0 and '::' in vec:
        vector_s = [str(x)[0].strip() for x in vector.strip().split('::')]
        vec_s = [str(x)[0].strip() for x in vec.strip().split('::')]
        if vec_s[0] == vector[0] and all(x in vec_s for x in vector_s):
                return True

    return False
    

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


def find_range(vars, file, le, string_val, num, my_range, bl, al):
    poss = []
    indices = {}
    coments = ['*','/','#']
    vars = [x for x in vars if len(x.strip()) > 1 and not x.strip().isdigit() and not x.strip().startswith('-')]
    limiter = my_range.split(',')[0].strip()
    if any(limiter.startswith(x) for x in ['+','-']):
        limiter = limiter[1:].strip()
    for lnm in range(len(file)-le):
        if string_val != None:
            if string_val in file[lnm] and not any(file[lnm].strip().startswith(x) for x in coments):
                poss.append(lnm - num)
        used = []
        for index in range(lnm, lnm+le):
            for item in vars:
                if item in file[index] and item.strip() not in used:
                    used.append(item.strip())
        
        if len(used) >= int(len(vars) / 2):
            indices[lnm] = len(used)
        #indices[lnm] = { 'val':len(used), 'list': used }

    if len(indices) == 0:
        return [0]
    max_val = max([indices[x] for x in indices])
    indices_1 = [x for x in indices.keys() if indices[x] >= max_val - 1] + poss
    indices_2 = [x for x in indices.keys() if indices[x] == max_val] + poss
    if max_val > 0: 
        sections = tools.split_blocks(indices_1) #we split the indices in sections and chose the best fit of each section according to context
        for sec_ind, sec in enumerate(sections):
            spl = 3
            if len(sec) >= 15:
                spl += int(len(sec)/10)
            tempo = sec[::spl]
            tempo.extend([sec[0], sec[-1]])
            sections[sec_ind] = sorted(list(set(tempo)))
        sections = [index for sec in sections for index in sec]
        if len(sections) > 50:
            sections = [x for x in sections if x in indices_2]
        limits =[int(limiter) - 2000, int(limiter) + 2000] #because this only check index values, there is no need to check the lines actual values
        sections = [x for x in sections if x > limits[0] and x < limits[1]]
        if len(sections) > 0 and len(sections) < 50:
            return sections
        else: 
            if len(indices_1) < 50:
                return indices_1
            else:
                return indices_2
    else:
        if len(indices_1) < 50:
                return indices_1
        else:
            return indices_2



def reconst_cond(params, vec):
    vec2 = copy.deepcopy(vec)
    p1 = vec[vec.find("(")+1: vec.rfind(")")]
    p1 = [x for x in set(p1.replace('|', ",").replace("c-", "").replace("e-", "").strip().split(","))]
    
    fixing = {}
    for par in params:
        if '+' in par:
            plus = par.find('+')
        else:
            plus = len(par)
        if '-' in par and par.find('-') < plus:
            plus = par.find('-')
        fixing[par[:plus]] = par  

    for record in fixing.keys():
        regex = re.compile(fr'{re.escape(record)}(?!\d)')
        vec2 = regex.sub(fixing[record],vec2)
    return vec2


def get_cond_params(vec):
    p1 = vec[vec.find("(")+1: vec.rfind(")")]
    p1 = set(p1.replace('|', ",").replace("c-", "").replace("e-", "").replace('b-', '').strip().split(","))
    order = True
    return [[x for x in p1],order]
    

def check_var(variables, var):
    for key in variables:
        if variables[key].strip() == var.strip():
            return [True, key]
    return [False, ""]

def replace(vector, vars):
    v = copy.deepcopy(vector)
    for va in vars:
        regex = re.compile(fr'{re.escape(va)}(?!\d)')
        replacement = va[0].upper()
        v = regex.sub(replacement,v)
    return v

#======================================================================================
#This is based on our own knowledge of coding conventions, sometimes variable extraction may fail. there is room for improvement
#======================================================================================

def gen_vector(plus_s, bfr_s, aft_s, extension, prev_lines, mode=0):
    permit_change = False #this variable allows to track a change in a one line patch to execute the vector comparison
    st_p = 0
    variables = {}
    # bool_val = 0 #no need, maybe we will add it.
    var_val = 0
    f_val = 0
    ins_val = 0
    string_val = 0
    ret_val = 0
    loop_val = 0
    exceptions = {'{','}', ';', '};', '*'}
    comments = ['// ', '* ', '/*', '*/']
    valid_c = ['c', 'cpp', 'cc', 'cxx', 'h']
    operators = [' == ',' != ',' < ',' > ',' <= ',' >= ',' &= ', '|= ']
    if extension.strip() not in valid_c:
        comments.append('#') 
    if mode == 1:
        lines = plus_s
        for il, l in enumerate(lines):
            for comm in comments:
                if l.strip().startswith(comm):
                    lines[il] = ''
                elif comm in l and comm != '* ':
                    lines[il] = l[:l.find(comm)]
            if any(l.strip().startswith(h) for h in comments):
                lines[il] = ''
        lines = [l.strip() for l in lines if not l.strip().startswith('//') and not l.strip().startswith('Powered by') and len(l.strip()) > 0]
        lines = [l.strip() for l in tools.fix_segmented(lines)]
        #here I need to joing nested conditionals since I still have {} signs to do it !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        if len(lines) > 0:
            lines = tools.combine_ifs(lines)
            levels = tools.calc_levels(lines)
            lines = [x.strip() for x in lines if x.strip() not in exceptions and len(x.strip()) > 0 and not x.strip().startswith('android_errorWriteLog')]
            ed_p = len(lines) - 1
        if len(lines) == 0:
            ed_p = 0
        if len(prev_lines) > 0:
            [lines, perm_change] = tools.check_equality(lines, prev_lines)
            permit_change = perm_change

    else:
    #arrenge the lines in an array of non trivial lines
    #writing logs wont affect the flow and may appear and generate lower similarity rates, we ignore those. 
        plus = tools.clean(plus_s.split(",+"))
        if len(plus) > 0 and plus[0].strip().startswith("+"):
            if plus[0].strip() == "+":
                del plus[0]
            else:
                plus[0] = plus[0][1:].strip()   
        bfr = tools.clean(tools.fixsplit(bfr_s).split("`"), 0)
        aft = tools.clean(tools.fixsplit(aft_s).split("`"), 0)
        for linef_ind, linef in enumerate(aft):
            if 'Powered by' in linef:
                linef = linef[:linef.find('Powered by')]
            if linef.endswith(','):
                linef = linef[:-1]
            aft[linef_ind] = linef
        
        try:
            limit_bfr = [x.strip() for x in bfr if not x.strip().startswith('//') and len(x.strip()) > 0 and not any(x.startswith(k) for k in comments) and not x.strip() in exceptions][-1].strip()
        except:
            limit_bfr = 'no_limit'
        try:
            limit_aft = [x.strip() for x in aft if not x.strip().startswith('//') and len(x.strip()) > 0 and not any(x.startswith(k) for k in comments) and not x.strip() in exceptions][0].strip()
        except:
            limit_aft = 'no_limit'
        lines = bfr + plus + aft
        lines = [x for x in lines if not x.startswith('@')]
        ed_p = len(lines)
        for il, l in enumerate(lines):
            if '//' in l:
                lines[il] = l[:l.find('//')] 
            if any(l.strip().startswith(h) for h in comments):
                lines[il] = ''
        
        lines = [l.strip() for l in tools.fix_segmented(lines) if not l.strip().startswith('//') and not l.strip().startswith('Powered by') and len(l.strip()) > 0]
        #here I need to joing nested conditionals since I still have {} signs to do it !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        if len(lines) > 0:
            lines = tools.combine_ifs(lines)
            levels = tools.calc_levels(lines)
            lines = [x.strip() for x in lines if x.strip() not in exceptions and len(x.strip()) > 0 and not x.strip().startswith('android_errorWriteLog')]
            
        st_lin = False
        
        if '//' in limit_bfr:
            limit_bfr = limit_bfr[:limit_bfr.find('//')].strip()
        if '#' in limit_bfr and limit_bfr.find('/#') > 2:
            limit_bfr = limit_bfr[:limit_bfr.find('#')].strip()
        if '//' in limit_aft:
            limit_aft = limit_aft[:limit_aft.find('//')].strip()
        if '#' in limit_aft and limit_aft.find('/#') > 2:
            limit_aft = limit_aft[:limit_aft.find('#')].strip()

        for lin_in, lin in enumerate(lines):
                    
            if (limit_bfr in lin or lin in limit_bfr) and not st_lin:
                st_p = lin_in + 1
                st_lin = True
                break
            # if (limit_aft in lin or lin in limit_aft) and st_lin:
            #     ed_p = lin_in - 1
            #     break
        for lin_in in range(len(lines)-1, 0, -1):
            if (limit_aft in lines[lin_in] or lines[lin_in] in limit_aft) and st_lin:
                ed_p = lin_in - 1
                break
        
    for inli, lin in enumerate(lines):
        pattern = r'/\*(.*?)\*/'
        lines[inli] = re.sub(pattern, '', lin)
         
    vector = []
    for lnm, line in enumerate(lines):
        line = tools.clean_params(line).strip()
        if line.startswith('Powered by') or line =='}' or len(line) == 0 or line.startswith('try') or line.startswith('} catch') :
            continue
        
        if line.startswith("if") or line.startswith("else if"):
            params = tools.split_cond_pars(line[line.find('(')+1:line.rfind(')')])
            values = []
            for param in params:
                cond_type = params[param]['type']
                cond_vars = params[param]['vars']
                tempo = []
                for var in cond_vars:
                    [permit, key] = check_var(variables, var)
                    if permit == True:
                        tempo.append(key)
                    else:
                        tempo.append("var" + str(var_val))
                        variables["var" + str(var_val)] = var
                        var_val += 1
                values.append(cond_type + "-" + ','.join(tempo))

            vector.append("C(" + '|'.join(values) + ")")            

        
        else: #regular lines 
            loop_step = ['--', '++']
            poss_assign = [' = ',' += ',' -= ',' *= ', ' /= ', ' &=', ' |=']
            if line.startswith('return'):
                if line.strip().endswith(';'):
                    line = line.strip()[:-1]
                #variables["r" + str(ret_val)] = line.strip()
                
                ret_val += 1
                values = []
                param = fix_param(line.replace('return', "").strip())
                if len(param.strip().split(" ")) == 2:
                    param = param.strip().split(" ")[1] #trying to leave behinf the type
                if param.startswith('&') or param.startswith('*'):
                    param = param[1:] #avoid pointer markers
                if param.startswith('!'):
                    param = param[1:]
                my_exceptions = [' = ',' += ',' -= ',' *= ', ' /= ', ' &=', ' |=', '!=', ' > ',' < ',' <= ', ' >= ', '&&']
                for p0 in param.split(" "):
                    if p0 not in my_exceptions:
                        [permit, key] = check_var(variables, param)
                        if permit == True:
                            values.append(key)
                        else:
                            if len(param.strip()) > 0:
                                variables["var" + str(var_val)] = param.strip()
                                values.append("var" + str(var_val))
                                var_val += 1
                vector.append("R(" + ','.join(values) + ")")
                
            elif 'log' in line.lower().split('(')[0] and '"' in line: #this is for logs need to check the is_line_coimplete also joing c++ structire LOGs
                
                if '<<' in line and '(' in line:
                    params = [x.strip() for x in line.strip().split('<<')[1:] if len(x) > 0] 
                else:
                    params = []
                    op_ind = []
                    for ind, char in enumerate(line):
                        if char == '"':
                            if len(op_ind) == 0:
                                op_ind.append(ind)
                            if len(op_ind) == 0:
                                my_str = line[op_ind[0]:ind+1]
                                params.append(my_str)
                                line.replace(my_str, '')
                                           
                        
                    p01 = line[line.find('(')+1:line.rfind(')')]
                    if '(' in p01 and ')' in p01:
                        p02 = p01[p01.find('(')+1:p01.rfind(')')]
                        p01 = p01.replace(p02, '')
                        params = []
                        if ',' in p01:
                            params.extend([x.strip() for x in p01.split(",") if len(x) > 0 and '()' not in x])
                        else:
                            params.append(p01)
                        if ',' in p02:
                            params.extend([x.strip() for x in p02.split(",") if len(x) > 0])
                        else:
                            params.append(p02)
                    else:
                        params = []
                        if '"' in p01 and p01.find('"') < p01.rfind('"'):
                            pattern = r'"(.*?)"'
                            matches = re.findall(pattern, p01)
                            for match in matches:
                                val_s = '"'+str(match)+'"'
                                params.append(val_s)
                                p01 = p01.replace(match, '')
                        p01 = p01.replace('""', '')    
                        params09 = [x.strip() for x in p01.split(",") if len(x) > 0]
                        for p09 in params09:
                            if ' + ' in p09:
                                for element in p09.split('+'):
                                    params.append(element.strip())
                            else:
                                params.append(p09.strip()) 
                values = []
                params = tools.split2_param(params, 1)
                params = [x.strip() for x in params if len(x.strip()) > 0]
                for param in params:
                    if param.startswith('!'):
                        param = param[1:]
                    if '.' in param:
                        if param.split('.')[0].strip() == 'this':
                            param = param[param.find('.')+1:].strip()
                        testing  = param.split('.')
                        if len(testing) > 1:
                            if testing[-1].endswith('()'):
                                param = testing[0]
                            elif testing[0][0].upper() == True:
                                param = testing[-1]
                            else:
                                param = testing[0]
                                

                    param = fix_param(param)
                    if len(param.strip().split(" ")) > 1 and '"' not in param:
                        param = param.strip().split(" ")[-1] #trying to leave behind the type
                    if param.startswith('&') or param.startswith('*'):
                        param = param[1:] #avoid pointer markers
                    [permit, key] = check_var(variables, param)
                    if permit == True:
                        values.append(key)
                    else:
                        if param.startswith('"'):
                            if param[0] == '"':
                                param = param[1:] #this is done in two setps on purpose, sometimes a broken line may cause a missinf quote, although this should not happen at this point, we want to make sure.
                            if param[-1] == '"':
                                param = param[:-1] 
                            variables["str" + str(string_val)] = param
                            values.append("str" + str(string_val))
                            string_val += 1
                        else:
                            variables["var" + str(var_val)] = param.strip()
                            values.append("var" + str(var_val))
                            var_val += 1
                #vector.append("l" + str(loop_val-1)  +"(" + ','.join(values) + ")") 
                vector.append("P(" + ','.join(values) + ")")   
        
            elif line.startswith('for') or line.startswith('while'):
                tmp = line[line.find('(')+1:line.rfind(')')]
                if ' : ' in tmp:
                    params = [x.strip() for x in tmp.split(':') if len(x) > 0]
                else:
                    params = [x.strip() for x in tmp.split(';') if len(x) > 0]

                #variables["l" + str(loop_val)] = line.split('{')[0].strip()
                params = tools.loop_vars_check(tools.split2_param(params))
                
                loop_val += 1
                values = []
                for param in params:
                    
                    if param.startswith('!'):
                        param = param[1:]
                    if '.' in param and param.split('.')[0].strip() == 'this':
                        param = param[param.find('.')+1:].strip()
                    param = fix_param(param)
                    if len(param.strip().split(" ")) == 2:
                        param = param.strip().split(" ")[1] #trying to leave behind the type
                    if param.startswith('&') or param.startswith('*'):
                        param = param[1:] #avoid pointer markers
                    [permit, key] = check_var(variables, param)
                    if permit == True:
                        values.append(key)
                    else:
                        
                        variables["var" + str(var_val)] = param.strip()
                        values.append("var" + str(var_val))
                        var_val += 1
                #vector.append("l" + str(loop_val-1)  +"(" + ','.join(values) + ")") 
                vector.append("L(" + ','.join(values) + ")")   
                

            elif line.strip().endswith('{') and '(' not in line and ' : ' not in line and not any(x in line for x in operators): 
                tes = line.replace('{', '')
                tes = tes.replace('}', '').strip()
                if tes == 'else':
                    continue
                [permit, key] = check_var(variables, line.split('{')[0].strip())
                if permit == True:
                    vector.append(key)
                else:
                    if len(line.split('{')[0].split(' ')[-1].strip()) > 0:
                        variables["f" + str(f_val)] = line.split('{')[0].split(' ')[-1].strip()
                    else:
                        variables["f" + str(f_val)] = line.split('{')[0].split(' ')[-2].strip()
                    vector.append("F()")
                    #vector.append("f" + str(f_val) + "()")
                    f_val += 1
            
            elif ' : ' in line and (line.endswith('};') or line.endswith('{')):
                funcs = line.split('{')[0].strip().split(':')
                params = []
                for it in funcs:
                    if '(' in it and ')' in it:
                        s1 = '('
                        s2 = ')'
                    elif '<' in it and '>' in it:
                        s1 = '<'
                        s2 = '>'
                    else:
                        continue
                    v2 = it[it.find(s1)+1:it.rfind(s2)].split(',')
                    for c in v2:
                        if len(c) > 0 and c != ' ':
                            params.append(c.strip())
                variables["f" + str(f_val)] = line.split('{')[0].split(' ')[-1].strip()
                f_val += 1
                values = []
                params = tools.split2_param(params)
                for param in params:
                    if param.startswith('!'):
                        param = param[1:]
                    if '.' in param and param.split('.')[0].strip() == 'this':
                        param = param[param.find('.')+1:].strip()
                    param = fix_param(param)
                    if len(param.strip().split(" ")) == 2:
                        param = param.strip().split(" ")[1] #trying to leave behinf the type
                    if param.startswith('&') or param.startswith('*'):
                        param = param[1:] #avoid pointer markers
                    [permit, key] = check_var(variables, param)
                    if permit == True:
                        values.append(key)
                    else:
                        if param.startswith('!'):
                            param = param[1:]
                        variables["var" + str(var_val)] = param.strip()
                        values.append("var" + str(var_val))
                        var_val += 1
                vector.append("F(" + ','.join(values) + ")") 
                #vector.append("f" + str(f_val-1)  +"(" + ','.join(values) + ")") 

            elif line.strip().endswith('{') and '(' in line and ')' in line:
                params = [x.strip() for x in line[line.find('(')+1: line.rfind(')')].split(',') if len(x.strip()) > 0]
                if len(params) > 0:
                    params = tools.split2_param(params)
                # funcs2 = ['public', 'private', 'static', 'protected']
                # if any(line.strip().startswith(x) for x in funcs2):
                #     params = [line.strip().split(" ")[-2]] #this is for functions like onResume()
                test_func_name = line.split('(')[0].strip()
                if '.' not in test_func_name and ' ' in test_func_name:
                    variables["f" + str(f_val)] = test_func_name.split(' ')[-1].strip() 
                else:
                    variables["f" + str(f_val)] = test_func_name
                f_val += 1
                values = []
                for param in params:
                    if param.startswith('!'):
                        param = param[1:]
                    if '.' in param and param.split('.')[0].strip() == 'this':
                        param = param[param.find('.')+1:].strip()
                    param = fix_param(param)
                    if len(param.strip().split(" ")) > 1:
                        param = param.strip().split(" ")[-1] #trying to leave behinf the type
                    if param.startswith('&') or param.startswith('*'):
                        param = param[1:] #avoid pointer markers
                    [permit, key] = check_var(variables, param)
                    if permit == True:
                        values.append(key)
                    else:
                        if param.startswith('!'):
                            param = param[1:]
                        variables["var" + str(var_val)] = param.strip()
                        values.append("var" + str(var_val))
                        var_val += 1
                #vector.append("F(" + ','.join(values) + ")")
                vector.append("F" + str(f_val-1)  +"(" + ','.join(values) + ")")
                
            elif (line.endswith(');') or line.endswith(')')) and '(' in line and not is_assign(line):
                values = []
                params = [] 
                key_words = ['android', 'Manifest', 'permission', 'Context', 'Window', 'Manager']
                if '.' in line:
                    test = tools.get_points_out(line)
                    for it in test:
                        if '(' not in it:
                            params.append(it)
                        else:
                            
                            inner_it = it[it.find('(') + 1: it.rfind(')') ] 
                            if '.' in inner_it:
                                [mcheck, ind_check] = tools.test_param_struc(inner_it)
                                if mcheck:
                                    arr02 = []
                                    arr02.append(it[:it.find('(')].strip())
                                    start_index = 0
                                    for index in ind_check:
                                        arr02.append(inner_it[start_index:index].strip())
                                        start_index = index+1
                                    arr02.append(inner_it[start_index:].strip())
                                    
                                    for el02 in arr02:
                                        if '.' in el02 and '(' in el02 and tools.empty_par(el02) and not el02.startswith('"'):
                                            params.append(el02.split('.')[0].strip())
                                            inner_2  = el02[el02.find('.') + 1:]
                                        elif '(' in el02 and ')' in el02 and not el02.startswith('"'):
                                            inner_2 = el02[el02.find('(') + 1: el02.rfind(')') ]
                                        else: 
                                            inner_2 = el02
                                        it2 = tools.get_points_out(inner_2)
                                        for it3 in it2:
                                            if '(' in it3 and not it3.startswith('"'): #is not a string
                                                params += set([h.strip() for h in it3[it3.find('(')+1: it3.rfind(')')].split(',') if h.strip() not in params])
                                            else:
                                            	params.append(it3.strip())    
                                else:
                                    it2 = tools.get_points_out(inner_it)
                                    
                                    for it3 in it2:
                                        if '(' in it3 and ')' in it3:
                                            #necesito checkear los parenthesis!!!!!!!!!!!!!
                                            it3_arr = tools.test_diff_par([it3])
                                            it3_arr = [x.strip() for x in it3_arr if not x.startswith('get') and not x.startswith('set') and len(x) >= 4]
                                            it31_arr = []
                                            for it3_item0 in it3_arr:
                                                if '&&' in it3_item0:
                                                    it31_arr = [x.strip() for x in it3_item0.split('&&') if len(x) > 0]  
                                                elif '||' in it3_item0:
                                                    it31_arr = [x.strip() for x in it3_item0.split('||') if len(x) > 0]
                                                elif '|' in it3_item0:
                                                    it31_arr = [x.strip() for x in it3_item0.split('|') if len(x) > 0]
                                            for it3_item in it31_arr:
                                                if ',' in it3_item and '.' not in it3_item:
                                                    params += list(set([x.strip() for x in it3_item.split(',')]))
                                                elif '.' in it3_item and ',' not in it3_item:
                                                    sp_it3 = it3_item.split('.')[0]
                                                    if sp_it3[0].isupper() and sp_it3[1].islower():
                                                        params.append(it3_item.split('.')[-1])
                                                    else:
                                                        params.append(sp_it3)
                                                else:
                                                    params += set([h.strip() for h in it3[it3.find('(')+1: it3.rfind(')')].split(',') if h.strip() not in params])
                                        elif it3 in key_words:
                                            continue
                                        else:
                                            if ' + ' in it3:
                                                params += [x.strip() for x in it3.split(' + ')]
                                            else:
                                                params.append(it3)                                     
                            elif ',' in inner_it:
                                params += set([r.strip() for r in inner_it.split(',') if r.strip() not in params])
                                
                else:
                    stripped_line = copy.deepcopy(line)
                    if '(' in line and (line.endswith(')') or line.endswith(');')):
                        params.append(line[:line.find('(')].split(" ")[-1])
                        stripped_line = line[stripped_line.find('(') + 1: stripped_line.rfind(')')]
                        if '"' in stripped_line:
                            str0 = stripped_line[stripped_line.find('"'): stripped_line.rfind('"') + 1]
                            if len(str0) > 2:
                                params.append(str0)
                                stripped_line = stripped_line.replace(str0, '')
                    [mcheck, ind_check] = tools.test_param_struc(stripped_line)
                    if mcheck:
                        
                        start_index = 0
                        for index in ind_check:
                            params.append(stripped_line[start_index:index])
                            start_index = index+1
                        params.append(stripped_line[start_index:])
                params = [x.strip() for x in params if x not in key_words and len(x.strip()) > 0]

                if len(params) == 1 and len(params[0].strip()) < 1 and '.' in line: 
                    params = [line.strip()[:-1].split('.')[-1]]
                elif len(params) == 1 and ',' not in params[0] and '(' in params[0]:
                    if params[0].endswith(')'):
                        params[0] = params[0][:-1]
                    params = [params[0][params[0].rfind('(')+1:]]
                ins_val += 1
                params = tools.split2_param(params)
                for param in params:
                  
                    if '.' in param and param.split('.')[0].strip() == 'this':
                        param = param[param.find('.')+1:].strip()
                    if '"' in param:
                        st = param[param.find('"')+1:param.rfind('"')]
                        [permit, key] = check_var(variables, st)
                        if permit == True:
                            values.append(key)
                        else:
                            if st.startswith('!'):
                                st = st[1:]
                            variables["str" + str(string_val)] = st.strip()
                            values.append("str" + str(string_val))
                            string_val += 1
                        rest = [j.strip() for j in param[param.rfind('"')+1:].split('+') if len(j.strip()) > 0]
                        if len(rest) > 0:
                            for v4 in rest:
                                v4 = fix_param(v4)
                                if v4.startswith('!'):
                                    v4 = v4[1:]
                                [permit, key] = check_var(variables, v4)
                                if permit == True:
                                    values.append(key)
                                else:
                                   
                                    variables["var" + str(var_val)] = v4.strip()
                                    values.append("var" + str(var_val))
                                    var_val += 1
                        continue

                    if len(param.strip()) == 0:
                        continue
                    param = fix_param(param)
                    if param.startswith('!'):
                        param = param[1:]
                    if len(param) > 0:
                        if param.startswith('&') or param.startswith('*'):
                            param = param[1:] #avoid pointer markers
                        [permit, key] = check_var(variables, param)
                        if permit == True:
                            values.append(key)
                        else:
                            if param.startswith('!'):
                                param = param[1:]
                            variables["var" + str(var_val)] = param.strip()
                            values.append("var" + str(var_val))
                            var_val += 1
                vector.append("I(" + ','.join(values) + ")")
            
            elif (line.endswith(');') or line.endswith(')')) and '(' not in line and not is_assign(line):
                line = line[:-2]
                params = []
                values = []
                if line.startswith('+'):
                    line = line[1:]
                if '"' in line and line.find('"') < line.rfind('"'):
                    params.append(line[line.find('"') : line.rfind('"') + 1])
                if '+' in line:
                    params += [x.strip() for x in line.split('+') if '"' not in x]
                for param in params:
                    param = fix_param(param)
                    if len(param) > 0:
                        if param.startswith('&') or param.startswith('*'):
                            param = param[1:] #avoid pointer markers
                        [permit, key] = check_var(variables, param)
                        if permit == True:
                            values.append(key)
                        else:
                            if param.strip().startswith('"'):
                                variables["str" + str(string_val)] = param.strip()
                                values.append("str" + str(string_val))
                                string_val += 1
                            else:
                                variables["var" + str(var_val)] = param.strip()
                                values.append("var" + str(var_val))
                                var_val += 1          
                vector.append("I(" + ','.join(values) + ")")    
            
            elif any(x in line for x in poss_assign):
                spl_val = ''
                for pa in poss_assign:
                    if pa in line:
                        spl_val = pa
                        break
                
                vars = [x for x in tools.fix_vars([x.strip() for x in line.split(spl_val)]) if x.lower() != 'context'] 
                
                values = []
                cast = ['int32', 'int8', 'int16','int32_t', 'int8_t', 'int16_t', 'int64', 'int64_t', 'size_t']
                for var in vars:
                    if var.strip().startswith('(') and var[var.find('(')+1:var.find(')')].strip() in cast:
                        var = var[var.find(')')+1:]

                    if var.strip().endswith(';'):
                        var = var.strip()[:len(var.strip())-1]
                    if '(' in var and ')' in var:
                        sub_vars = [x.strip() for x in var[var.find('(')+1:var.rfind(')')].split(',') if len(x.strip()) > 0]
                        for var2 in sub_vars:
                            if var2.startswith('!'):
                                var2 = var2[1:]
                            if '.' in var2 and var2.split('.')[0].strip() == 'this':
                                var2 = var2[var2.find('.')+1:].strip()
                            if var2.startswith('&') or var2.startswith('*'):
                                var2 = var2[1:] #avoid pointer markers
                            [permit, key] = check_var(variables, var2)
                            if permit == True:
                                values.append(key)
                            else:
                                
                                variables["var" + str(var_val)] = var2.strip()
                                values.append("var" + str(var_val))
                                var_val += 1
                    else:
                        if '.' in var and var.split('.')[0].strip() == 'this':
                            var = var[var.find('.')+1:].strip()
                        if var.startswith('&') or var.startswith('*'):
                            var = var[1:] #avoid pointer markers
                        if var.startswith('!'):
                            var = var[1:]
                        [permit, key] = check_var(variables, var)
                        if permit == True:
                            values.append(key)
                        else:
                           
                            variables["var" + str(var_val)] = var.strip()
                            values.append("var" + str(var_val))
                            var_val += 1
                vector.append("A(" + ','.join(values) + ")")
            
            elif line.endswith(';') and len(line.split(' ')) > 1 and '"' not in line: #will ignore partial logs at the beggining of bfr, they dont have any information for us
                var0 = line.split(' ')[-1].strip()
                if '.' in var0 and var0.split('.')[0].strip() == 'this':
                    var0 = var0[var0.find('.')+1:].strip()
                my_vars = []
                if '[' in var0: #we are delclearing an array and specifying a size
                    my_vars = [x.strip() for x in var0.replace(']', '').split('[')]
                else:
                    my_vars = [var0]
                values = []
                for var in my_vars:
                    if var.startswith('&') or var.startswith('*'):
                        var = var[1:] #avoid pointer markers
                    if var.endswith(';'):
                        var = var[:-1]
                    if var.startswith('!'):
                        var = var[1:]
                    [permit, key] = check_var(variables, var)
                    if permit == True:
                        values.append(key)
                    else:
                        if var.startswith('!'):
                            var = var[1:]
                        variables["var" + str(var_val)] = var.strip()
                        values.append("var" + str(var_val))
                        var_val += 1
                vector.append("D(" + ','.join(values) + ")")


    if len(vector) == len(lines): #sometimes the patch cannot be interpreted in the right way, and some lines are lost, we dont adjust the vector if that happens.
        vector  = [x for ind, x in enumerate(vector) if ind >= st_p and ind <= ed_p]
        try:
            levels  = [x for ind, x in enumerate(levels) if ind >= st_p and ind <= ed_p]
        except:
            levels = []   
        
    copy_vec = copy.deepcopy(vector) 
    for index0, vec in enumerate(vector):
        if len(levels) > 0:
            level = levels[index0]
        else:
            level = 0
        order = False
        type = vec.split("(")[0].strip()
        if type == 'C':
            [params, order] = get_cond_params(vec)
        else:
            params = vec[vec.find("(")+1:vec.rfind(")")].split(",")
        params = [x.strip() for x in params if len(x.strip()) > 0]
        t_plus_count = 0
        t_minus_count = 0
        var_add = {}
        var_rem = {}
        for p in params:
            var_add[p] = []
            var_rem[p] = []
        for index1, v in enumerate(vector): 
            if index0 == index1:
                continue
            type2 = v.split("(")[0].strip()
            if type2 == 'C':
                [params2, order2] = get_cond_params(v)
            else:
                params2 = v[v.find("(")+1:v.rfind(")")].split(",")
            
            if type == type2:
                if index0 < index1:
                    t_plus_count += 1
                else:
                    t_minus_count += 1
            for par in params:
                if par in params2:
                    if index0 < index1:
                        var_add[par].append(type2)
                    else:
                        var_rem[par].append(type2)
        #here I use the counts to modify the vector into something that doesnt need variable names. 
        if t_plus_count > 0:
            type = type + "+" + str(t_plus_count)
        if t_minus_count > 0:
            type = type + "-" + str(t_minus_count) #the if are in purpose, to add both if necessary

        for pnm, key in enumerate(params):
            fin = str(key)
            if len(var_add[key]) > 0:
                res = Counter(var_add[key])
                for k in res.keys():
                    fin += "+" + str(res[k]) + str(k)
                    
            if len(var_rem[key]) > 0:
                res2 = Counter(var_rem[key])
                for k in res2.keys():
                    fin += "-" + str(res2[k]) + str(k)
            params[pnm] = fin #this line changes values on the go. need a copy for it?
        #here I nned to replace vector values using variables and reconstruct the C lines
        if order == True:
            copy_vec[index0] = reconst_cond(params, vec) + "@" + str(level)
        else:
            copy_vec[index0] = type + "(" + ','.join(params) + ")" + "@" + str(level)
    
    
    return [replace('::'.join(copy_vec), [x for x in variables.keys()]), [variables[x] for x in variables], lines, permit_change]


def parse(plus, bfr, aft, file, ext, my_range):
    comments = ['//', '* ', '/*', '*/']
    valid_c = ['c', 'cpp', 'cc', 'cxx', 'h']
    if ext.strip() not in valid_c:
        comments.append('#') 
    exceptions = ['{', '}', ';', '', '+']

    plus_t = [x.strip() for x in tools.clean(plus.split(',+')) if x.strip() not in exceptions and not x.startswith('Powered')]
    if len(plus_t) > 0 and plus_t[0].startswith("+"):
       plus_t[0] = plus_t[0][1:].strip()
    plus_t = [x.strip() for x in plus_t if not any(x.startswith(k) for k in comments)]
    plus_strip = [x.strip() for x in plus_t if x not in exceptions and len(x.strip()) > 0] # we want the exact plus section as in the database

    pl = tools.fix_segmented(plus_t) #we want to know how many intructions are in the patch to decide the range
    bl2 = [x.strip() for x in tools.clean(tools.fixsplit(bfr).split("`"),0) if x.strip() not in exceptions and not x.startswith('Powered')]
    bl = len(bl2)
    al2 = [x.strip() for x in tools.clean(tools.fixsplit(aft).split("`"),0) if x.strip() not in exceptions and not x.startswith('Powered')]
    al = len(al2)
    pass_var = False
    if len(pl) > 0 and pl[0].startswith('+'):
        pl[0] = pl[0][1:].strip()
    
    #pl = [x for x in pl if not any(x.startswith(comm) for comm in comments)]
    bl2 = [x for x in bl2 if not any(x.startswith(comm) for comm in comments)]
    al2 = [x for x in al2 if not any(x.startswith(comm) for comm in comments)]
    pass_test = False
    for lpl in pl:
        if not any(lpl.startswith(comment) for comment in comments):
            pass_test = True
    if pass_test == False:
        return ['comments', ['comments']] #this is to avoid processing a patch that is fully commented, we consider the patch trivial and we set the similarity to 100% 
                 
  
    if len(pl) < 3:
        le = len(pl)+bl+al+3 
    else:
        le = int(2.5*(len(pl)+bl+al))
    
    [vector, vars, gen_inst, permit_change] = gen_vector(plus, bfr, aft, ext, [])
    
           
    encoders = ['utf-8', 'windows-1252', 'iso-8859-1', 'ascii', 'latin1']
    for enc in encoders:
        try:
            with open(file, "r", encoding=enc) as buff:
                buffer = buff.readlines()
            buff.close()
            break
        except:
            pass
    vars = [v.strip() for v in vars if len(v) > 0 and v.strip() != 'null' and v != 'TAG']
    vars2 = [v.strip() for v in vars if len(v) > 0 and v.strip().lower() not in ['true', 'false']]
    if len(vars2) > 3:
        vars = vars2
    
    string_val = None
    for pl_li in pl:
        if '(' in pl_li and ')' in pl_li:
            test =  pl_li[pl_li.find('(') + 1: pl_li.rfind(')')].split(',')
            if len(test) == 2:
                t = test[1].replace('"', '').strip()
                if all(x.isdigit() for x in t) and 'log' in pl_li[:pl_li.find('(')].lower():
                    string_val = t 
            if string_val == None:
                test = pl_li[pl_li.find('(') + 1: pl_li.rfind(')')].split(' ')
                for el in test:
                    t = el.replace(')', '').replace(')', '').strip()
                    if t.isdigit():
                        if int(t) > 99:
                            string_val = str(t)
                            break

    ranges = find_range(vars, buffer, le, string_val, len(pl) + al, my_range, tools.clean_2comm(bl2), tools.clean_2comm(al2))
    gen_inst_2_arr = []
    vecs = []
    tempo = [x.strip() for x in bl2] + [x.strip() for x in plus_strip] + [x.strip() for x in al2]
    tempo = [x for x in tempo if not x.strip().startswith('@') and not x.strip().startswith('try ') and not x.strip().startswith('catch ')]
    trigg = 0
    for r in ranges:
        lines = []
        p = 0
        for index in range(r, r+le):  #le is three times the length of the block (we want to make sure to account for extra lines even in big blocks, the extra lines should not break the underlying pattern)
            if index <= len(buffer) - 1:
                lines.append(buffer[index])
            else:
                break
        lines = tools.adjust_lines(lines, bfr, aft, plus,ext)
        permit = len([x for x in lines if any(tools.get_similarity_ratio(x, t) >= 0.9 for t in tempo)])
        [tvec, tparam, gen_inst_2, permit_change] = gen_vector(lines,'','', ext, gen_inst, 1)
        if permit >= (len(tempo) - len(plus_strip)) / 2:
            p = 1
        gen_inst_2_arr.extend([x for x in gen_inst_2 if x not in gen_inst_2_arr])
        if permit_change == True:
            trigg += 1
        # permit = check_vec_struct(vector, tvec)
    
        if '::' in tvec:# and permit == True:
            vecs.append([p,tvec])
    count = sum(1 for element in vecs if element[0] == 1) #sometimes the context lines are too different, so we use all of teh ranges
    if count > 0:
        vecs = [vector[1] for vector in vecs if vector[0] == 1]
    else:
        vecs = [vector[1] for vector in vecs]

    if len([item for item in pl if not any(item.startswith(comment) for comment in comments)]) == 1: #for one intruction we trust layer 1 unless is a conditional, a loop or a method since those will affect the var patterns.
        if not (pl[0].startswith('if') or pl[0].startswith('for')):
            if not ('(' in pl[0] and len(pl[0]) > 40 and trigg > 0):
                pass_var = True
       
    if pass_var == True:
        indices = tools.group_indices(sorted([index for index, value in enumerate(gen_inst_2_arr) if value in bl2 or value in al2]))
        f_indices = []
        if len(indices) > 0:
            for group in indices:
                f_indices.append(group[0])
        test_ind = [index for index, x in enumerate(gen_inst_2_arr) if tools.get_similarity_ratio(x,pl[0]) >= 0.93] 
        if len (test_ind) > 0:
            if len(f_indices) > 0:
                ret_val = ['Layer_1']
                for x in f_indices:
                    for y in test_ind:
                        if y - 10 <= x <= y + 10:
                            ret_val = ['checked']
                            break
                return [vector, ret_val]
            else:
                return [vector, ['checked']]
        else:
            return [vector, ['Layer_1']]  
    return [vector, vecs]


