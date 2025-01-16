
import tools
import copy


def check_levels(vec1, vec2): #this only check returns to avoid generating false vectors
    vec1_el = [x.strip() for x in vec1.split('::')]
    vec2_el = [x.strip() for x in vec2.split('::')]
    flow_2 = [x.strip()[0] for x in vec2_el]
    flow_1 = [x.strip()[0] for x in vec1_el]
    differences_1 = []
    differences_2 = []
    if 'R' in flow_1 and 'R' in flow_2:
        indices_of_R_1 = [index for index, type in enumerate(flow_1) if type == 'R']
        indices_of_R_2 = [index for index, type in enumerate(flow_2) if type == 'R']
        for ind in indices_of_R_1:
            try:
                v1 = int(vec1_el[ind].split('@')[1])
                v2 = int(vec1_el[ind-1].split('@')[1])
                differences_1.append([ind,v1-v2])
            except:
                differences_1.append([ind, 0])
        for ind in indices_of_R_2:
            try:
                differences_2.append([ind, (int(vec2_el[ind].split('@')[1]) - int(vec2_el[ind-1].split('@')[1]))])
            except:
                differences_2.append([ind, 0])
        
        for ind, element in enumerate(differences_1):
            try:
                if element[1] != differences_2[ind][1]:
                    del vec2_el[element[0]]
            except:
                continue

        return '::'.join(vec2_el)
    else:    
        return vec2


def check_vars_class(vars_line, vars_cmp_line):
    
    classes01 = [vars_line[idx]['class'] for idx in vars_line]
    classes02 = [vars_cmp_line[idx]['class'] for idx in vars_cmp_line]
    
    return all(x in classes02 for x in classes01)


def flow_check(base_vec, file_vec):
    result = []
    original_flow = [x.strip()[0] for x in base_vec.split('::')]
    for ind in range(len(original_flow)):
        tmp_flow = original_flow[ind:]

        file_flow = [x.strip()[0] for x in file_vec.split('::')]
        collection = [x.strip() for x in file_vec.split('::')]
        possibilities = [(index, index2) for index, element_A in enumerate(tmp_flow)
                        for index2, element_B in enumerate(file_flow) if element_B == element_A]
        my_list = {}
        for poss in possibilities:
            order, index2 = poss
            my_list.setdefault(order, []).append(index2)

        vectors = []
        for key in my_list.keys():
            if not vectors:
                vectors = [[ele] for ele in my_list[key]]
            else:
                new_vectors = []
                for vec in vectors:
                    for val in my_list[key]:
                        if val > vec[-1]:
                            new_vectors.append(vec + [val])
                vectors += new_vectors

        try:
            max_len = max(map(len, vectors))
        except:
            return [file_vec] #sometimes variables are used in a vector that is too different, we return it and leave the comp function to discard it
        result += [v for v in vectors if len(v) == max_len]
        #result += [('::').join([collection[line_index] for line_index in v]) for v in vectors]
        
    max_len = max(map(len, result))
    return list(set([('::').join([collection[line_index] for line_index in v]) for v in result if len(v) == max_len]))
   

def get_var_value(var, vars2, used): #used keep track of lines with a similarity value attached to it
    plus = var['plus']
    minus = var['minus']
    var_class = var['class']
    values = {}
    for index, var_cmp in enumerate(vars2):
        if index in used:
            continue #this avoids using the same var twice
        var_value = 0
        plus_cmp = vars2[var_cmp]['plus']
        minus_cmp = vars2[var_cmp]['minus']
        var_cmp_class = vars2[var_cmp]['class']
        if var_class != var_cmp_class:
            values[index] = 0
            continue
        if len(plus) == 0:
            var_value += 50
        else:
            for element in plus:
                ty_el = element[-1]
                count_el = element[:-1]
                if len(plus_cmp) == 0:
                    continue
                for ele2 in plus_cmp:
                    ty_el_2 = ele2[-1]
                    count_el_2 = ele2[:-1]
                    if ty_el == ty_el_2:
                        if count_el_2 >= count_el:
                            var_value += 50 / len(plus)
                        elif count_el > count_el_2:
                            var_value += 40 / len(plus)
                        break
        
        if len(minus) == 0:
            var_value += 50
        else:
            for element in minus:
                ty_el = element[-1]
                count_el = element[:-1]
                if len(minus_cmp) == 0:
                    continue
                for ele2 in minus_cmp:
                    ty_el_2 = ele2[-1]
                    count_el_2 = ele2[:-1]
                    if ty_el == ty_el_2:
                        if count_el_2 >= count_el:
                            var_value += 50 / len(minus)
                        elif count_el > count_el_2:
                            var_value += 40 / len(minus)
                        break
        values[index] = var_value
    if len(values) == 0:
        return [0, 'empty']
    max_val = max([values[x] for x in values])
    for i in values:
        if values[i] == max_val:
            return [values[i], i] #this returns allways the smallest index with the max similarity
    

def ext_pat(array1):
    lines = {}
    for lnm, line in enumerate(array1):
        info = {}
        info['type'] = line.strip()[0]
        info['level'] = int(line[line.find('@')+1:])
        line = line[:line.find('@')]
        line_count = line[:line.find('(')]
        info['counts'] = {}
                
        if '+' in line_count and '-' in line_count:
            info['counts']['plus'] = line[line.find('+')+1:line.find('-')]
            info['counts']['minus'] = line[line.find('-')+1:line.find('(')]
        elif '+' in line_count:
            info['counts']['plus'] = line[line.find('+')+1:line.find('(')]
            info['counts']['minus'] = 0
        elif '-' in line_count:
            info['counts']['minus'] = line[line.find('-')+1:line.find('(')]
            info['counts']['plus'] = 0
        else:
            info['counts']['plus'] = 0
            info['counts']['minus'] = 0
        if info['type'] != 'C':
            vars = line[line.find('(')+1:line.find(')')]
            if vars.strip() == '':
                info['vars'] = [] #this may happen only in lines like namespace or struct, they will be translated to F().
            else:
                info['vars'] = {}
                for index, var in enumerate(vars.split(',')):
                    info['vars'][index] = {}
                    info['vars'][index]['plus'] = []
                    info['vars'][index]['minus'] = []
                    info['vars'][index]['class'] = var.strip()[0]
                    var = var.strip()[1:]
                    indices = []
                    for i, letter in enumerate(var):
                        if letter == '+' or letter == '-':
                            indices.append(i)
                    for count, j in enumerate(indices):
                        if count == len(indices) - 1:
                         
                            if var[j] == '+':
                                info['vars'][index]['plus'].append(var[j+1:])
                            else:
                                info['vars'][index]['minus'].append(var[j+1:])
                        else:
                            
                            if var[j] == '+':
                                info['vars'][index]['plus'].append(var[j+1:indices[count+1]])
                            else:
                                info['vars'][index]['minus'].append(var[j+1:indices[count+1]])
                   
        else: #this is for C lines
            conds = line[line.find('(')+1:line.find(')')].split('|')
            info['conds'] = {}
            for condnum, cond in enumerate(conds):
                info['conds'][condnum] = {}
                info['conds'][condnum]['cond_type'] = cond[0:2]
                info['conds'][condnum]['vars'] = {}
                condvars = cond[2:].split(',')

                for index, condvar in enumerate(condvars):
                    info['conds'][condnum]['vars'][index] = {}
                    info['conds'][condnum]['vars'][index]['plus'] = []
                    info['conds'][condnum]['vars'][index]['minus'] = []
                    #take the class of the variable (variable, string or function)
                    info['conds'][condnum]['vars'][index]['class'] = condvar.strip()[0]
                    condvar = condvar.strip()[1:]
                    indices = []
                    for i, letter in enumerate(condvar):
                        if letter == '+' or letter == '-':
                            indices.append(i)
                    for count, j in enumerate(indices):
                        if count == len(indices) - 1:
                            if condvar[j] == '+':
                                info['conds'][condnum]['vars'][index]['plus'].append(condvar[j+1:])
                            else:
                                info['conds'][condnum]['vars'][index]['minus'].append(condvar[j+1:])
                        else:
                            if condvar[j] == '+':
                                info['conds'][condnum]['vars'][index]['plus'].append(condvar[j+1:indices[count+1]])
                            else:
                                info['conds'][condnum]['vars'][index]['minus'].append(condvar[j+1:indices[count+1]])
                   
        lines[lnm] = info
    return lines


def compare_arrays(vec1, vec20):
    
    if len(vec1.split('::')) < 10:
        poss_vec2 = flow_check(vec1, vec20)
        
    else:
        poss_vec2 = [vec20]
    values = []
    for vec2 in poss_vec2:
        vec2 = check_levels(vec1, vec2)
        if vec1 == '' or vec2 == '':
            return 0
        
        struct1 = ext_pat(vec1.split('::'))
        struct2 = ext_pat(vec2.split('::'))
        similarity_values = []
        used = []
        for line_num in struct1:
            line = struct1[line_num]
            poss_vals = {} #this have all the possible matches for each line and its similarity percentage 

            if line['type'] != 'C':
                if line['type'] == 'P': #when using vctors, a Log line may not be present, or be drastically different, it wont affect the patch, so we set it to 100. We still make the line in SV so we can save ralationships for other lines.
                    similarity_values.append(100)
                    continue
                count_plus = line['counts']['plus']
                count_minus = line['counts']['minus']
                tot_vars = len(line['vars'])
                ret_vals = {}
                for index, cmp_line in enumerate(struct2): #this loop is compearing the different lines one by one, then we take the best match
                    cmp_line = struct2[cmp_line]
                    count_similarity = 0
                    var_similarity = 0
                    if cmp_line['type'].strip() == line['type'].strip() and index not in used:
                                                                      
                        if len(line['vars']) > 0:
                            if check_vars_class(line['vars'], cmp_line['vars']) == False:
                                continue
                        #similarity in counts // we want AT LEAST the same value to consider a full match
                        #this means the pattern is conserved, a bigger value in cmp_line may be due to extra lines after customization
                        count_plus_cmp = cmp_line['counts']['plus']
                        count_minus_cmp = cmp_line['counts']['minus']
                        if int(count_plus_cmp) >= int(count_plus):
                            count_similarity += 50
                        else:
                            count_similarity = float(count_plus_cmp) / float(count_plus)
                        if int(count_minus_cmp) >= int(count_minus):
                            count_similarity += 50
                        else:
                            count_similarity = float(count_minus_cmp) / float(count_minus)
                        #for variables we use the same approach BUT we take the amount of struct1 variables as a base for similarity.
                        #this is because during customization an extra var can be added, we don't care as long as the pattern is conserved.
                        
                        if tot_vars == 0 and len(cmp_line['vars']) == 0:
                            var_similarity = 100
                        elif tot_vars > 0 and len(cmp_line['vars']) == 0: 
                            var_similarity = 0
                        else:
                            penalty = 1
                            if tot_vars > len(cmp_line['vars']):
                                penalty = float(len(cmp_line['vars']) / tot_vars)
                            used_vars = []
                            for ind in line['vars']:
                                var = line['vars'][ind]
                                if len(var['plus']) + len(var['minus']) == 0:
                                    var_similarity += 100 / tot_vars
                                else:
                                    [val, used_var] = get_var_value(var, cmp_line['vars'], used_vars)
                                    if used_var != 'empty':
                                        used_vars.append(used_var)
                                    var_similarity += float(val / tot_vars) * penalty
                        
                        ret_vals[index] = count_similarity / 4 + var_similarity * 0.75
                if len(ret_vals) == 0:
                    line_similarity = 0
                else:
                    line_similarity = max(ret_vals[x] for x in ret_vals)
                    for ind_ret_vals in ret_vals:
                        if ret_vals[ind_ret_vals] == line_similarity:
                            used.append(ind_ret_vals)
                similarity_values.append(line_similarity)           
            #even more messy due to the dict structure... too many things to check
            
            else: #the line is a conditional, we need to check each condition to decide. 
                conds_line = line['conds']
                cond_similarity = 0
                poss_vals = {}
                for index, cmp_line in enumerate(struct2):
                    cmp_line = struct2[cmp_line]
                    if cmp_line['type'].strip() == line['type'].strip() and index not in used:
                        conds_cmp = cmp_line['conds']
                        if len(conds_line) <= len(conds_cmp): #here I have at least the same amount of conditions or more than the diff code... It may be a match
                            cond_values = []
                            for condind in conds_line:
                                cond_used = []
                                my_condition_type = conds_line[condind]['cond_type'].strip()
                                conds_vals = {}                                                                                            
                                for cmp_cond_id in conds_cmp:
                                    cmp_condition_type = conds_cmp[cmp_cond_id]['cond_type'].strip()
                                    if my_condition_type == cmp_condition_type and cmp_cond_id not in cond_used:
                                        vars1 = conds_line[condind]['vars']
                                        vars2 = conds_cmp[cmp_cond_id]['vars']
                                        cond_var_similarity = 0   
                                        if len(vars1) <= len(vars2):
                                            tot_vars = len(vars1)
                                            used_vars = []
                                            for var01 in vars1:
                                                if len(vars1[var01]['plus']) + len(vars1[var01]['minus']) == 0:
                                                    cond_var_similarity += 100 / tot_vars
                                                else:
                                                    [val, used_var] = get_var_value(vars1[var01], vars2, used_vars)
                                                    if used_var != 'empty':
                                                        used_vars.append(used_var)
                                                    cond_var_similarity += val / tot_vars
                                        conds_vals[cmp_cond_id] = cond_var_similarity    
                                if len(conds_vals) == 0:
                                    better = 0
                                else:
                                    better = max(conds_vals[x] for x in conds_vals)
                                    for j in conds_vals:
                                        if conds_vals[j] == better:
                                            cond_used.append(j)
                                            break
                                cond_values.append(better)
                            poss_vals[index] = sum(cond_values) / len(conds_line) #save the average value for an entire conditional comparison       
                if len(poss_vals) == 0: #this takes care of a block that have no possible match for the conditional
                    cond_similarity = 0
                else:
                    cond_similarity = max(poss_vals[x] for x in poss_vals)
                    for h in poss_vals:
                        if poss_vals[h] == cond_similarity:
                            used.append(h)
                            break
                similarity_values.append(cond_similarity)
        #given the logic of the above code, the resulting values follow the same flow as the original block (instruction types sequence)
        #a missing value will be replaced by 0 and diminish the similarty by 1/block lenght
        v = sum(similarity_values) / len(struct1) 
        values.append(v)
       
    return max(values)
        


      
                                

                        
                    





