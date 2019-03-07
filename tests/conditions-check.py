#!/usr/bin/python

import json
import yaml

f = open('example-rules.yaml')
y = yaml.load(f)

data = [{'value': 'dupa1', 'published': True, 'deleted': False, 'type': 'url', 'id': 6},
        {'value': 'kupa1', 'published': True, 'deleted': True, 'type': 'url', 'id': 76},
        {'value': 'razraz', 'published': False, 'deleted': True, 'type': 'url', 'id': 111},
        {'value': 'dwadwa', 'published': False, 'deleted': False, 'type': 'url', 'id': 6}]

def check_row(row, export):
    if 'operator' not in export:
        raise Exception('Error in config file. Export doesn\'t have operator field.')
    if 'components' not in export:
        raise Exception('Error in config file. Export doesn\'t have components field.')

    components = export['components']
    operator = export['operator']

    if not isinstance(components, list):
        raise Exception('Error in config file. Components field is {} insted of a list.'.format(type(components)))

    allowed_operators = ['&', '|']
    if operator not in allowed_operators:
        raise Exception('Error in config file. Operator {} is not allowed operator. Allowed operators are: {}'.format(operator, allowed_operator))

    if operator == '&':
        result = True # True & the rest of the statement
    else:
        result = False # False | the rest of the statement
    
    for c in components:
        if 'field' in c and 'value' in c and 'condition' in c:
            # Analyzing one condition
            #print('{} ({}) {} {}'.format(c['field'], row[c['field']], c['condition'], c['value']))
            if c['condition'] == '=':
                cond_result = row[c['field']] == c['value']
            elif c['condition'] == '!=':
                cond_result = row[c['field']] != c['value']
            elif c['condition'] == '~':
                cond_result = row[c['field']] in c['value']
            elif c['condition'] == '!~':
                cond_result = row[c['field']] not in c['value']
            elif c['condition'] == '[]':
                cond_result = row[c['field']] in c['value']
            elif c['condition'] == '!{}':
                cond_result = row[c['field']] not in c['value']
        elif 'components' in c and 'operator' in c:
            # Going down to deeper conditions
            cond_result = check_row(row, c)
        else:
            raise Exception('Component has invalid structure. It has to have fields: "field", "value", "condition" or "components", "operator". Instead it has: {}'.format(c))
            #logging.warning('Component has invalid structure. It has to have fields: "field", "value", "condition" or "components", "operator". Instead it has: {}'.format(c))
            #continue

        if operator == '&':
            result = result & cond_result
        else:
            result = result | cond_result

    return result

for d in data:
    print('{} = {}'.format(d, check_row(d, y)))
