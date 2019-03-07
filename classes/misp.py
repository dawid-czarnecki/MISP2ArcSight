"""MISP connection & data processing."""

import copy
from datetime import datetime
import logging
import re
import simplejson as json
import yaml

from pymisp import PyMISP

from classes.helper import Helper

class Misp:
    """Based on the rules and priorities pull data from MISP. Conduct filtering, merging,
    prioritization and manipulation of data from MISP.

    Example:
        misp = Misp(config.get('misp-url'), config.get('misp-key'), not config.get('misp-no-verify-cert'))

        misp.loadRules(config.get('rules-file'))
        misp.downloadOrganisations()
        misp.loadPriorities(config.get('priorities-file'))
        misp.downloadAttributes(config.get('timestamp'))
        misp.applyProposals()
        misp.filterAttributes()
        misp.combineIdenticalAttributes()
        print(json.dumps(misp.getToAddAttributes()))
        print(json.dumps(misp.getToDeleteAttributes()))

    Attributes:
        conditions (list): List of available conditions in rules file.
        available_operators (list): List of available operators in rules file.
        available_fields (dict): Dictionary of available fields in rules file.
            with corresponding conditions and value type.
        attributes_to_add (list of dicts): List of attributes to create in receiving class.
            Each attribute is dict with key names from MISP.
        attributes_to_del (list of dicts): List of attributes to remove in receiving class.
            Each attribute is dict with key names from MISP.
        organisations (list of dicts): List of all available organisations with its
            corresponding priorities.
        pymisp (PyMISP): PyMISP object for handling communication with MISP.
        helper (Helper): Object with some helping methods for processing.
        misp_attributes (list of dicts): Attributes downloaded from MISP
        rules (): ...

    Args:
        url (str): MISP URL.
        key (str): MISP API key.
        verify_cert (bool): Check the validity of MISP certificate

    """
    conditions = [ '=', '!=', '~', '!~', '[]', '![]', '>', '<', '>=', '<=', 'r', '!r' ]
    available_operators = ['&', '|']
    available_fields = {
            # TODO - create separate dict with types and avaliable operators
            # TODO - there are the same conditions for every field with the same type
            # Attribute
            'id': {
                'conditions': ['=', '!=', '[]', '![]', '>', '<', '>=', '<='],
                'value': '[INT]'
            },
            'event_id': {
                'conditions': ['=', '!=', '[]', '![]', '>', '<', '>=', '<='],
                'value': '[INT]'
            },
            'object_id': {
                'conditions': ['=', '!=', '[]', '![]', '>', '<', '>=', '<='],
                'value': '[INT]'
            },
            'category': {
                'conditions': [ '=', '!=', '[]', '![]' ],
                'value': ['Antivirus detection', 'Artifacts dropped', 'Attribution', 'External analysis', 'Financial fraud', 'Internal reference', 'Network activity', 'Other', 'Payload delivery', 'Payload installation', 'Payload type', 'Persistence mechanism', 'Person', 'Social network', 'Support Tool', 'Targeting data'],
            },
            'type': {
                'conditions': [ '=', '!=', '[]', '![]' ],
                # ip type is only for domain|ip type
                'value': ['ip', 'ip-src', 'ip-dst', 'email-src', 'email-dst', 'url', 'domain', 'hostname', 'email-subject', 'email-attachment', 'user-agent', 'target-email', 'filename', 'domain|ip', 'filename|md5', 'filename|sha1', 'filename|sha256']
            },
            'to_ids': {
                'conditions': [ '=', '!=' ],
                'value': [True, False],
            },
            'uuid': {
                'conditions': [ '=', '!=', '~', '!~', '[]', '![]', 'r', '!r' ],
                'value': '[STR]',
            },
            'timestamp': {
                'conditions': [ '=', '!=', '>', '<', '>=', '<=' ],
                'value': '[TIME]', # '^[0-9]+(y|m|d|h)$'
            },
            'distribution': {
                'conditions': ['=', '!=', '[]', '![]', '>', '<', '>=', '<='],
                'value': '[INT]'
            },
            'sharing_group_id': {
                'conditions': ['=', '!=', '[]', '![]', '>', '<', '>=', '<='],
                'value': '[INT]'
            },
            'comment': {
                'conditions': [ '=', '!=', '~', '!~', '[]', '![]', 'r', '!r' ],
                'value': '[STR]',
            },
            # TODO - deleted
            'to_ids': {
                'conditions': [ '=', '!=' ],
                'value': [True, False],
            },
            'value': {
                'conditions': [ '=', '!=', '~', '!~', '[]', '![]', 'r', '!r' ],
                'value': '[STR]',
            },

            # Event
            'Event.id': {
                'conditions': ['=', '!=', '[]', '![]', '>', '<', '>=', '<='],
                'value': '[INT]'
            },
            'Event.org_id': {
                'conditions': ['=', '!=', '[]', '![]', '>', '<', '>=', '<='],
                'value': '[INT]'
            },
            'Event.orgc_id': {
                'conditions': ['=', '!=', '[]', '![]', '>', '<', '>=', '<='],
                'value': '[INT]'
            },
            'Event.date': {
                'conditions': [ '=', '!=', '>', '<', '>=', '<=' ],
                'value': '[TIME]', # '^[0-9]+(y|m|d|h)$'
            },
            'Event.threat_level_id': {
                'conditions': ['=', '!=', '[]', '![]', '>', '<', '>=', '<='],
                'value': '[INT]'
            },
            'Event.info': {
                'conditions': [ '=', '!=', '~', '!~', '[]', '![]' ],
                'value': '[STR]'
            },
            'Event.published': {
                'conditions': [ '=', '!=' ],
                'value': [True, False],
            },
            'Event.uuid': {
                'conditions': [ '=', '!=', '~', '!~', '[]', '![]' ],
                'value': '[STR]'
            },
            'Event.analysis': {
                'conditions': ['=', '!=', '[]', '![]', '>', '<', '>=', '<='],
                'value': '[INT]'
            },
            'Event.timestamp': {
                'conditions': [ '=', '!=', '>', '<', '>=', '<=' ],
                'value': '[TIME]', # '^[0-9]+(y|m|d|h)$'
            },
            'Event.distribution': {
                'conditions': ['=', '!=', '[]', '![]', '>', '<', '>=', '<='],
                'value': '[INT]'
            },
            'Event.proposal_email_lock': {
                'conditions': [ '=', '!=' ],
                'value': [True, False],
            },
            'Event.locked': {
                'conditions': [ '=', '!=' ],
                'value': [True, False],
            },
            'Event.publish_timestamp': {
                'conditions': [ '=', '!=', '>', '<', '>=', '<=' ],
                'value': '[TIME]', # '^[0-9]+(y|m|d|h)$'
            },
            'Event.sharing_group_id': {
                'conditions': ['=', '!=', '[]', '![]', '>', '<', '>=', '<='],
                'value': '[INT]'
            },
            'Event.disable_correlation': {
                'conditions': [ '=', '!=' ],
                'value': [True, False],
            },
            # Event Org
            'Event.Org.name': {
                'conditions': [ '=', '!=', '~', '!~', '[]', '![]' ],
                'value': '[STR]'
            },
            'Event.Org.uuid': {
                'conditions': [ '=', '!=', '~', '!~', '[]', '![]' ],
                'value': '[STR]'
            },
            # Event Tag
            'Event.Tag.id': {
                'conditions': ['=', '!=', '[]', '![]', '>', '<', '>=', '<='],
                'value': '[INT]'
            },
            'Event.Tag.name': {
                'conditions': [ '=', '!=', '~', '!~', '[]', '![]' ],
                'value': '[STR]'
            },
            # Event Galaxy
            'Event.Galaxy.id': {
                'conditions': ['=', '!=', '[]', '![]', '>', '<', '>=', '<='],
                'value': '[INT]'
            },
            'Event.Galaxy.uuid': {
                'conditions': [ '=', '!=', '~', '!~', '[]', '![]' ],
                'value': '[STR]'
            },
            'Event.Galaxy.name': {
                'conditions': [ '=', '!=', '~', '!~', '[]', '![]' ],
                'value': '[STR]'
            },
            'Event.Galaxy.type': {
                'conditions': [ '=', '!=', '~', '!~', '[]', '![]' ],
                'value': '[STR]'
            },
    }
    attributes_to_add = []
    attributes_to_del = []
    organisations = []
    
    def __init__(self, url, key, verify_cert):
        self.pymisp = PyMISP(url, key, verify_cert)
        self.helper = Helper()

    def loadRules(self, rules_file):
        """Load and verify rules from file.
        It accepts yaml and json files. Saves rules to self.rules

        Args:
            rules_file (str): Rules filename.

        Exits:
            If there is wrong file type or if there is an bug in the format of the file.

        """

        # Rules file check
        if rules_file[-5:] == '.yaml':
            rules = yaml.load(open(rules_file, 'r'))
        elif rules_file[-5:] == '.json':
            rules = json.load(open(rules_file, 'r'))
        else:
            logging.error('Rules file in wrong format: {} insted of {}'.format(rules_file[-5:], ['yaml', 'json']))
            exit()

        if not self.verifyRules(rules):
            logging.error('There is an error in the rules file: {}'.format(rules_file))
            exit()

        self.rules = rules

    def downloadAttributes(self, timestamp):
        """Download attributes from MISP in a given timestamp.
        It enriches each attribute with data about event.
        Save attributes to self.misp_attributes.
        Sends one REST API request to MISP.

        Args:
            timestamp (str): Interval since last update (in seconds or 1d, 1h, ...).

        """
        p = self.pymisp.search('attributes', timestamp=timestamp, deleted=True, includeProposals=True)['response']
        if 'Attribute' not in p:
            logging.info('No new or changed attributes in MISP.')
            return

        self.misp_attributes = p['Attribute']

        # Enrich attributes with Event info
        if len(self.misp_attributes) != 0:
            if 'threat_level_id' not in self.misp_attributes[0]['Event']:
                self.enrichAttributes()
            
            self.misp_attributes = self.explodePiped(self.misp_attributes)

        try:
            time_readable = datetime.utcfromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            time_readable = timestamp
        logging.info('Downloaded {} attributes from MISP since {}.'.format(len(self.misp_attributes), time_readable))

    def loadAttributes(self, fname):
        """Load attributes from JSON file.

        Args:
            fname (str): JSON filename

        Exits:
            If extension of the file is not json.

        """
        if fname[-5:] != '.json':
            logging.error('Input file in wrong format: {} insted of json'.format(priorities_file[-5:]))
            exit()
        self.misp_attributes = json.load(open(fname, 'r'))
        logging.info('Loaded {} attributes from MISP.'.format(len(self.misp_attributes)))

    def enrichAttributes(self):
        """Pull additional data about events and enrich attributes with that
        Modify self.misp_attributes and saves result there.
        Sends one REST API request to MISP.

        """

        event_ids = {}
        for attribute in self.misp_attributes:
            event_ids[int(attribute['Event']['id'])] = True

        event_ids = list(event_ids.keys())
        events = self.pymisp.search('events', eventid=event_ids)['response']
        for i in range(len(events)):
            del events[i]['Event']['Attribute']
            del events[i]['Event']['ShadowAttribute']
            del events[i]['Event']['RelatedEvent']

        for attribute in self.misp_attributes:
            for event in events:
                event = event['Event']
                if event['id'] == attribute['event_id']:
                    break
            attribute['Event'] = event

    def printAttributes(self):
        """Print downloaded attributes in json format"""

        print(json.dumps(self.misp_attributes))

    def downloadOrganisations(self):
        """Download all organisations
        Saves result to self.organisations

        """

        organisations = self.pymisp.get_organisations_list('all')['response']

        # Get max organisation id
        max_id = 0
        for org in organisations:
            id = int(org['Organisation']['id'])
            if id > max_id:
                max_id = id

        self.organisations = [None] * (max_id + 1)

        for org in organisations:
            o = org['Organisation']
            self.organisations[int(o['id'])] = {'name': o['name']}

        logging.info('Loaded {} organisations from MISP.'.format(len(organisations)))
    
    def loadPriorities(self, priorities_file):
        """Load and verify priorities from file
        Accept yaml and json files.
        Save priorities to self.organisations.

        Args:
            priorities_file (str): Priorities filename.

        Exits:
            If there is wrong file type or if there is an bug in the format of the file.

        """

        # Priorities file check
        if priorities_file[-5:] == '.yaml':
            priorities = yaml.load(open(priorities_file, 'r'))
        elif priorities_file[-5:] == '.json':
            priorities = json.load(open(priorities_file, 'r'))
        else:
            logging.error('Priorities file in wrong format: {} insted of {}'.format(priorities_file[-5:], ['yaml', 'json']))
            exit()

        verified = self.verifyPriorities(priorities)
        if not verified:
            logging.error('There is an error in the priorities file: {}'.format(priorities_file))
            exit()

        loaded = 0
        for org in verified:
            for id in range(len(self.organisations)):
                if self.organisations[id] is not None and org['name'] == self.organisations[id]['name']:
                    loaded += 1
                    self.organisations[id]['priority'] = org['priority']
        
        logging.info('Loaded {} priorities.'.format(loaded))

    def explodePiped(self, misp_attributes):
        """Explode each piped attribute into two
        It uses deepcopy to completely copy attribute with.

        Args:
            misp_attributes (list of dicts): List of attributes

        Returns:
            list: List of attributes

        """

        piped = []
        for misp_attribute in misp_attributes:
            if '|' in misp_attribute['type']:
                attribute1 = copy.deepcopy(misp_attribute)
                attribute1['type'] = attribute1['type'].split('|')[0]
                attribute1['value'] = attribute1['value'].split('|')[0]

                attribute2 = copy.deepcopy(misp_attribute)
                attribute2['type'] = attribute2['type'].split('|')[1]
                attribute2['value'] = attribute2['value'].split('|')[1]

                piped.append(attribute1)
                piped.append(attribute2)
            else:
                piped.append(misp_attribute)

        return piped

    def applyProposals(self):
        """Apply proposals to attributes for further processing.
        Use priorities to decide which proposal is more important.
        Operates on self.misp_attributes
        Saves result to self.attributes_to_add

        Exits:
            If no organisations have been loaded.

        """

        if self.misp_attributes is None:
            logging.warning('No MISP attributes to parse')
            return
        if self.organisations is None:
            logging.error('No organisations loaded')
            exit()

        merged = []
        count = 0
        for attribute in self.misp_attributes:
            if 'ShadowAttribute' not in attribute:
                merged.append(attribute)
                continue

            final = attribute
            event = attribute['Event']

            for shadow in attribute['ShadowAttribute']:
                # Compare orgs priorities
                final_priority = self.organisations[int(event['orgc_id'])].get('priority', 0)
                shadow_priority = self.organisations[int(shadow['org_id'])].get('priority', 0)
                if shadow_priority > final_priority:
                    final = shadow
                    final['Event'] = event
                    continue
                elif final_priority > shadow_priority:
                    continue

                # Compare ids flags
                final_ids = final['to_ids']
                final_delete = final['deleted']
                final_decision = not final_delete if final_delete else final_ids

                shadow_ids = shadow['to_ids']
                shadow_delete = shadow['proposal_to_delete']
                shadow_decision = not shadow_delete if shadow_delete else shadow_ids
                # When two shadow attributes are with different decision take this one where decision is positive
                # old_id key exists only in final which is shadow attribute
                if 'old_id' in final and final_decision != shadow_decision and final_decision:
                    continue

                # By default replace final attribute with the newest shadow attribute
                final = shadow
                final['Event'] = event

            merged.append(final)
            if 'old_id' in final:
                count += 1

        self.attributes_to_add = merged
        # self.merged_attributes = merged
        logging.info('{} proposals applied to attributes.'.format(count))

    def filterAttributes(self):
        """Filter attributes according to rules
        Operates on self.attributes_to_add
        Saves result to self.attributes_to_add

        Exits:
            If there is no rules loaded.

        """

        if self.attributes_to_add is None:
            logging.warning('No MISP attributes to parse')
            return
        if self.rules is None:
            logging.error('No rules found')
            exit()

        filtered = []
        for attribute in self.attributes_to_add:
            if self.checkAttribute(attribute, self.rules):
                filtered.append(attribute)
            else:
                self.attributes_to_del.append(attribute)

        logging.info('With total {} attributes {} marked to add, {} marked to delete according to rules.'.format(len(self.attributes_to_add), len(filtered), len(self.attributes_to_del)))
        self.attributes_to_add = filtered
        #logging.info('{} out of {} attributes filtered out according to rules.'.format(len(self.merged_attributes) - len(self.attributes_to_add), len(self.merged_attributes)))

    def combineIdenticalAttributes(self):
        """Combine attributes with identical values from different events.
        Operates on self.attributes_to_add

        Todo:
            Combine identical to_delete (not only to_add)

        """
        combined = []
        # Search for attrs with identical value and merge them by adding dict key 'Related' to first of them
        for left in self.attributes_to_add:
            if 'already_parsed' in left:
                continue

            related = []
            for right in self.attributes_to_add:
                if left['value'] == right['value']:
                    if left['uuid'] == right['uuid']:
                        continue

                    related.append(copy.deepcopy(right))
                    right['already_parsed'] = 1

            tmp = copy.deepcopy(left)
            if len(related) > 0:
                tmp['Related'] = related
            combined.append(tmp)

        logging.info('Found {} identical attributes. After combine {} attributes left.'.format(len(self.attributes_to_add) - len(combined), len(combined)))
        # self.combined_attributes = combined
        self.attributes_to_add = combined

    def skipUnpublished(self):
        """Remove from attributes_to_add and attributes_to_delete attributes from unpublished events"""

        skipped = 0
        for i in range(len(self.attributes_to_add)):
            if not self.checkIfPublished(self.attributes_to_add[i]):
                del self.attributes_to_add[i]
                skipped += 1

        for i in range(len(self.attributes_to_del)):
            if not self.checkIfPublished(self.attributes_to_del[i]):
                del self.attributes_to_del[i]
                skipped += 1

        logging.info('Skipped {} attributes from unpublished events.'.format(skipped))

    def checkIfPublished(self, attribute):
        """Check if attribute's event is published
        
        Args:
            attribute (dict): Attribute dictionary with all the fields from MISP.

        Returns:
            bool: True if event of a given attribute is published. False otherwise.

        """

        if 'Event' not in attribute:
            logging.error('Attribute {} from event {} does not have event details. Published state cannot be established.'.format(attribute['value'], attribute['event_id']))
            exit()

        if 'published' not in attribute['Event']:
            logging.error('Attribute {} from event {} does not have publish state.'.format(attribute['value'], attribute['event_id']))
            exit()

        return attribute['Event']['published']

    def getToAddAttributes(self):
        """Return attributes which should be added"""

        return self.attributes_to_add

    def getToDeleteAttributes(self):
        """Return attributes which should be removed"""

        return self.attributes_to_del

    def checkAttribute(self, attribute, rules):
        """Recursively check if attribute passes rules filter or not

        Args:
            attribute (dict): Attribute dictionary with all the fields from MISP.
            rules (nested dict): Rules dictionary.

        Returns:
            bool: True if attribute passes filter. False otherwise.

        Exits:
            If rules dictionary is incorrectly build (e.g. no operator, or condition is incorrect)

        """
        
        components = rules.get('components')
        operator = rules.get('operator')
        if operator is None:
            logging.error('Error in rules file. Rules doesn\'t have operator field.')
            exit()
        if components is None:
            logging.error('Error in rules file. Rules doesn\'t have components field.')
            exit()
        if not isinstance(components, list):
            logging.error('Error in rules file. Components field is type {} insted of a list.'.format(type(components)))
            exit()
        if operator not in self.available_operators:
            logging.error('Error in rules file. Operator {} is not allowed operator. Allowed operators are: {}'.format(operator, self.available_operators))
            exit()

        # Set first left side of the condition
        if operator == '&':
            result = True
        else:
            result = False

        for c in components:
            if 'field' in c and 'condition' in c and 'value' in c:
                if '.' in c['field']:
                    attribute_values = self.helper.getValueFromObject(attribute, c['field'])
                else:
                    attribute_values = attribute[c['field']]

                if not isinstance(attribute_values, list):
                    attribute_values = [attribute_values]

                if len(attribute_values) == 0:
                    cond_result = False
                else:
                    # Check if any of the values meet the condition
                    for attribute_value in attribute_values:
                        # Analyzing one condition
                        if c['condition'] == '=':
                            cond_result = attribute_value == c['value']
                        elif c['condition'] == '!=':
                            cond_result = attribute_value != c['value']
                        elif c['condition'] == '~':
                            cond_result = c['value'] in attribute_value
                        elif c['condition'] == '!~':
                            cond_result = c['value'] not in attribute_value
                        elif c['condition'] == '[]':
                            cond_result = attribute_value in c['value']
                        elif c['condition'] == '![]':
                            cond_result = attribute_value not in c['value']
                        elif c['condition'] == '>':
                            cond_result = int(attribute_value) > int(c['value'])
                        elif c['condition'] == '<':
                            cond_result = int(attribute_value) < int(c['value'])
                        elif c['condition'] == '>=':
                            cond_result = int(attribute_value) >= int(c['value'])
                        elif c['condition'] == '<=':
                            cond_result = int(attribute_value) <= int(c['value'])
                        elif c['condition'] == 'r':
                            regex = c['value']
                            cond_result = re.search(regex, attribute_value) is not None
                        elif c['condition'] == '!r':
                            regex = c['value']
                            cond_result = re.search(regex, attribute_value) is None
                        else:
                            logging.error('Error in checking attribute {}'.format(attribute_value))
                            exit()

                        if cond_result:
                            break
            elif 'components' in c and 'operator' in c:
                # Going down to deeper conditions
                cond_result = self.checkAttribute(attribute, c)
            else:
                logging.warning('Component has invalid structure. It has to have fields: "field", "value", "condition" or "components", "operator". Instead it has: {}'.format(', '.join(c.keys())))
                continue

            if operator == '&':
                result = result and cond_result
            else:
                result = result or cond_result

        return result

    # def extendAttributes(self):
    #     """Extends attributes with additional fields."""

    #     for num in range(len(self.attributes_to_add)):
    #         a = self.extendAttribute(self.attributes_to_add[num])
    #         self.attributes_to_add[num] = a

    # def extendAttribute(self, attribute):
    #     """Extends attribute with additional fields ingested by ArcSight."""

    #     # 1. Organisation name
    #     org_id = int(attribute['Event']['org_id'])
    #     orgc_id = int(attribute['Event']['orgc_id'])
    #     attribute['Event']['org_name'] = self.organisations[org_id]['name']
    #     attribute['Event']['orgc_name'] = self.organisations[orgc_id]['name']

    #     return attribute

    def verifyPriorities(self, priorities):
        """Verify correctness of priorities
        Verify all provided priorities. Skip organisation if there is some error.

        Args:
            priorities (dict): Priorities to verify. Example
                {'organisations': [
                    {'name': 'Organisation A', 'priority': 1},
                    {'name': 'Organisation B', 'priority': 2}
                ]}:

        Returns:
            bool: False if there is no organisations key in dictionary.
            list: List of parsed priorities.

        """
        org_priorities = priorities.get('organisations')
        if org_priorities is None:
            logging.warning('Error in priorities file. Organisations field is required.')
            return False

        verified = []
        for priority_org in org_priorities:
            if 'name' not in priority_org:
                logging.warning('Error in priorities file. Organisation doesn\'t have name field. Skipping.')
                continue
            else:
                # TODO Write verification if this prioritzanisation exists in MISP
                orgs = [org['name'] for org in self.organisations if org is not None]
                if priority_org['name'] not in orgs:
                    logging.warning('Error in priorities file. Organisation {} doesn\'t exist. Skipping.'.format(priority_org.get('name')))
                    continue

            if 'priority' not in priority_org:
                logging.warning('Error in priorities file. Organisation {} doesn\'t have priority field. Skipping.'.format(priority_org.get('name')))
                continue
            elif not isinstance(priority_org.get('priority'), int):
                logging.warning('Error in priorities file. Organisation {} priority is not int. It is: {}. Skipping.'.format(priority_org.get('name'), type(priority_org.get('priority'))))
                continue

            verified.append(priority_org)
        return verified

    def verifyRules(self, rules):
        """Verify correctness of rules
        Verify recursively all provided operators, fields, conditions and values.

        Args:
            rules (nested dict): Rules to verify:
                operator: "&"
                components:
                - field: Event.Tag.name
                  condition: "="
                  value: "APT"

        Returns:
            bool: True if successfully parsed rules, False otherwise.

        """
        components = rules.get('components')
        operator = rules.get('operator')

        if operator is None:
            logging.warning('Error in rules file. Rules doesn\'t have operator field.')
            return False
        if components is None:
            logging.warning('Error in rules file. Rules doesn\'t have components field.')
            return False
        if not isinstance(components, list):
            logging.warning('Error in rules file. Components field is type "{}" insted of a list.'.format(type(components)))
            return False
        if operator not in self.available_operators:
            logging.warning('Error in rules file. Operator "{}" is not allowed operator. Allowed operators are: {}'.format(operator, self.available_operators))
            return False

        result = True
        for c in components:
            if 'field' in c and 'value' in c and 'condition' in c:
                if c['condition'] not in self.conditions:
                    logging.warning('Condition "{}" is invalid for the field "{}". All posible conditions: {}'.format(c['condition'], c['field'], ', '.join(self.conditions)))
                    result = False
                # Check if field is correct
                if c['field'] not in self.available_fields:
                    logging.warning('Field "{}" is invalid. Valid fields are: {}'.format(c['field'], ', '.join(self.available_fields.keys())))
                    result = False
                # Check if condition is appropriate for the field
                elif c['condition'] not in self.available_fields[c['field']]['conditions']:
                    logging.warning('Field "{}" cannot be processed with condition "{}". Available conditions: {}'.format(c['field'], c['condition'], ', '.join(self.available_fields[c['field']]['conditions'])))
                    result = False
                # Check if value is appropriate type for the field
                else:
                    if self.available_fields[c['field']]['value'] == '[INT]':
                        if isinstance(c['value'], list):
                            for temp_value in c['value']:
                                if not isinstance(temp_value, int):
                                    logging.warning('Field "{}" can have only int values. One of the value "{}" is type "{}".'.format(c['field'], temp_value, type(temp_value)))
                                    result = False
                        elif not isinstance(c['value'], int):
                            logging.warning('Field "{}" can have only int values. Value "{}" is type "{}".'.format(c['field'], c['value'], type(c['value'])))
                            result = False
                    elif self.available_fields[c['field']]['value'] == '[STR]':
                        if isinstance(c['value'], list):
                            for temp_value in c['value']:
                                if not isinstance(temp_value, str):
                                    logging.warning('Field "{}" can have only str values. One of the value "{}" is type "{}".'.format(c['field'], temp_value, type(temp_value)))
                                    result = False
                        elif not isinstance(c['value'], (str, list)):
                            logging.warning('Field "{}" can have only str values. Value "{}" is type "{}".'.format(c['field'], c['value'], type(c['value'])))
                            result = False
                    elif self.available_fields[c['field']]['value'] == '[TIME]':
                        search = re.search(r'^[0-9]+(y|m|d|h)?$', c['value'], re.I)
                        if not search:
                            logging.warning('Field "{}" can have only time values (1d, 3h, 2m). Value "{}" is type "{}".'.format(c['field'], c['value'], type(c['value'])))
                            result = False
                    elif isinstance(self.available_fields[c['field']]['value'], list):
                        if isinstance(c['value'], list):
                            for temp_value in c['value']:
                                if temp_value not in self.available_fields[c['field']]['value']:
                                    logging.warning('One of the values "{}" is invalid for the field "{}". It has to be one of the following: {}'.format(temp_value, c['field'], ', '.join([str(x) for x in self.available_fields[c['field']]['value']])))
                                    result = False
                        elif c['value'] not in self.available_fields[c['field']]['value']:
                            logging.warning('Value "{}" is invalid for the field "{}". It has to be one of the following: {}'.format(c['value'], c['field'], ', '.join([str(x) for x in self.available_fields[c['field']]['value']])))
                            result = False
            elif 'components' in c and 'operator' in c:
                # Going down to deeper conditions
                result = result and self.verifyRules(c)
            else:
                logging.warning('Component has invalid structure. It has to have fields: "field", "value", "condition" or "components", "operator". Instead it has: {}'.format(', '.join(c.keys())))
                result = False

        return result

    