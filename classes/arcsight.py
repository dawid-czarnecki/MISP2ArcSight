"""ArcSight active list connection & manipulation."""
import copy
from datetime import datetime
import logging
import simplejson as json
import time
import yaml

from pyasesm import ActiveLists

from classes.helper import Helper

class ArcSight:
    """Update ArcSight active lists with provided data.
    Take data from MISP and push it to ArcSight.
    After updating active lists it pulls data from current Active Lists
    and make diff between those entries and entries in memory (from MISP or other source).

    Example:
        arcsight = ArcSight(config.get('arcsight-url'), config.get('arcsight-username'),
        config.get('arcsight-password'), config.get('arcsight-map'), proxies=proxy)
        arcsight.addEntries(to_add)
        arcsight.deleteEntries(to_delete)
        if arcsight.verifyChanges() is not False:
            print('MISP to ArcSight export went successful. Expected result achieved.')

    Attributes:
        test (bool): If true don't update active lists just print actions.
        helper (Helper): Object with some helping methods for processing.
        maps (dict): Mapping rules of active lists.
        default_merge_function (str): Default function used to merge multiple values.
        default_convert_function (str): Default function used to conver mapped values.
        active_lists (ActiveLists): pyasesm.ActiveLists object for handling communication with ArcSight Active Lists.
        entries (dict of lists): Dictionary with current active lists entries.
        to_add (dict of lists): Dictionary with active lists entries to add.
        to_delete (dict of lists): Dictionary with active lists entries to remove.
        attributes_to_skip (list of dicts): List of attributes to skip. Those attributes will not change their state.
            They will not be added to active list or removed/updated from one.

    Args:
        url (str): ArcSight ESM URL.
        username (str): ArcSight ESM username.
        password (str): ArcSight ESM password.
        map_file (str): Filename of yaml file with mapping rules.
        proxies (dict): Proxy configuration
        verify (bool): Check the validity of ArcSight ESM certificate

    Exits:
        If there is wrong map_file type or there was an error in ESM connection.

    """
    def __init__(self, url, username, password, map_file, proxies=None, verify=True):
        # Ruleset to map fields from MISP to ArcSight
        # For each field of MISP attribute convert function (example: self._convertComma) will be executed
        # If dots are in misp field name threat it as a nested dict. Example A.B.C -> misp_entry[A][B][C]
        self.test = False
        self.helper = Helper()
        self.maps = yaml.load(open(map_file, 'r'))
        if not self._verifyMap(self.maps):
            logging.error('There is an error in the map file: {}'.format(map_file))
            exit()

        self.default_merge_function = 'space'
        self.default_convert_function = 'return'

        self.active_lists = ActiveLists(url, username, password, proxies=proxies, verify=False)
        if not self.active_lists:
            logging.error('Could not connect to ArcSight ESM')
            exit()

        self.entries = {}
        self.to_add = {}
        self.to_delete = {}
        self.attributes_to_skip = []

        for i in range(len(self.maps)):
            active_list = self.maps[i]
            # Select active list primary key if there is none
            if 'primary_key' not in active_list:
                for rule in active_list['map']:
                    if rule['misp'] == 'value':
                        self.maps[i]['primary_key'] = rule['arcsight']
                        break
            self.to_add[active_list['id']] = []
            self.to_delete[active_list['id']] = []
            self.entries[active_list['id']] = self.active_lists.getEntries(active_list['id'])

    def skipAttributes(self, attributes):
        """Saves attributes to skip.

        Args:
            attributes (list of dicts): MISP attributes to skip

        """

        for attribute in attributes:
            self.attributes_to_skip.append(attribute['value'])

    def addEntries(self, to_add):
        """Add list of entries to arcsight.

        Args:
            to_add (list): List of entries.

        Returns:
            int: Number of added entries.

        """

        for new in to_add:
            self.prepareEntryToAdd(new)

        result = 0
        for list_id in self.to_add:
            if len(self.to_add[list_id]) > 0:
                result += self.active_lists.addEntries(self.to_add[list_id], list_id)
        return result

    def prepareEntryToAdd(self, misp_attribute):
        """Prepare entry by mapping it from MISP field names to Active List.
        Save result to self.to_add

        Args:
            misp_attribute (dict): MISP attribute with all the properties for preparation to add.
        
        Todo:
            Comment on for's what are they for.

        """

        assigned_num = 0
        for active_list in self.maps:
            arcsight_entry = {}
            if isinstance(active_list['value'], list):
                if misp_attribute.get(active_list['key']) in active_list['value']:
                    logging.debug('Attribute {} assigned to list {}.'.format(misp_attribute['value'].replace("\r\n",' '), active_list['name']))
                    assigned_num += 1
                else:
                    continue
            else:
                if misp_attribute.get(active_list['key']) == active_list['value']:
                    logging.debug('Attribute {} assigned to list {}.'.format(misp_attribute['value'].replace("\r\n",' '), active_list['name']))
                    assigned_num += 1
                else:
                    continue
            for rule in active_list['map']:
                # Iterate through rules

                # Prepare function for converting MISP value for ArcSight
                convert_name = rule.get('convert', self.default_convert_function)
                convert_name = convert_name[0].upper() + convert_name[1:]
                convertFunction = getattr(self, '_convert'+convert_name)

                merge_name = rule.get('merge', self.default_merge_function)
                merge_name = merge_name[0].upper() + merge_name[1:]
                mergeFunction = getattr(self, '_merge'+merge_name)

                if isinstance(rule['misp'], list):
                    map_misp_fields = rule['misp']
                else:
                    # Create one-element list for easier and more clear processing
                    map_misp_fields = [rule['misp']]

                misp_values = []
                # 1. Iterate through all fields in MISP and merge them
                for dot_filter in map_misp_fields:
                    # if dot_filter[len(dot_filter)-1] != '.':
                    #     # Add dot at the end for easier and more clear processing
                    #     dot_filter += '.'

                    # 2. Iterate through dotted field names and extract nested falue (example: misp_attribute['Event']['info'])
                    misp_values.append(self.helper.getValueFromObject(misp_attribute, dot_filter, convertFunction, mergeFunction))

                arcsight_entry[rule['arcsight']] = mergeFunction(misp_values)

            self.to_add[active_list['id']].append(arcsight_entry)

        logging.debug('Attribute {} assigned to {} lists.'.format(misp_attribute['value'].replace("\r\n",' '), assigned_num))

    def deleteEntries(self, to_delete):
        """Remove list of entries to arcsight.

        Args:
            to_add (list): List of entries.

        Returns:
            int: Number of removed entries

        """

        for entry in to_delete:
            self.prepareEntryToDelete(entry)

        result = 0
        for list_id in self.to_delete:
            if len(self.to_delete[list_id]) > 0:
                result += self.active_lists.deleteEntries(self.to_delete[list_id], list_id)
        return result

    def prepareEntryToDelete(self, misp_attribute):
        """Prepare entry by mapping it from MISP field names to Active List.
        Save result to self.to_delete.

        Args:
            misp_attribute (dict): MISP attribute with all the properties for preparation to delete.

        Todo:
            verify correctness of this function. Last line of this method is incorrect (logging.debug)

        """
        assigned_num = 0
        for active_list in self.maps:
            if isinstance(active_list['value'], list):
                if misp_attribute.get(active_list['key']) in active_list['value']:
                    logging.debug('Attribute {} assigned to list {}.'.format(misp_attribute['value'].replace("\r\n",' '), active_list['name']))
                    assigned_num += 1
                else:
                    continue
            else:
                if misp_attribute.get(active_list['key']) == active_list['value']:
                    logging.debug('Attribute {} assigned to list {}.'.format(misp_attribute['value'].replace("\r\n",' '), active_list['name']))
                    assigned_num += 1
                else:
                    continue
            for entry in self.entries[active_list['id']]:
                if entry[active_list['primary_key']] == misp_attribute['value']:
                    self.to_delete[active_list['id']].append(entry)

        logging.debug('Attribute {} assigned to {} lists.'.format(misp_attribute['value'].replace("\r\n",' '), assigned_num))

    def testDifferences(self, to_add, to_delete):
        """Prepare lists of attributes to add and to delete.
        Additionaly save the different jsons to logs directory.

        Args:
            to_add (list): List of entries to add
            to_delete (list): List of entries to delete

        Returns:
            bool: True if adding and removing entries from active lists went successful.
            
        """

        self.test = True
        for entry in to_add:
            self.prepareEntryToAdd(entry)

        for entry in to_delete:
            self.prepareEntryToDelete(entry)
        
        result = self.verifyChanges()
        if result is True:
            return True

        # Prints warning messages - differences
        for error in result:
            print('List: {}. Attribute: {} = {}. {}'.format(error['list'], error['primary_key'], error['value'], error['message']))

        # Save differences
        now = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        with open('logs/{}_current.json'.format(now), 'w') as file:
            json.dump(self.entries, file)
        with open('logs/{}_expected.json'.format(now), 'w') as file:
            json.dump(self.expected, file)

        return False

    def selectActiveList(self, misp_attribute):
        """Get num and id of active list for particular misp attribute
        
        Args:
            misp_attribute (dict): MISP attribute with all the properties.

        Returns:
            dict: List number and list id of a given misp attribute.

        """

        list_num = list_id = None
        for i in range(len(self.maps)):
            list_map = self.maps[i]
            if isinstance(list_map['value'], list):
                if misp_attribute.get(list_map['key']) in list_map['value']:
                    list_num = i
                    list_id = self.maps[i]['id']
                    logging.debug('Attribute {} assigned to list {}.'.format(misp_attribute['value'], list_map['name']))
                    break
            else:
                if misp_attribute.get(list_map['key']) == list_map['value']:
                    list_num = i
                    list_id = self.maps[i]['id']
                    logging.debug('Attribute {} assigned to list {}.'.format(misp_attribute['value'], list_map['name']))
                    break

        if list_num is None:
            return False
        return {'num': list_num, 'id': list_id}

    def info(self, list_id=None):
        """Get the details of active list

        Args:
            list_id (int): Id of active list.
        
        Returns:
            dict: Active list properties.

        """
        return self.active_lists.info(list_id)

    def verifyChanges(self):
        """Pull entries from ArcSight again and compare it from those before the change

        Returns:
            bool: True if lists are equal and export went successfully.
            List: List with differencies.

        """

        # Prepare list with expected ArcSight entries
        self.expected = {}
        for active_list in self.maps:
            list_id = active_list['id']
            primary_key = active_list['primary_key']
            self.expected[list_id] = copy.deepcopy(self.entries[list_id])

            if len(self.to_add[list_id]) == 0:
                continue
            for to_add_entry in self.to_add[list_id]:
                exists = False
                for expected_entry in self.expected[list_id]:
                    if to_add_entry[primary_key] == expected_entry[primary_key]:
                        exists = True
                        break
                if not exists:
                    self.expected[list_id].append(to_add_entry)

            # for entry in self.entries[list_id]:
            #     exists = False
            #     for to_add_entry in self.to_add[list_id]:
            #         if to_add_entry[primary_key] == entry[primary_key]:
            #             exists = True
            #             self.expected[list_id].append(to_add_entry)
            #             break
            #     if not exists:
            #         self.expected[list_id].append(entry)
            # print(json.dumps(self.to_add))
            # exit()
            new_expected = []
            for expected_entry in self.expected[list_id]:
                add = True
                for to_delete_entry in self.to_delete[list_id]:
                    if to_delete_entry[primary_key] == expected_entry[primary_key]:
                        add = False
                        break
                if add:
                    new_expected.append(expected_entry)
            self.expected[list_id] = new_expected
            del new_expected

        valid_str = '_valid_arcsight_entry'
        errors = []
        for active_list in self.maps:
            list_id = active_list['id']
            primary_key = active_list['primary_key']
            if self.test:
                current = self.entries[list_id]
            else:
                current = self.active_lists.getEntries(list_id)

            # Compare precisely current ArcSight database and expected result
            for expected_entry in self.expected[list_id]:
                found = False
                current_entry = None
                for i in range(len(current)):
                    current_entry = current[i]
                    if expected_entry[primary_key] != current_entry[primary_key]:
                        continue

                    found = True
                    current_entry[valid_str] = True
                    errors.extend(self._compareEntries(current_entry, expected_entry, primary_key, active_list['name']))
                    break
                if not found:
                # if current_entry is None or valid_str not in current_entry:
                    errors.append({'primary_key': primary_key, 'value': expected_entry[primary_key], 'list': active_list['name'], 'message': 'Entry does not exist in ArcSight.'})
                    if not self.test:
                        logging.error('ArcSight entry {} does not exist in list {}.'.format(expected_entry[primary_key], active_list['name']))

            # Check if there are some current entries which are not in the expected list
            for current_entry in current:
                if valid_str not in current_entry:
                    errors.append({'primary_key': primary_key, 'value': current_entry[primary_key], 'list': active_list['name'], 'message': 'Entry should not exists in ArcSight'})
                    if not self.test:
                        logging.error('Entry {} should not exist in ArcSight {}.'.format(current_entry[primary_key], active_list['name']))

        if errors:
            return errors
        return True

    def _compareEntries(self, current, expected, primary_key, list_name):
        """Compares current and expected ArcSight entry

        Args:
            current (dict): Current entry from active list.
            expected (dict): Entry which is expected to be on active list.
            primary_key (str): Primary key based on which comparison is made.
            list_name (str): List name for messaging purposes.

        Returns:
            list: Errors if any or empty list.

        """

        errors = []
        for key, expected_value in expected.items():
            # This is temporary bypass for auto-updating time in ticketDate.
            # Remove it when GMT to timestamp conversion is ready and 
            #  addEntries is modified so it sends only changed entries
            if key in ('ticketDate', 'publishedDate'):
                continue
            if key not in current:
                errors.append({'primary_key': primary_key, 'value': expected[primary_key], 'list': list_name, 'message': 'missing key: '+key, })
                if not self.test:
                    logging.error('ArcSight entry {} was not updated in list {}. {} does not exist in ArcSight and should be "{}".'.format(expected[primary_key], list_name, key, expected_value))
            else:

                if current[key] != expected_value:
                    errors.append({'primary_key': primary_key, 'value': expected[primary_key], 'list': list_name, 'message': 'value is different than expected for key: {}. Current: {}. Expected: {}.'.format(key, current[key], expected_value), })
                    if not self.test:
                        logging.error('ArcSight entry {} was not updated in list {}. {} is "{}" but should be "{}".'.format(expected[primary_key], list_name, key, current[key], expected_value))

        return errors

    def _mergeComma(self, values):
        """Merge values by comma

        Args:
            values (list/any): list of values to merge.

        Returns:
            str: Merged values or original value if not list was provided.

        """
        if isinstance(values, list):
            return ','.join(list(filter(None, values)))
        return values

    def _mergeSpace(self, values):
        """Merge values by space

        Args:
            values (list/any): list of values to merge.

        Returns:
            str: Merged values or original value if not list was provided.

        """
        if isinstance(values, list):
            return ' '.join(list(filter(None, values)))
        return values

    def _mergeDash(self, values):
        """Merge values by dash

        Args:
            values (list/any): list of values to merge.

        Returns:
            str: Merged values or original value if not list was provided.

        """

        if isinstance(values, list):
            return '-'.join(list(filter(None, values)))
        return values

    def _convertReturn(self, value):
        """Return the same value. This method is required to keep the code clean.

        Args:
            values (any): Value to return.

        Returns:
            any: Not modified value.

        """

        return value

    def _convertTimestampToEpoch(self, timestamps):
        """Convert timestamp to epoch timestamp

        Args:
            timestamps (list/str): List of timestamps or one timestamp in int.

        Returns:
            str: Merged with comma string with epoch format of given timestaps.

        """

        if isinstance(timestamps, list):
            return self._mergeComma([timestamp+'000' for timestamp in timestamps])
        return timestamps+'000'

    def _convertDateToEpoch(self, dates):
        """Convert dates to epoch timestamp

        Args:
            dates (list/str): Dates in format Y-m-d or list of dates

        Returns:
            str: Merged with comma string with epoch format of given dates.

        """

        if isinstance(dates, list):
            # convert all dates in list to epoch and merge with commas
            return self._mergeComma([str(int(time.mktime(time.strptime(str(date), '%Y-%m-%d'))))+'000' for date in dates])

        date = dates
        return str(int(time.mktime(time.strptime(str(date), '%Y-%m-%d'))))+'000'

    def _convertIpToClassC(self, ips):
        """Convert ip to class C with just first three octets

        Args:
            ips (list/str): Ip addess or list of ip addresses.

        Returns:
            str: First three octets of each ip merged with comma.

        """
        if isinstance(ips, list):
            return self._mergeComma([ip[ip.rfind('.')] for ip in ips])
        return ips[:ips.rfind('.')]

    def _find(self, value, list_id):
        """Find attributes in the current active list based on the value

        Args:
            value (str): Value to search for.
            list_id (int): Id of active list where the search is done.

        Returns:
            bool: True if found, false otherwise.

        """

        # Select active list primary key
        for active_list in self.maps:
            if active_list['id'] != list_id:
                continue
            primary_key = active_list['primary_key']
            break

        for entry in self.entries[list_id]:
            if entry[primary_key] == value:
                #return entry
                return True

        return False

    def _verifyMap(self, map_list):
        """Verify map file content correctness

        Args:
            map_list (dict): Map

        Returns:
            bool: True if map has all required fields. False otherwise.

        Todo:
            Code it. Right now it's doing nothing.

        """

        if map_list:
            return True
        return False

