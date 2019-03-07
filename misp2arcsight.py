#!/usr/bin/python
"""Tool to integrate MISP with ArcSight ESM active lists.

MISP export to ArcSight
Author: Dawid Czarnecki

Todo:
    * Do parsing of dates rules parameters. For example 2y, 3M (etc).
    * Add functionality for expiried attributes. May be create predefined column in active list with expiration dates of each attribute and iterate through all at the end of the process.
    * Allow taking only part of piped attributes. For example if there is domain|ip take only domain. If there is filename|md5, filename|sha1, filename|sha256 take only hash.
    * Add functionality to add additional tags on the fly (may be similar to ArcSight._convertX methods).
    * Write ArcSight._verifyMap method.
    * Move misp[key] == value condition from map.yaml to rules. Condition placed over there is only temporary solution. map.yaml and rules are two places to set conditions which is redundant. It should be in one place.
    * Mark attributes which are on warninglist and will go to active list.
    * Write verification if org from priority list exist.
    * Write help with all available rules.
    * Write tests for edge cases:
        - Event without attribute.
        - Create in MISP event and attribute wich will be exported according to the rules. Export to ArcSight. Remove event from MISP. Run misp2arcsight. Check if attribute is still in active list. Should be removed.
        - The same test as above but add attribute which will not be sent to ArcSight and then shadow attribute which will be according to the rules.
        - Org A publish event with attr 8.8.8.8, it goes to ArcSight, then org B (with higher priority) adds shadow attribute with delete flag. Then author modifies event and it becomes unpublished. In the next export it will should be removed from ArcSight.
        - There are two attrs with the same value (different event) but different type (both exportable according to rules). We should threat them as related attributes.
        - Scenario: Day 1: An attribute exist in two MISP events (Org A event and Org B event) and those two are send to ArcSight. Day 2: Org A makes changes to the event, event becomes unpublished, attribute from that event is not removed from the ArcSight. Day 3: Org B removes attribute (or mark ids=no) and publish event. Attribute is removed from the ArcSight. If we switch day 2 and day 3 then attribute stays in ArcSight database.
        - Add atribute to MISP, export it to ArcSight, change value of exported attribute and export again.
        - Create the same attribute in two different events but in one event ids=0 and in the second ids=1.
        - Create attribute ids=1 and shadow ids=0 (as the same organisation).

Supported conditions:
    =       equals
    !=      not equals
    ~       contains
    !~      not contains
    []      is in list
    ![]     is not in list
    r       matches regular expression
    !r      doesnt match regular expression
    Field - [contains,doesn't contain, =, !=, if any of, if not any of, matches regex, doesnt match regex] - [bool, string, regex, list]

"""

import copy
from datetime import datetime
import logging
import re

try:
    import simplejson as json
except ImportError:
    import json

import time
import yaml

from pyasesm import ActiveLists

from classes.logger import Logger
from classes.configuration import Configuration
from classes.helper import Helper
from classes.misp import Misp
from classes.arcsight import ArcSight

LOGLEVEL='info'

if __name__ == '__main__':
    logger = Logger()
    logger.customize(LOGLEVEL)
    config = Configuration('Script synchronize MISP with ArcSight.')
    config.run_parser()
    #logger.customize(config.get('loglevel'))

    proxy = config.get('proxy')
    proxy = {'http': config.get('proxy'), 'https': config.get('proxy')}

    misp = Misp(config.get('misp-url'), config.get('misp-key'), not config.get('misp-no-verify-cert'))

    misp.loadRules(config.get('rules-file'))
    misp.downloadOrganisations()
    misp.loadPriorities(config.get('priorities-file'))

    if config.get('input'):
        misp.loadAttributes(config.get('input'))
    else:
        misp.downloadAttributes(config.get('timestamp'))
        if config.get('export'):
            misp.printAttributes()
            exit()

    misp.applyProposals()
    misp.filterAttributes()

    misp.combineIdenticalAttributes()

    if config.get('skip-unpublished'):
        misp.skipUnpublished()

    to_add = misp.getToAddAttributes()
    to_delete = misp.getToDeleteAttributes()
    
    if len(to_add) != 0 and len(to_delete) != 0:
        arcsight = ArcSight(config.get('arcsight-url'), config.get('arcsight-username'), config.get('arcsight-password'), config.get('arcsight-map'), proxies=proxy)

        if config.get('production'):
            arcsight.addEntries(to_add)
            arcsight.deleteEntries(to_delete)

            if arcsight.verifyChanges() is not False:
                logging.info('MISP to ArcSight export went successful. Expected result achieved.')
        else:
            arcsight.testDifferences(to_add, to_delete)
            logging.info('Test finished.')
    else:
        logging.info('Nothing to update in ArcSight.')
