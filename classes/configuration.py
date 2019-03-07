"""Quick configuration preparation."""
import argparse
import logging
import yaml

# from classes.logger import Logger

class Configuration:
    """Parse arguments and config files

    Prepare clean rules based on config export conditions.
    Prepare logging for the whole application.

    Example:
        config = Configuration('Save proxy details.')
        config.run_parser()
        proxy = config.get('proxy')

    Attributes:
        arguments (dict): Dictionary with available arguments and their properties.
        required (list): Required parameters
        description (str): Description of the application
        args (): User's provided parameters parsed by class ArgumentParser.

    Args:
        description (str): Description of the application.

    Todo:
        write check for required fields.

    """

    # You can pass arguments by command line parameters or entries in config file
    # The highest priorit have command line parameters, then config file arguments and at the end default values are taking into consideration
    # Bool default has to be always False!
    arguments = {
            'config-file': {
                'type': 'file-read',
                'default': 'configs/config.yaml',
                'help': 'YAML or JSON file with configuration',
            },
            'rules-file': {
                'type': 'file-read',
                'default': 'configs/rules.yaml',
                'help': 'YAML or JSON file with rules',
            },
            'priorities-file': {
                'type': 'file-read',
                'default': 'configs/priorities.yaml',
                'help': 'YAML or JSON file with priorities for merging proposals with attributes and identical attributes',
            },
            'misp-url': {
                'type': 'string',
                'default': 'https://localhost',
                'help': 'URL address to MISP',
                'required': True,
            },
            'misp-key': {
                'type': 'string',
                'help': 'MISP API key',
                'required': True,
            },
            'misp-no-verify-cert': {
                'type': 'bool',
                'default': False,
                'help': 'Flag enabling and disabling certificate verification',
            },
            'arcsight-url': {
               'type': 'string',
               'default': 'localhost',
               'help': 'ArcSight ESM url',
               'required': True,
            },
            'arcsight-username': {
               'type': 'string',
               'help': 'ArcSight ESM username with access to Active List',
               'required': True,
            },
            'arcsight-password': {
               'type': 'string',
               'help': 'ArcSight ESM password with access to Active List',
               'required': True,
            },
            'arcsight-map': {
               'type': 'file-read',
                'default': 'configs/map.yaml',
               'help': 'ArcSight ESM resource ids of Active List and full map of fields from MISP to ArcSight',
               'required': True,
            },
            'input': {
                'type': 'file-read',
                'default': None,
                'help': 'JSON file with input. If provided it will not connect to MISP but take the data from this file.',
            },
            'export': {
                'type': 'bool',
                'default': False,
                'help': 'Print enriched attributes in json.',
            },
            'log': {
                'type': 'file-write',
                'default': None,
                'help': 'Log filename. If not specified logging to stdout',
            },
            'loglevel': {
                'type': 'string',
                'default': 'DEBUG',
                'help': 'Level of logging messages: debug, info, warning, error, critical',
            },
            'timestamp': {
                'type': 'string',
                'default': '1d',
                'help': 'Time of the attribute last modification. For example: 1d or 12h or 30m or timestamp',
            },
            'proxy': {
                'type': 'string',
                'default': None,
                'help': 'Proxy url. Proxy only ArcSight traffic',
            },
            'production': {
                'type': 'bool',
                'default': False,
                'help': 'Make changes to ArcSight active list. By default it doesn\'t push changes to ArcSight',
            },
            'skip-unpublished': {
                'type': 'bool',
                'default': False,
                'help': 'Skip attributes from unpublished events. It overrides rules.yaml. Each attribute which event is unpublished will not be added, updated or removed from active list',
            },
    }
    required = ['misp-url', 'misp-key', 'arcsight-url', 'arcsight-username', 'arcsight-password']

    def __init__(self, description):
        self.description = description

    def get(self, name):
        """Get parameter passed by user

        Args:
            name (str): Name of a paramiter.

        Returns:
            str: Value of a parameter provided by a user.

        Raises:
            Exception: If the requested parameter is not defined.

        """

        if name in self.arguments:
            return self.arguments[name]['value']
        raise Exception('Requested wrong configuration name: {} which doesn\'t exist in Configuration class.'.format(name))

    def _prepare_parser(self):
        """Parse parameters provided by user"""

        parser = argparse.ArgumentParser(description=self.description)
        #parser.add_argument('--proposal-orgs', dest='table', nargs='+', help='Proposals/shadow attributes from those organisations will be threated as more important than original attribute')
        for argument, details in self.arguments.items():
            if details['type'] == 'file-read':
                parser.add_argument('--'+argument, type=argparse.FileType('r'), help=details['help'])
            elif details['type'] == 'file-write':
                parser.add_argument('--'+argument, type=argparse.FileType('w'), help=details['help'])
            elif details['type'] == 'string':
                parser.add_argument('--'+argument, help=details['help'])
            elif details['type'] == 'bool':
                parser.add_argument('--'+argument, action='store_true', help=details['help'])
            else:
                logging.error('New argument added to the source code which type is not supported: {}'.format(argument))
                exit()

        self.args = parser.parse_args()

    def _parse(self):
        """Parse config file and select valid value of the same parameters.
        If the same parameter was provided in config file and command line the one from command line has a priority.

        """

        if self.args.config_file is None:
            config_file = self.arguments['config-file']['default']
        else:
            config_file = self.args.config_file.name
        self.arguments['config-file']['value'] = config_file

        # Config file check
        if config_file[-5:] == '.yaml':
            config = yaml.load(open(config_file, 'r'))
        elif config_file[-5:] == '.json':
            config = json.load(open(config_file, 'r'))
        else:
            logging.error('Config file in wrong format: {} insted of {}'.format(config_file[-5:], ['yaml', 'json']))
            exit()
        
        # # Rules file check
        # if self.args.rules_file.name[-5:] == '.yaml':
        #     rules = yaml.load(self.args.rules_file)
        # elif self.args.rules_file.name[-5:] == '.json':
        #     rules = json.load(self.args.rules_file)
        # else:
        #     logging.error('Rules file in wrong format: {} insted of {}'.format(self.args.rules_file.name[-5:], ['yaml', 'json']))

        # # Priorities file check
        # if self.args.priorities_file.name[-5:] == '.yaml':
        #     priorities = yaml.load(self.args.priorities_file)
        # elif self.args.priorities_file.name[-5:] == '.json':
        #     priorities = json.load(self.args.priorities_file)
        # else:
        #     logging.error('Priorities file in wrong format: {} insted of {}'.format(self.args.priorities_file.name[-5:], ['yaml', 'json']))

        # self.arguments['rules-file']['value'] = self.args.rules_file.name
        # self.arguments['priorities-file']['value'] = self.args.priorities_file.name

        # Grabbing values from parameters and config files
        for argument, details in self.arguments.items():
            if argument in ('config-file'):
                continue
            # Bool need a special treatment because argparser makes it False by default
            # which indicate no config file check
            argument_argparse = argument.replace('-', '_')
            if details['type'] == 'bool' and argument_argparse in self.args and getattr(self.args, argument_argparse) is True:
                self.arguments[argument]['value'] = True
            elif 'file' in details['type'] and argument_argparse in self.args and getattr(self.args, argument_argparse) is not None:
                self.arguments[argument]['value'] = getattr(self.args, argument_argparse).name
            elif details['type'] != 'bool' and argument_argparse in self.args and getattr(self.args, argument_argparse) is not None:
                self.arguments[argument]['value'] = getattr(self.args, argument_argparse)
            elif argument in config:
                self.arguments[argument]['value'] = config[argument]
            else:
                self.arguments[argument]['value'] = self.arguments[argument].get('default', None)

            # Log what config parameters were set up
            if self.arguments[argument]['value'] is not None:
                logging.debug("Configuration loaded: {}: {}".format(argument, self.arguments[argument]['value']))

        for r in self.required:
            if self.get(r) is None:
                logging.error('You didn\'t provide \'{}\' field in the config'.format(r))
                exit()

    def run_parser(self):
        """Prepare and run parser"""
        
        self._prepare_parser()
        self._parse()
