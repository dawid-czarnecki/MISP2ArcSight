"""Logging configuration."""

import logging

class Logger:
    """Conduct logging to stdout, files and monitoring system.

    Example:
        import logging
        logger = Logger()
        logger.customize('DEBUG')

        logging.debug('Debug info')

    Attributes:
        loglevel (str): One of the available logging levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
        log (str): Filename logs

    Args:
        loglevel (str): One of the available logging levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
        log (str): Filename logs

    """
    
    def __init__(self, loglevel='WARNING', log=None):
        #loglevel = getattr(logging, loglevel.upper(), None)
        #if not isinstance(loglevel, int):
        #   raise ValueError('Invalid log level: {}'.format(loglevel))
        self.loglevel = loglevel.upper()
        self.log = log
        
        # ONLY FOR TESTS: Remove warnings
        if loglevel in ('DEBUG', 'WARNING'):
            import urllib3
            urllib3.disable_warnings()
        # ONLY FOR TESTS: Remove warnings

    def customize(self, loglevel=None):
        """Customize logging behaviors. Configures logging on stderr or to file.

        Args:
            loglevel (str): One of the available logging levels: DEBUG, INFO, WARNING, ERROR, CRITICAL

        """
        if loglevel is not None:
            self.loglevel = loglevel.upper()

        if self.log:
            logging.basicConfig(filename=self.log, level=self.loglevel, format='%(asctime)s:%(levelname)s:%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        else:
            self.color_logging()
            logging.basicConfig(level=self.loglevel, format='%(asctime)s:%(levelname)s:%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    def color_logging(self):
        """Add ASCII colors characters to prettify logging to stdout"""
        colors = {
            'gray': '\033[1;30m',
            'red': '\033[1;31m',
            'green': '\033[1;32m',
            'yellow': '\033[1;33m',
            'blue': '\033[1;34m',
            'magenta': '\033[1;35m',
            'cyan': '\033[1;36m',
            'white': '\033[1;37m',
            'crimson': '\033[1;38m',
        }
        hcolors = {
            'red': '\033[1;41m',
            'green': '\033[1;42m',
            'brown': '\033[1;43m',
            'blue': '\033[1;44m',
            'magenta': '\033[1;45m',
            'cyan': '\033[1;46m',
            'gray': '\033[1;47m',
            'crimson': '\033[1;48m'
        }
        end = '\033[1;m'
        levels = {
                'WARNING': 'cyan',
                'INFO': 'crimson',
                'DEBUG': 'yellow',
                'CRITICAL': 'RED',
                'ERROR': 'red',
        }
        for level, color in levels.items():
            if color.isupper():
                logging.addLevelName(getattr(logging, level), "{}{}{}".format(hcolors[color.lower()], level, end))
            else:
                logging.addLevelName(getattr(logging, level), "{}{}{}".format(colors[color], level, end))
