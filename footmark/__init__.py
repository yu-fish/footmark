#
import datetime
import logging
import logging.config
import os

from footmark.pyami.config import Config, FootmarkConfigLocations

__version__ = '1.0.5'
Version = __version__  # for backware compatibility

datetime.datetime.strptime('', '')

config = Config()


def init_logging():
    for file in FootmarkConfigLocations:
        try:
            logging.config.fileConfig(os.path.expanduser(file))
        except:
            pass


class NullHandler(logging.Handler):
    def emit(self, record):
        pass


log = logging.getLogger('footmark')
perflog = logging.getLogger('footmark.perf')
log.addHandler(NullHandler())
perflog.addHandler(NullHandler())
init_logging()


# convenience function to set logging to a particular file

def set_file_logger(name, filepath, level=logging.INFO, format_string=None):
    global log
    if not format_string:
        format_string = "%(asctime)s %(name)s [%(levelname)s]:%(message)s"
    logger = logging.getLogger(name)
    logger.setLevel(level)
    fh = logging.FileHandler(filepath)
    fh.setLevel(level)
    formatter = logging.Formatter(format_string)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    log = logger


def set_stream_logger(name, level=logging.DEBUG, format_string=None):
    global log
    if not format_string:
        format_string = "%(asctime)s %(name)s [%(levelname)s]:%(message)s"
    logger = logging.getLogger(name)
    logger.setLevel(level)
    fh = logging.StreamHandler()
    fh.setLevel(level)
    formatter = logging.Formatter(format_string)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    log = logger


def connect_ecs(acs_access_key_id=None, acs_secret_access_key=None, **kwargs):
    """
    :type acs_access_key_id: string
    :param acs_access_key_id: Your AWS Access Key ID

    :type acs_secret_access_key: string
    :param acs_secret_access_key: Your AWS Secret Access Key

    :rtype: :class:`footmark.ecs.connection.ECSConnection`
    :return: A connection to Amazon's ECS
    """
    from footmark.ecs.connection import ECSConnection
    return ECSConnection(acs_access_key_id, acs_secret_access_key, **kwargs)
