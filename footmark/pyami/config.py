#
import os
import re

# from footmark.compat import expanduser, ConfigParser, NoOptionError, NoSectionError, StringIO
from ConfigParser import SafeConfigParser as ConfigParser

try:
    os.path.expanduser('~')
    expanduser = os.path.expanduser
except (AttributeError, ImportError):
    # This is probably running on App Engine.
    expanduser = (lambda x: x)
try:
    import simplejson as json
except ImportError:
    import json

# By default we use two locations for the footmark configurations,
# /etc/footmark.cfg and ~/.footmark (which works on Windows and Unix).
FootmarkConfigPath = '/etc/footmark.cfg'
FootmarkConfigLocations = [FootmarkConfigPath]
UserConfigPath = os.path.join(expanduser('~'), '.footmark')
FootmarkConfigLocations.append(UserConfigPath)

# If there's a FOOTMARK_CONFIG variable set, we load ONLY
# that variable
if 'FOOTMARK_CONFIG' in os.environ:
    FootmarkConfigLocations = [expanduser(os.environ['FOOTMARK_CONFIG'])]

# If there's a FOOTMARK_PATH variable set, we use anything there
# as the current configuration locations, split with os.pathsep.
elif 'FOOTMARK_PATH' in os.environ:
    FootmarkConfigLocations = []
    for path in os.environ['FOOTMARK_PATH'].split(os.pathsep):
        FootmarkConfigLocations.append(expanduser(path))


class Config(object):
    def __init__(self, path=None, fp=None, do_load=True):
        self._parser = ConfigParser({'working_dir': '/mnt/pyami',
                                     'debug': '0'})
        if do_load:
            if path:
                self.load_from_path(path)
            elif fp:
                self.readfp(fp)
            else:
                self.read(FootmarkConfigLocations)

    def __setstate__(self, state):
        # There's test that verify that (transitively) a Config
        # object can be pickled.  Now that we're storing a _parser
        # attribute and relying on __getattr__ to proxy requests,
        # we need to implement setstate to ensure we don't get
        # into recursive loops when looking up _parser when
        # this object is unpickled.
        self._parser = state['_parser']

    def __getattr__(self, name):
        return getattr(self._parser, name)

    def has_option(self, *args, **kwargs):
        return self._parser.has_option(*args, **kwargs)

    def load_from_path(self, path):
        file = open(path)
        for line in file.readlines():
            match = re.match("^#import[\s\t]*([^\s^\t]*)[\s\t]*$", line)
            if match:
                extended_file = match.group(1)
                (dir, file) = os.path.split(path)
                self.load_from_path(os.path.join(dir, extended_file))
        self.read(path)

    def save_option(self, path, section, option, value):
        """
        Write the specified Section.Option to the config file specified by path.
        Replace any previous value.  If the path doesn't exist, create it.
        Also add the option the the in-memory config.
        """
        config = ConfigParser()
        config.read(path)
        if not config.has_section(section):
            config.add_section(section)
        config.set(section, option, value)
        fp = open(path, 'w')
        config.write(fp)
        fp.close()
        if not self.has_section(section):
            self.add_section(section)
        self.set(section, option, value)

    def save_user_option(self, section, option, value):
        self.save_option(UserConfigPath, section, option, value)

    def save_system_option(self, section, option, value):
        self.save_option(FootmarkConfigPath, section, option, value)

    def getbool(self, section, name, default=False):
        if self.has_option(section, name):
            val = self.get(section, name)
            if val.lower() == 'true':
                val = True
            else:
                val = False
        else:
            val = default
        return val

    def setbool(self, section, name, value):
        if value:
            self.set(section, name, 'true')
        else:
            self.set(section, name, 'false')
