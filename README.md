# footmark
python sdk for aliyun, and give ansible-module used first

## Package footmark
When you modify footmark, you need to package and distribute it. First, you need to edit footmark/__init__.py and set a new version to '__version__ '. Second execute command as follows:

    # build footmark package
    $ python setup.py sdist

    # make sure your enviroment has installed twine, if not, execute command:
    $ sudo pip install twine

    # distribute new footmark
    # upload your project
	$ twine upload dist/<your-footmark-package>
Finally, use the following command to update footmark:

    $ sudo pip install footmark --upgrade
