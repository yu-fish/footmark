# encoding: utf-8
"""
Represents a connection to the OSS service.
"""


from footmark.connection import ACSQueryConnection
import oss2
from footmark.exception import OSSResponseError


class OSSConnection(ACSQueryConnection):
    DefaultRegionId = 'cn-hangzhou'
    DefaultRegionName = u'杭州'.encode("UTF-8")
    DefaultConnectionErrorMsg = "Error in connecting to OSS. This usually occurs due to invalid region"
    ResponseError = OSSResponseError

    def __init__(self, acs_access_key_id=None, acs_secret_access_key=None,
                 region=None):
        """
        Init method to create a new connection to OSS.
        """
        if not region:
            region = self.DefaultRegionId

        self.region = region

        self.endpoint = "http://oss-" + self.region + ".aliyuncs.com"

        self.auth = oss2.Auth(acs_access_key_id, acs_secret_access_key)

        '''super(OSSConnection, self).__init__(acs_access_key_id=acs_access_key_id,
                                            acs_secret_access_key=acs_secret_access_key,
                                            region=self.region)'''

    def error_handler(self, exception):
        """

        :param exception:
        :return:
        """

        details = self.DefaultConnectionErrorMsg
        class_name = exception.__class__.__name__

        if hasattr(exception, 'details'):
            if exception.details:
                e_details = exception.details
                details = '{'
                for key in e_details:
                    details += str(key) + ": " + str(e_details[key]) + ', '

                details += '}'

        return details
