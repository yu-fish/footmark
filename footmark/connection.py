# coding:utf-8
import sys

reload(sys)
sys.setdefaultencoding("utf-8")
"""
Handles basic connections to ACS
"""

import footmark
import importlib
from footmark.exception import FootmarkServerError
from footmark.provider import Provider
import json

from aliyunsdkcore import client


class ACSAuthConnection(object):
    def __init__(self, acs_access_key_id=None,
                 acs_secret_access_key=None,
                 region=None,
                 provider='acs', security_token=None):
        """
        :keyword str acs_access_key_id: Your ACS Access Key ID (provided by
            Alicloud). If none is specified, the value in your
            ``ACS_ACCESS_KEY_ID`` environmental variable is used.
        :keyword str acs_secret_access_key: Your ACS Secret Access Key
            (provided by Alicloud). If none is specified, the value in your
            ``ACS_SECRET_ACCESS_KEY`` environmental variable is used.
        :keyword str security_token: The security token associated with
            temporary credentials issued by STS.  Optional unless using
            temporary credentials.  If none is specified, the environment
            variable ``ACS_SECURITY_TOKEN`` is used if defined.

        :keyword str region: The region ID.

        """
        self.region = region
        if isinstance(provider, Provider):
            # Allow overriding Provider
            self.provider = provider
        else:
            self._provider_type = provider
            self.provider = Provider(self._provider_type,
                                     acs_access_key_id,
                                     acs_secret_access_key,
                                     security_token)

    def acs_access_key_id(self):
        return self.provider.access_key

    acs_access_key_id = property(acs_access_key_id)
    access_key = acs_access_key_id

    def acs_secret_access_key(self):
        return self.provider.secret_key

    acs_secret_access_key = property(acs_secret_access_key)
    secret_key = acs_secret_access_key

    def region_id(self):
        return self.region


class ACSQueryConnection(ACSAuthConnection):
    ResponseError = FootmarkServerError

    def __init__(self, acs_access_key_id=None, acs_secret_access_key=None,
                 region=None, product=None, security_token=None, provider='acs'):
        super(ACSQueryConnection, self).__init__(
            acs_access_key_id,
            acs_secret_access_key,
            region=region,
            security_token=security_token,
            provider=provider)

        self.product = product

    def make_request(self, action, params=None):
        try:
            conn = client.AcsClient(self.acs_access_key_id, self.acs_secret_access_key, self.region)
            if not conn:
                footmark.log.error('%s %s' % ('Null AcsClient ', conn))
                raise self.FootmarkClientError('Null AcsClient ', conn)
            if action:
                module = importlib.import_module(self.product + '.' + action + 'Request')
                request = getattr(module, action + 'Request')()
                request.set_accept_format('json')
                if params and isinstance(params, dict):
                    for k, v in params.items():
                        if hasattr(request, k):
                            getattr(request, k)(v)
                        else:
                            request.add_query_param(k[4:], v)
            return conn.do_action_with_exception(request)
        except Exception as ex:
            return ex

    # This method facilitates unit test of oss methods
    def make_oss_request(self, api_method):
        return api_method()

    def build_list_params(self, params, items, label):
        params['set_%s' % label] = items

    def parse_response(self, markers, response, connection):
        results = []
        response = json.loads(response, encoding='UTF-8')
        if markers and markers[0] in response:
            for value in response[markers[0]].itervalues():
                if value is None or len(value) < 1:
                    return results
                for item in value:
                    element = markers[1](connection)
                    self.parse_dict(element, item)
                    results.append(element)
        return results

    def parse_dict(self, element, dict_data):
        if not isinstance(dict_data, dict):
            return

        for k, v in dict_data.items():
            if isinstance(v, dict):
                value = {}
                for kk, vv in v.items():
                    value[self.convert_name(kk)] = vv
                v = value
                self.parse_dict(element, v)
            setattr(element, self.convert_name(k), v)

    def convert_name(self, name):
        if name:
            new_name = ''
            for ch in name:
                if ch.isupper():
                    ch = '_' + ch.lower()
                new_name += ch
            if new_name.startswith('_'):
                new_name = new_name[1:]
            return new_name

    # generics

    def get_list(self, action, params, markers):
        response = self.make_request(action, params)
        if type(response) is str:
            return self.parse_response(markers, response, self)
        else:
            footmark.log.error('%s' % (response))
            raise self.ResponseError(response)
        

    def get_status(self, action, params):
        response = self.make_request(action, params)
        footmark.log.debug(response)
        if type(response) is str:
            footmark.log.info('error= %s' % (response))
            return json.loads(response)   
        else:
            footmark.log.error('%s' % (response))
            raise self.ResponseError(response)  
               

