# encoding: utf-8
"""
Represents a connection to the ECS service.
"""

import warnings

from footmark.exception import FootmarkClientError
from footmark.connection import ACSQueryConnection
from footmark.ecs.instance import Instance
from footmark.ecs.regioninfo import RegionInfo
from footmark.exception import ECSResponseError
import six

class ECSConnection(ACSQueryConnection):


    # SDKVersion = footmark.config.get('Footmark', 'ecs_version', '2014-05-26')
    SDKVersion = '2014-05-26'
    DefaultRegionId = 'cn-hangzhou'
    DefaultRegionName = u'杭州'.encode("UTF-8")
    ResponseError = ECSResponseError

    def __init__(self, acs_access_key_id=None, acs_secret_access_key=None,
                 region=None, sdk_version= None, security_token=None,):
        """
        Init method to create a new connection to ECS.
        """
        if not region:
            region = RegionInfo(self, self.DefaultRegionName,
                                self.DefaultRegionId)
        self.region = region
        if sdk_version:
            self.SDKVersion = sdk_version

        self.ECSSDK = 'aliyunsdkecs.request.v' + self.SDKVersion.replace('-','')

        super(ECSConnection, self).__init__(acs_access_key_id,
                                            acs_secret_access_key,
                                            self.region, self.ECSSDK, security_token)

    # def build_filter_params(self, params, filters):
    #     if not isinstance(filters, dict):
    #         filters = dict(filters)
    #
    #     i = 1
    #     for name in filters:
    #         acs_name = name
    #         if acs_name.startswith('tag:'):
    #             params['set_Tag%dKey' % i] = acs_name[4:]
    #             params['set_Tag%dValue' % i] = filters[acs_name]
    #             i += 1
    #             continue
    #         acs_name = ''.join(s.capitalize() for s in acs_name.split('_'))
    #         params['set_' + acs_name] = filters[name]

    def build_filter_params(self, params, filters):
        if not isinstance(filters, dict):
            return

        i = 1
        for key,value in filters.items():
            acs_key = key
            if acs_key.startswith('tag:'):
                while(('set_Tag%dKey' % i) in params ):
                    i += 1
                if i<6:
                    params['set_Tag%dKey' % i] = acs_key[4:]
                    params['set_Tag%dValue' % i] = filters[acs_key]
                i += 1
                continue
            if key == 'group_id':
                if not value.startswith('sg-') or len(value) != 12:
                    warnings.warn(
                        "The group-id filter now requires a security group "
                        "identifier (sg-*) instead of a security group ID. "
                        "The group-id " + value + "may be invalid.",
                        UserWarning)
                params['set_SecurityGroupId'] = value
                continue
            if not isinstance(value, dict):
                acs_key = ''.join(s.capitalize() for s in acs_key.split('_'))
                params['set_' + acs_key] = value
                continue

            self.build_filters_params(params, value)

    # Instance methods

    def get_all_instances(self, instance_ids=None, filters=None, max_results=None):
        """
        Retrieve all the instance associated with your account.

        :rtype: list
        :return: A list of  :class:`footmark.ecs.instance.Reservation`

        """
        warnings.warn(('The current get_all_instances implementation will be '
                       'replaced with get_all_reservations.'),
                      PendingDeprecationWarning)

        params = {}
        if instance_ids:
            self.build_list_params(params, instance_ids, 'InstanceIds')
        if filters:
            self.build_filter_params(params, filters)
        if max_results is not None:
            params['MaxResults'] = max_results
        return self.get_list('DescribeInstances', params, ['Instances', Instance])

    def start_instances(self, instance_ids=None):
        """
        Start the instances specified

        :type instance_ids: list
        :param instance_ids: A list of strings of the Instance IDs to start

        :rtype: list
        :return: A list of the instances started
        """
        params = {}
        results = []
        if instance_ids:
            if isinstance(instance_ids, six.string_types):
                instance_ids = [instance_ids]
            for instance_id in instance_ids:
                self.build_list_params(params, instance_id, 'InstanceId')
                if self.get_status('StartInstance', params):
                    results.append(instance_id)
        return results

    def stop_instances(self, instance_ids=None, force=False):
        """
        Stop the instances specified

        :type instance_ids: list
        :param instance_ids: A list of strings of the Instance IDs to stop

        :type force: bool
        :param force: Forces the instance to stop

        :rtype: list
        :return: A list of the instances stopped
        """
        params = {}
        results = []
        if force:
            self.build_list_params(params, 'true', 'ForceStop')
        if instance_ids:
            if isinstance(instance_ids, six.string_types):
                instance_ids = [instance_ids]
            for instance_id in instance_ids:
                self.build_list_params(params, instance_id, 'InstanceId')
                if self.get_status('StopInstance', params):
                    results.append(instance_id)
        return results

    def reboot_instances(self, instance_ids=None, force=False):
        """
        Reboot the specified instances.

        :type instance_ids: list
        :param instance_ids: The instances to terminate and reboot

        :type force: bool
        :param force: Forces the instance to stop

        """
        params = {}
        results = []
        if force:
            self.build_list_params(params, 'true', 'ForceStop')
        if instance_ids:
            if isinstance(instance_ids, six.string_types):
                instance_ids = [instance_ids]
            for instance_id in instance_ids:
                self.build_list_params(params, instance_id, 'InstanceId')
                if self.get_status('RebootInstance', params):
                    results.append(instance_id)

        return results

    def run_instances(self, **kwargs):
        """

        :rtype: Instance
        :return: The :class:`footmark.ecs.instance` associated with
                 the request for machines
        """
        params = {}
        if len(kwargs)>0:
            self.build_filter_params(params, kwargs)
        instance_ids = []
        try:
            count = kwargs.get('count', None)
            if count:
                count = int(count)
            else:
                count = 1
        except FootmarkClientError as e:
            e.reason('count %s is not valid int' % kwargs['count'])
        for i in range(0, count):
            instance_ids.append(self.get_object('CreateInstance', params, 'InstanceId'))

        return self.get_all_instances(instance_ids=instance_ids)

    def terminate_instances(self, instance_ids=None, force=False):
        """
        Terminate the instances specified

        :type instance_ids: list
        :param instance_ids: A list of strings of the Instance IDs to terminate

        :type force: bool
        :param force: Forces the instance to stop

        :rtype: list
        :return: A list of the instance_ids terminated
        """
        params = {}
        result = []
        if force:
            self.build_list_params(params, 'true', 'ForceStop')
        if instance_ids:
            self.build_list_params(params, instance_ids, 'InstanceId')
        if instance_ids:
            if isinstance(instance_ids, six.string_types):
                instance_ids = [instance_ids]
            for instance_id in instance_ids:
                self.build_list_params(params, instance_id, 'InstanceId')
                if self.get_status('DeleteInstance', params):
                    result.append(instance_id)
        return result