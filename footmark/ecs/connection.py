# encoding: utf-8
"""
Represents a connection to the ECS service.
"""

import warnings

import six
import time
import json

from footmark.connection import ACSQueryConnection
from footmark.ecs.instance import Instance
from footmark.ecs.regioninfo import RegionInfo
from footmark.ecs.securitygroup import SecurityGroup
from footmark.ecs.volume import Disk
from footmark.exception import ECSResponseError


class ECSConnection(ACSQueryConnection):
    # SDKVersion = footmark.config.get('Footmark', 'ecs_version', '2014-05-26')
    SDKVersion = '2014-05-26'
    DefaultRegionId = 'cn-hangzhou'
    DefaultRegionName = u'杭州'.encode("UTF-8")
    ResponseError = ECSResponseError

    def __init__(self, acs_access_key_id=None, acs_secret_access_key=None,
                 region=None, sdk_version=None, security_token=None, ):
        """
        Init method to create a new connection to ECS.
        """
        if not region:
            region = RegionInfo(self, self.DefaultRegionName,
                                self.DefaultRegionId)
        self.region = region
        if sdk_version:
            self.SDKVersion = sdk_version

        self.ECSSDK = 'aliyunsdkecs.request.v' + self.SDKVersion.replace('-', '')

        super(ECSConnection, self).__init__(acs_access_key_id,
                                            acs_secret_access_key,
                                            self.region, self.ECSSDK, security_token)

    def build_filter_params(self, params, filters):
        if not isinstance(filters, dict):
            return

        flag = 1
        for key, value in filters.items():
            acs_key = key
            if acs_key.startswith('tag:'):
                while (('set_Tag%dKey' % flag) in params):
                    flag += 1
                if flag < 6:
                    params['set_Tag%dKey' % flag] = acs_key[4:]
                    params['set_Tag%dValue' % flag] = filters[acs_key]
                flag += 1
                continue
            if key == 'group_id':
                if not value.startswith('sg-') or len(value) != 12:
                    warnings.warn("The group-id filter now requires a security group "
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
        :return: A list of  :class:`footmark.ecs.instance`

        """
        warnings.warn(('The current get_all_instances implementation will be '
                       'replaced with get_all_instances.'),
                      PendingDeprecationWarning)

        params = {}
        if instance_ids:
            self.build_list_params(params, instance_ids, 'InstanceIds')
        if filters:
            self.build_filter_params(params, filters)
        if max_results is not None:
            params['MaxResults'] = max_results
        instances = self.get_list('DescribeInstances', params, ['Instances', Instance])
        for inst in instances:
            filters = {}
            filters['instance_id'] = inst.id
            volumes = self.get_all_volumes(filters=filters)
            block_device_mapping = {}
            for vol in volumes:
                block_device_mapping[vol.id] = vol
            setattr(inst, 'block_device_mapping', block_device_mapping)
            filters = {}
            filters['security_group_id'] = inst.security_group_id
            security_groups = self.get_all_security_groups(filters=filters)
            setattr(inst, 'security_groups', security_groups)

        return instances

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
            self.build_list_params(params, 'true', 'Force')
        if instance_ids:
            if isinstance(instance_ids, six.string_types):
                instance_ids = [instance_ids]
            for instance_id in instance_ids:
                self.build_list_params(params, instance_id, 'InstanceId')
                if self.get_status('DeleteInstance', params):
                    result.append(instance_id)
        return result

    def get_all_volumes(self, volume_ids=None, filters=None):
        """
        Get all Volumes associated with the current credentials.

        :type volume_ids: list
        :param volume_ids: Optional list of volume ids.  If this list
                           is present, only the volumes associated with
                           these volume ids will be returned.

        :type filters: dict
        :param filters: Optional filters that can be used to limit
                        the results returned.  Filters are provided
                        in the form of a dictionary consisting of
                        filter names as the key and filter values
                        as the value.  The set of allowable filter
                        names/values is dependent on the request
                        being performed.  Check the ECS API guide
                        for details.

        :type dry_run: bool
        :param dry_run: Set to True if the operation should not actually run.

        :rtype: list of :class:`boto.ec2.volume.Volume`
        :return: The requested Volume objects
        """
        params = {}
        if volume_ids:
            self.build_list_params(params, volume_ids, 'DiskIds')
        if filters:
            self.build_filter_params(params, filters)
        return self.get_list('DescribeDisks', params, ['Disks', Disk])         
   
    def get_security_status(self, vpc_id=None, group_id=None):
        """
        Querying Security Group List returns the basic information about all
              user-defined security groups.

        :type  vpc_id: dict
        :param vpc_id: ID of a vpc to which an security group belongs. If it is
            null, a vpc is selected by the system

        :type group_id: dict
        :param group_id: Provides a list of security groups ids.

        :return: A list of the total number of security groups,
                 the ID of the VPC to which the security group belongs

                """

        params = {}
        results = []
        changed = False 

        if vpc_id:
            self.build_list_params(params, vpc_id, 'VpcId')
        if group_id:
            self.build_list_params(params, group_id, 'SecurityGroupIds')        

        try:
            results = self.get_status('DescribeSecurityGroups', params)
            changed = True
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results        
         
    def get_all_security_groups(self, group_ids=None, filters=None):
        """
        Get all security groups associated with your account in a region.

        :type group_ids: list
        :param group_ids: A list of IDs of security groups to retrieve for
                          security groups within a VPC.

        :type filters: dict
        :param filters: Optional filters that can be used to limit
                        the results returned.  Filters are provided
                        in the form of a dictionary consisting of
                        filter names as the key and filter values
                        as the value.  The set of allowable filter
                        names/values is dependent on the request
                        being performed.  Check the EC2 API guide
                        for details.

        :rtype: list
        :return: A list of :class:`boto.ec2.securitygroup.SecurityGroup`
        """
        params = {}
        if group_ids:
            self.build_list_params(params, group_ids, 'SecurityGroupId')
        if filters:
            self.build_filter_params(params, filters)
        return self.get_list('DescribeSecurityGroups', params, ['SecurityGroups', SecurityGroup])

    def create_security_group(self, group_name=None, group_description=None, group_tags=None, vpc_id=None,
                              inbound_rules=None,outbound_rules=None):
        """
        create and authorize security group in ecs

        :type group_name: string
        :param group_name: Name of the security group

        :type group_description: string
        :param group_description: Description of the security group

        :type group_tags: list
        :param group_tags: A list of hash/dictionaries of disk
            tags, '[{tag_key:"value", tag_value:"value"}]', tag_key
            must be not null when tag_value isn't null

        :type vpc_id: string
        :param vpc_id: The ID of the VPC to which the security group belongs

        :type inbound_rules: list
        :param inbound_rules: Inbound rules for authorization

        :type outbound_rules: list
        :param outbound_rules: Outbound rules for authorization

        :rtype: dict
        :return: Returns a dictionary of group information about
            the the group created/authorized. If the group was not
            created and authorized, "changed" will be set to False.
        """

        params = {}
        results = []
        changed = False
        security_group_id = None

        # Security Group Name
        self.build_list_params(params, group_name, 'SecurityGroupName')

        # Security Group VPC Id
        if vpc_id:
            self.build_list_params(params, vpc_id, 'VpcId')

        # Security Group Description
        self.build_list_params(params, group_description, 'Description')

        # Instance Tags
        tagno = 1
        if group_tags:
            for group_tag in group_tags:
                if group_tag:
                    if 'tag_key' in group_tag:
                        self.build_list_params(params, group_tag[
                            'tag_key'], 'Tag' + str(tagno) + 'Key')
                    if 'tag_value' in group_tag:
                        self.build_list_params(params, group_tag[
                            'tag_value'], 'Tag' + str(tagno) + 'Value')
                    tagno = tagno + 1

        # Client Token


        # CreateSecurityGroup method call, returns newly created security group id
        try:
            response = self.get_status('CreateSecurityGroup', params)
            security_group_id = response['SecurityGroupId']
            results.append("Security Group Creation Successful")
            changed = True
        except Exception as ex:
            error_code = ex.error_code
            msg = ex.message
            results.append("Following error occurred while creating Security Group")
            results.append("error Code: " + error_code)
            results.append("Message: " + msg)
        else:
            if inbound_rules or outbound_rules:
                c, msg = self.authorize_security_group(security_group_id, inbound_rules=inbound_rules,
                                                    outbound_rules=outbound_rules)
                results.extend(msg)

        return changed, security_group_id, results
           
    def authorize_security_group(self, security_group_id=None, inbound_rules=None, outbound_rules=None):
        """
            authorize security group in ecs

            :type security_group_id: string
            :param group_name: The ID of the target security group

            :type rules: list
            :param rules: rules for authorization

            :type rule_type: string
            :param rule_type: Rule type like 'inbound' or 'outbound'

            :rtype: list
           :return: Returns the successful message if all rules successfully authorized else returns details of failed authorization rules.

           Note: Use validate_sg_rules(rules) method for pre-defined basic validation before using this method.
        """
        rule_types = []
        rule_choice = {
              "inbound": inbound_rules,
              "outbound": outbound_rules,
            }

        changed = False

        tcp_proto_start_port = 1
        tcp_proto_end_port = 65535

        if inbound_rules:
            rule_types.append('inbound')

        if outbound_rules:
            rule_types.append('outbound')

        result_details = []

        for rule_type in rule_types:

            rules = rule_choice.get(rule_type)
            total_rules = len(rules)
            success_rule_count = 0

            if total_rules != 0:

                for rule in rules:

                    params = {}

                    self.build_list_params(params, security_group_id, 'SecurityGroupId')

                    if 'proto' in rule:
                        ip_prototype = rule['proto']
                        from_port = 0
                        to_port = 0
                        port_range = None
                        self.build_list_params(params, ip_prototype, 'IpProtocol')

                        if ip_prototype in ("tcp", "udp"):

                            if 'from_port' in rule:
                                from_port = rule['from_port']
                            else:
                                from_port = tcp_proto_start_port

                            if 'to_port' in rule:
                                to_port = rule['to_port']
                            else:
                                to_port = tcp_proto_end_port


                        elif ip_prototype in ('icmp', 'gre', 'all'):
                            from_port = "-1"
                            to_port = "-1"

                        port_range = str(from_port) + "/" + str(to_port)


                        self.build_list_params(params, port_range, 'PortRange')

                        if 'group_id' in rule:
                            if "inbound" in rule_type:
                                self.build_list_params(params, rule['group_id'], 'SourceGroupId')
                            elif "outbound" in rule_type:
                                self.build_list_params(params, rule['group_id'], 'DestGroupId')

                        if 'cidr_ip' in rule:
                            if "inbound" in rule_type:
                                self.build_list_params(params, rule['cidr_ip'], 'SourceCidrIp')
                            elif "outbound" in rule_type:
                                self.build_list_params(params, rule['cidr_ip'], 'DestCidrIp')

                        if 'policy' in rule:
                            self.build_list_params(params, rule['policy'], 'Policy')
                        if 'priority' in rule:
                            self.build_list_params(params, rule['priority'], 'Priority')
                        if 'nic_type' in rule:
                            self.build_list_params(params, rule['nic_type'], 'NicType')

                        try:
                            if "inbound" in rule_type:
                                self.get_status("AuthorizeSecurityGroup", params)
                                success_rule_count += 1
                                changed = True

                            elif "outbound" in rule_type:
                                self.get_status("AuthorizeSecurityGroupEgress", params)
                                success_rule_count += 1
                                changed = True

                        except Exception as ex:
                            error_code = ex.error_code
                            msg = ex.message
                            result_details.append(rule_type + ' rule authorization failed for protocol ' + rule[
                                'proto'] + ' with port range ' + port_range)
                            result_details.append("error Code: " + error_code)
                            result_details.append("Message: " + msg)

                if success_rule_count == total_rules:
                    result_details.append(rule_type + ' rule authorization successful for group id ' + security_group_id)

        return changed, result_details

    def delete_security_group(self, group_ids):
        """
        Delete Security Group , delete security group inside particular region.

        :type  group_ids: dict
        :param group_ids: The Security Group ID

        :rtype: string
        :return: A method return result of after successfully deletion of security group
        """
        # Call DescribeSecurityGroups method to get response for all running instances
        params = {}
        results = []
        changed = False
        for group_id in group_ids:
            if group_id:
                self.build_list_params(params, group_id, 'SecurityGroupId')
            try:
                response = self.get_status('DescribeSecurityGroups', params)
                if len(response) > 0:
                    json_obj = response
                    total_instance = json_obj['TotalCount']
                    if total_instance > 0:
                        for items in json_obj['SecurityGroups']['SecurityGroup']:
                            available_instance = items['AvailableInstanceAmount']
                            if available_instance == 1000:
                                response = self.get_status('DeleteSecurityGroup', params)
                                results.append(response)
                                changed = True
            except Exception as ex:
                error_code = ex.error_code
                error_msg = ex.message
                results.append("Error Code:" + error_code + " ,Error Message:" + error_msg)
        return changed, results 

    def create_instance(self, image_id, instance_type, group_id=None, zone_id=None, instance_name=None,
                        description=None, internet_data=None, host_name=None, password=None, io_optimized=None,
                        system_disk=None, disks=None, vswitch_id=None, private_ip=None, count=None,
                        allocate_public_ip=None, bind_eip=None, instance_charge_type=None, period=None, auto_renew=None,
                        auto_renew_period=None, instance_tags=None, ids=None, wait=None, wait_timeout=None):
        """
        create an instance in ecs

        :type image_id: string
        :param image_id: ID of an image file, indicating an image selected
            when an instance is started

        :type instance_type: string
        :param instance_type: Type of the instance

        :type group_id: string
        :param group_id: ID of the security group to which a newly created
            instance belongs

        :type zone_id: string
        :param zone_id: ID of a zone to which an instance belongs. If it is
            null, a zone is selected by the system

        :type instance_name: string
        :param instance_name: Display name of the instance, which is a string
            of 2 to 128 Chinese or English characters. It must begin with an
            uppercase/lowercase letter or a Chinese character and can contain
            numerals, “.”, “_“, or “-“.

        :type description: string
        :param description: Description of the instance, which is a string of
            2 to 256 characters.

        :type internet_data: list
        :param internet_data: It includes Internet charge type which can be
            PayByTraffic or PayByBandwidth, max_bandwidth_in and max_bandwidth_out

        :type host_name: string
        :param host_name: Host name of the ECS, which is a string of at least
            two characters. “hostname” cannot start or end with “.” or “-“.
            In addition, two or more consecutive “.” or “-“ symbols are not
            allowed.

        :type password: string
        :param password: Password to an instance is a string of 8 to 30
            characters

        :type io_optimized: string
        :param io_optimized: values are (1) none: none I/O Optimized
            (2) optimized: I/O Optimized

        :type system_disk: list
        :param system_disk: It includes disk_category, disk_size,
            disk_name and disk_description

        :type disks: list
        :param disks: It includes device_category, device_size,
            device_name, device_description, delete_on_termination
            and snapshot

        :type vswitch_id: string
        :param vswitch_id: When launching an instance in VPC, the
            virtual switch ID must be specified

        :type private_ip: string
        :param private_ip: Private IP address of the instance, which cannot be specified separately.

        :type count: integer
        :param count: Create No. of Instances

        :type allocate_public_ip: bool
        :param allocate_public_ip: Allocate Public IP Address to Instance

        :type bind_eip: string
        :param bind_eip: Bind Elastic IP Address

        :type instance_charge_type: string
        :param instance_charge_type: instance charge type

        :type: period: integer
        :param period: The time that you have bought the resource,
            in month. Only valid when InstanceChargeType is set as
            PrePaid. Value range: 1 to 12

        :type: auto_renew: bool
        :param auto_renew: Whether automatic renewal is supported.
            Only valid when InstanceChargeType is set PrePaid. Value
            range True: indicates to automatically renew
                  False，indicates not to automatically renew
            Default value: False.

        :type: auto_renew_period: int
        :param auto_renew_period: The period of each automatic renewal. Required when AutoRenew is True.
        The value must be the same as the period of the created instance.

        :type: ids: list
        :param ids: A list of identifier for this instance or set of
            instances, so that the module will be idempotent with
            respect to ECS instances.

        :type instance_tags: list
        :param instance_tags: A list of hash/dictionaries of instance
            tags, '[{tag_key:"value", tag_value:"value"}]', tag_key
            must be not null when tag_value isn't null

        :type wait: string
        :param wait: after execution of method whether it has to wait for some time interval

        :type wait_timeout: int
        :param wait_timeout: time interval of waiting

        :rtype: dict
        :return: Returns a dictionary of instance information about
            the instances started/stopped. If the instance was not
            able to change state, "changed" will be set to False.
            Note that if instance_ids and instance_tags are both non-
            empty, this method will process the intersection of the two

        """

        params = {}
        results = []
        changed = False

        # Datacenter Zone ID
        if zone_id:
            self.build_list_params(params, zone_id, 'ZoneId')

        # Operating System
        self.build_list_params(params, image_id, 'ImageId')

        # Instance Type
        self.build_list_params(params, instance_type, 'InstanceType')

        # Security Group
        if group_id:
            self.build_list_params(params, group_id, 'SecurityGroupId')

        # Instance Details
        if instance_name:
            self.build_list_params(params, instance_name, 'InstanceName')

        # Description of an instance
        if description:
            self.build_list_params(params, description, 'Description')

        # Internet Data
        if internet_data:
            if 'charge_type' in internet_data:
                self.build_list_params(params, internet_data[
                    'charge_type'], 'InternetChargeType')
            if 'max_bandwidth_in' in internet_data:
                self.build_list_params(params, internet_data[
                    'max_bandwidth_in'], 'InternetMaxBandwidthIn')
            if 'max_bandwidth_out' in internet_data:
                self.build_list_params(params, internet_data[
                    'max_bandwidth_out'], 'InternetMaxBandwidthOut')

        # Security Setup
        if host_name:
            self.build_list_params(params, host_name, 'HostName')

        # Password to an instance
        if password:
            self.build_list_params(params, password, 'Password')

        # input/output optimized
        if io_optimized is True:
            self.build_list_params(params, "optimized", 'IoOptimized')

        # Storage - Primary Disk
        if system_disk:
            if 'disk_category' in system_disk:
                self.build_list_params(params, system_disk[
                    'disk_category'], 'SystemDisk.Category')
            if 'disk_size' in system_disk:
                self.build_list_params(params, system_disk[
                    'disk_size'], 'SystemDisk.Size')
            if 'disk_name' in system_disk:
                self.build_list_params(params, system_disk[
                    'disk_name'], 'SystemDisk.DiskName')
            if 'disk_description' in system_disk:
                self.build_list_params(params, system_disk[
                    'disk_description'], 'SystemDisk.Description')

        # Disks Details
        disk_no = 1
        if disks:
            for disk in disks:
                if disk:
                    if 'disk_size' in disk:
                        self.build_list_params(params, disk['disk_size'], 'DataDisk' + str(disk_no) + 'Size')
                    if 'disk_category' in disk:
                        self.build_list_params(params, disk['disk_category'], 'DataDisk' + str(disk_no) + 'Category')
                    if 'snapshot_id' in disk:
                        self.build_list_params(params, disk['snapshot_id'], 'DataDisk' + str(disk_no) + 'SnapshotId')
                    if 'disk_name' in disk:
                        self.build_list_params(
                            params, disk['disk_name'], 'DataDisk' + str(disk_no) + 'DiskName')
                    if 'disk_description' in disk:
                        self.build_list_params(params, disk['disk_description'],
                                               'DataDisk' + str(disk_no) + 'Description')
                    if 'delete_on_termination' in disk:
                        self.build_list_params(params, disk['delete_on_termination'],
                                               'DataDisk' + str(disk_no) + 'DeleteWithInstance')
                    disk_no += 1

        # VPC Switch Id
        if vswitch_id:
            self.build_list_params(params, vswitch_id, 'VSwitchId')

        # Private Ip\P
        if private_ip:
            self.build_list_params(params, private_ip, 'PrivateIpAddress')

        if instance_charge_type:
            self.build_list_params(params, instance_charge_type, 'InstanceChargeType')

            # when charge type is PrePaid add Period and Auto Renew Parameters
            if instance_charge_type == 'PrePaid':

                # period of an Instance
                if period:
                    self.build_list_params(params, period, 'Period')

                    # auto renewal of instance
                    if auto_renew:
                        self.build_list_params(params, auto_renew, 'AutoRenew')
                        self.build_list_params(params, auto_renew_period, 'AutoRenewPeriod')

        # Instance Tags
        tag_no = 1
        if instance_tags:
            for instance_tag in instance_tags:
                if instance_tag:
                    if 'tag_key' and 'tag_value' in instance_tag:
                        if (instance_tag['tag_key'] is not None) and (instance_tag['tag_value'] is not None):
                            self.build_list_params(params, instance_tag[
                                'tag_key'], 'Tag' + str(tag_no) + 'Key')                       
                            self.build_list_params(params, instance_tag[
                                'tag_value'], 'Tag' + str(tag_no) + 'Value')
                            tag_no += 1

        # Client Token
        if ids:
            if len(ids) == count:
                self.build_list_params(params, ids, 'ClientToken')

        for i in range(count):
            # CreateInstance method call, returns newly created instanceId
            try:
                response = self.get_status('CreateInstance', params)
                instance_id = response['InstanceId']
                results.append({"instance_id": instance_id})
                changed = True

            except Exception as ex:
                error_code = ex.error_code
                error_msg = ex.message
                results.append({"Error Code": error_code, "Error Message": error_msg})
            else:
                try:
                    time.sleep(30)
                    # Start newly created Instance
                    self.start_instances(instance_id)
                    time.sleep(30)
                    instance_info = self.get_all_instances(instance_ids=[str(instance_id)])
                    if instance_info:
                        # wait until instance status becomes running
                        instance_status = "Stopped"
                        while instance_status == "Stopped":
                            instance_info = self.get_all_instances(instance_ids=[str(instance_id)])
                            if instance_info:
                                time.sleep(30)
                                if instance_info[0].status:
                                    if instance_info[0].status in ['running', 'Running']:
                                        instance_status = instance_info[0].status

                except Exception as ex:
                    error_code = ex.error_code
                    error_msg = ex.message
                    results.append({"Error Code": error_code, "Error Message": error_msg})
                else:
                    # Allocate Public IP Address
                    try:
                        if allocate_public_ip:
                            # allocate allocate public ip
                            allocate_public_ip_params = {}
                            self.build_list_params(allocate_public_ip_params, instance_id, 'InstanceId')
                            public_ip_address_status = self.get_status('AllocatePublicIpAddress',
                                                                       allocate_public_ip_params)
                    except Exception as ex:
                        error_code = ex.error_code
                        error_msg = ex.message
                        results.append({"Error Code": error_code, "Error Message": error_msg})

                    # Allocate EIP Address
                    try:
                        if bind_eip:
                            allocate_eip_params = {}
                            self.build_list_params(
                                allocate_eip_params, bind_eip, 'AllocationId')
                            self.build_list_params(
                                allocate_eip_params, instance_id, 'InstanceId')
                            eip_address = self.get_status(
                                'AssociateEipAddress', allocate_eip_params)
                    except Exception as ex:
                        error_code = ex.error_code
                        error_msg = ex.message
                        results.append({"Error Code": error_code, "Error Message": error_msg})

        if wait in ['yes', True] and wait_timeout:
            time.sleep(wait_timeout)

        return changed, results

    def modify_instance(self, attributes=None):
        """
        modify the instance attributes such as name, description, password and host_name

        :type: list
        :param attributes: A list of dictionary of instance attributes which includes
            id, name, description, password and host_name
        :return: A list of the instance_ids modified
        """
        results = []
        changed = False
        
        if attributes:
            for attribute in attributes:
                if attribute:
                    params = {}
                    if 'id' in attribute:
                        self.build_list_params(params, attribute['id'], 'InstanceId')
                    if 'name' in attribute:
                        self.build_list_params(params, attribute['name'], 'InstanceName')
                    if 'description' in attribute:
                        self.build_list_params(params, attribute['description'], 'Description')
                    if 'password' in attribute:
                        self.build_list_params(params, attribute['password'], 'Password')
                    if 'host_name' in attribute:
                        self.build_list_params(params, attribute['host_name'], 'HostName')
                    

                    try:
                        result = self.get_status('ModifyInstanceAttribute', params)
                        results.append(result)
                        changed = True
                    except Exception as ex:
                        error_code = ex.error_code
                        error_msg = ex.message
                        results.append({"Error Code": error_code, "Error Message": error_msg})
        return changed, results

    def get_instance_status(self, zone_id=None, pagenumber=None, pagesize=None):
        """
        Get status of instance

        :type zone_id: string
        :param zone_id: Optional parameter. ID of the zone to which an instance belongs

        :type pagenumber: integer
        :param pagenumber: Page number of the instance status list. The start value is 1. The default value is 1

        :type pagesize: integer
        :param pagesize: Sets the number of lines per page for queries per page. The maximum value is 50.
        The default value is 10

        :rtype: json
        :return: The result of passed instances
        """

        params = {}
        results = []
        changed = False

        if zone_id:
            self.build_list_params(params, zone_id, 'ZoneId')
        if pagenumber:
            self.build_list_params(params, pagenumber, 'PageNumber')
        if pagesize:
            self.build_list_params(params, pagesize, 'PageSize')

        try:
            results = self.get_status('DescribeInstanceStatus', params)
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results

    def join_security_group(self, instance_ids, group_id):
        """
        Assign an existing instance to a pre existing security group

        :type instance_ids: List
        :param instance_ids: The list of instance id's which are to be assigned to the security group

        :type group_id: dict
        :param group_id: ID of the security group to which a instance is to be added

        :return: Success message, confirming joining security group or error message if any
        """
        params = {}
        results = []
        changed = False
        status = False

        
        if not isinstance(instance_ids,list):
            changed = False
            results.append("Error Code: " + "Invalid DataType")
            results.append("Error Message: " + "instance_ids must be of type list")
            return changed, results

        instance_count = len(instance_ids)
        json_obj = ''
        flag_fail = 0
        pass_cnt = 0

        success_instance_ids=[]
        failed_instance_ids=[]

        for counter in range(0, instance_count):
            id_of_instance = instance_ids[counter]

            # Instance Id, which is to be added to a security group
            self.build_list_params(params, id_of_instance, 'InstanceId')

            # Security Group ID, an already existing security group, to which instance is added
            self.build_list_params(params, group_id, 'SecurityGroupId')

            # Method Call, to perform adding action
            try:
                obtained_result = self.get_status('JoinSecurityGroup', params)
                results.append("Successfully added instance '" + str(
                    id_of_instance) + "' to security group " + str(group_id))

                #Verifying whether operation got performed successfully
                #3 attempts are used considering slow performance from server
                attempts = 0
                for i in range(0,10):
                    if status == False and attempts < 10:
                        status = self.verify_join_remove_securitygrp(id_of_instance, group_id, 'join')
                        if status == True:
                            pass_cnt = pass_cnt + 1
                            break;
                    attempts += 1  
                success_instance_ids.append(id_of_instance)
                    
            except Exception as ex:
                flag_fail = 1
                error_code = ex.error_code
                failed_instance_ids.append(id_of_instance)
                error_msg = "Join security group failed for instance: '" + str(
                    id_of_instance) + "' to security group " + str(
                    group_id)
                results.append(error_msg)
                results.append("Error Code: " + error_code)
                results.append("Error Message: " + ex.message)

        if flag_fail == 0 and pass_cnt > 0:
            changed = True
        elif flag_fail == 1 and pass_cnt > 0:
            changed = True
        elif flag_fail == 1 and pass_cnt == 0:
            changed = False 

        return changed, results, success_instance_ids, failed_instance_ids     

    def leave_security_group(self, instance_ids, group_id):
        """
        Remove an existing instance from given security group

        :type instance_ids: List
        :param instance_ids: The list of instance id's which are to be assigned to the security group

        :type group_id: dict
        :param group_id: ID of the security group to which a instance is to be added

        :return: Success message, confirming joining security group or error message if any
        """
        params = {}
        results = []
        flag_fail = 0
        pass_cnt = 0
        
        if not isinstance(instance_ids,list):
            changed = False
            results.append("Error Code: " + "Invalid DataType")
            results.append("Error Message: " + "instance_ids must be of type list")
            return changed, results

        instance_count = len(instance_ids)
        json_obj = ''
        changed = False
        status = False
        
        success_instance_ids=[]
        failed_instance_ids=[]

        for counter in range(0, instance_count):
            id_of_instance = instance_ids[counter]

            # Instance Id to be removed from a security group
            self.build_list_params(params, id_of_instance, 'InstanceId')

            # Security Group ID, an already existing security group, from which instance is removed
            self.build_list_params(params, group_id, 'SecurityGroupId')

            # Method Call, to perform adding action
            try:
                obtained_result = self.get_status('LeaveSecurityGroup', params)
                results.append("Successfully removed instance " + str(
                    id_of_instance) + " from security group " + str(group_id))

                #Verifying whether operation got performed successfully
                #3 attempts are used considering slow performance from server
                attempts = 0 
                for i in range(0,10):
                    if status == False and attempts < 10:
                        status = self.verify_join_remove_securitygrp(id_of_instance, group_id, 'remove')
                        if status == True:
                            pass_cnt = pass_cnt + 1
                            break;
                    attempts += 1  
                success_instance_ids.append(id_of_instance)

            except Exception as ex:
                flag_fail = 1
                error_code = ex.error_code
                failed_instance_ids.append(id_of_instance)
                error_msg = "Leave security group failed for instance: '" + str(
                    id_of_instance) + "' from security group " + str(
                    group_id)

                results.append(error_msg)
                results.append("Error Code" + error_code)
                results.append("Error Message" + ex.message)

        if flag_fail == 0 and pass_cnt > 0:
            changed = True
        elif flag_fail == 1 and pass_cnt > 0:
            changed = True
        elif flag_fail == 1 and pass_cnt == 0:
            changed = False

        return changed, results, success_instance_ids, failed_instance_ids

    def verify_join_remove_securitygrp(self, instance_id, group_id, mode):
        """
        To verify join & remove operations got performed in security group
        """
        time.sleep(5)
        done = False
        count = 0
        id_of_instance = [instance_id]
        try:

            instance_list = self.get_all_instances(id_of_instance, None, None)
            
            if len(instance_list) > 0:
                if mode.lower() == 'join':
                    for inst in instance_list:
                        if len(inst.security_group_ids['security_group_id']) > 0:
                            for grp in inst.security_group_ids['security_group_id']:
                                if grp == group_id:
                                    done = True

                elif mode.lower() == 'remove':
                    for inst in instance_list:
                        if len(inst.security_group_ids['security_group_id']) > 0:
                            for grp in inst.security_group_ids['security_group_id']:
                                if grp == group_id:
                                    count = count + 1
                            if count == 0:
                                done = True
        except Exception as ex:
            done = False

        return done            
    