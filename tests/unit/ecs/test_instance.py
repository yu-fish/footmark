#!/usr/bin/env python
# import sys
# sys.path.append("../../..")
from footmark.ecs.connection import ECSConnection
from tests.unit import ACSMockServiceTestCase
import json

DESCRIBE_INSTANCE = '''
{
  "Instances": {
    "Instance": [
      {
        "CreationTime": "2016-06-20T21:37Z",
        "DeviceAvailable": true,
        "EipAddress": {},
        "ExpiredTime": "2016-10-22T16:00Z",
        "HostName": "xiaozhu_test",
        "ImageId": "centos6u5_64_40G_cloudinit_20160427.raw",
        "InnerIpAddress": {
          "IpAddress": [
            "10.170.106.80"
          ]
        },
        "InstanceChargeType": "PostPaid",
        "InstanceId": "i-94dehop6n",
        "InstanceNetworkType": "classic",
        "InstanceType": "ecs.s2.large",
        "InternetChargeType": "PayByTraffic",
        "InternetMaxBandwidthIn": -1,
        "InternetMaxBandwidthOut": 1,
        "IoOptimized": false,
        "OperationLocks": {
          "LockReason": []
        },
        "PublicIpAddress": {
          "IpAddress": [
            "120.25.13.106"
          ]
        },
        "RegionId": "cn-shenzhen",
        "SecurityGroupIds": {
          "SecurityGroupId": [
            "sg-94kd0cyg0"
          ]
        },
        "SerialNumber": "51d1353b-22bf-4567-a176-8b3e12e43135",
        "Status": "Running",
        "Tags":{
          "Tag":[
            {
              "TagValue":"1.20",
              "TagKey":"xz_test"
            },
            {
              "TagValue":"1.20",
              "TagKey":"xz_test_2"
            }
          ]
        },
        "VpcAttributes": {
          "PrivateIpAddress": {
            "IpAddress": []
          }
        },
        "ZoneId": "cn-shenzhen-a"
      }
    ]
  },
  "PageNumber": 1,
  "PageSize": 10,
  "RequestId": "14A07460-EBE7-47CA-9757-12CC4761D47A",
  "TotalCount": 1
}
'''

MANAGE_INSTANCE = '''
{
    "RequestId": "14A07460-EBE7-47CA-9757-12CC4761D47A",
}
'''
         
Create_Security_Group ='''
{
    "RequestId": "AF3991A3-5203-4F83-8FAD-FDC1253AF15D",
    "SecurityGroupId": "sg-2ze95f8a2ni6bb2wql3b"
}
'''

Authorize_Security_Group = '''
{
    "RequestId": "AF3991A3-5203-4F83-8FAD-FDC1253AF15D"
}
'''

DELETE_SECURITY_GROUP = '''
{
    "PageNumber":1,
    "TotalCount":1,
    "PageSize":10,
    "RequestId":"D8C42A44-7B92-40BC-9DAA-41B7EB733A6C",
    "RegionId":"us-west-1",
    "SecurityGroups":
    {
    "SecurityGroup":[
       {
         "CreationTime":"2016-12-15T06:48:05Z",
         "Tags":{"Tag":[]},
         "SecurityGroupId":"sg-rj9606ryhhy2c3t8ljtx",
         "Description":"",
         "SecurityGroupName":"est",
         "AvailableInstanceAmount":1000,
         "VpcId":""
         }]
    }
}
'''

CREATE_INSTANCE = '''
{
    "InstanceId":"i-2zeg0900kzwn7dpo7zrb",
    "RequestId":"9206E7A7-BFD5-457F-9173-91CF4525DE21"
}
'''

GET_SECURITY_STATUS = '''
{
    "PageNumber": 1,
    "PageSize": 10,
    "RegionId": "cn-beijing",
    "RequestId": "2076C42F-7E15-4F69-926F-C404E6A2F0DD",
    "SecurityGroups": {
    "SecurityGroup": [
                    {
                        "AvailableInstanceAmount": 1000,
                        "CreationTime": "2016-12-19T04:54:38Z",
                        "Description": "",
                        "SecurityGroupId": "sg-2zegbxmrjvoz4ypz3kku",
                        "SecurityGroupName": "",
                        "Tags": {
                            "Tag": []
                        },
                        "VpcId": ""
                    },
                    {
                        "AvailableInstanceAmount": 1000,
                        "CreationTime": "2016-12-19T04:52:34Z",
                        "Description": "",
                        "SecurityGroupId": "sg-2zeaikpg8zhl7j5rrfnt",
                        "SecurityGroupName": "",
                        "Tags": {
                            "Tag": []
                        },
                        "VpcId": ""
                    },
                    {
                        "AvailableInstanceAmount": 1000,
                        "CreationTime": "2016-12-01T12:01:28Z",
                        "Description": "Allow inboud traffic for control nodes",
                        "SecurityGroupId": "sg-2ze80xuiw0b85tzbv7x9",
                        "SecurityGroupName": "hi-control",
                        "Tags": {
                            "Tag": []
                        },
                        "VpcId": "vpc-2zegy4zyl0nv0w5i1ay6j"
                    },
                    {
                        "AvailableInstanceAmount": 996,
                        "CreationTime": "2014-12-18T05:30:20Z",
                        "Description": "System created security group.",
                        "SecurityGroupId": "sg-25y6ag32b",
                        "SecurityGroupName": "sg-25y6ag32b",
                        "Tags": {
                            "Tag": []
                        },
                        "VpcId": ""
                    }
                ]
            },
    "TotalCount": 4
}

'''

MODIFY_INSTANCE = '''
{
       
        "changed": true,
        "instance_ids": ["i-rj97hhf9ue16ewoged75"],
        "result": [
            {
                "RequestId": "855267EE-BC10-49BB-847A-2A564B63178C"
            }
        ]
}
'''

GET_INSTANCE = '''
{
    "PageNumber": 1,
    "InstanceStatuses":
         {"InstanceStatus": [
            {"Status": "Running", "InstanceId": "i-2zehcagr3vt06iyir7hc"},
            {"Status": "Running", "InstanceId": "i-2zedup3d5p01daky1622"},
            {"Status": "Stopped", "InstanceId": "i-2zei2zq55lx87st85x2j"},
            {"Status": "Running", "InstanceId": "i-2zeaoq67u62vmkbo71o7"},
            {"Status": "Running", "InstanceId": "i-2ze5wl5aeq8kbblmjsx1"}
         ]},
        "TotalCount": 9,
        "PageSize": 5,
        "RequestId": "5D464158-D291-4C69-AA9E-84839A669B9D"
}
'''

JOIN_GROUP = '''
{
    "RequestId": "AF3991A3-5203-4F83-8FAD-FDC1253AF15D"
}
'''

LEAVE_GROUP = '''
{
    "RequestId": "AF3991A3-5203-4F83-8FAD-FDC1253AF15D"
}
'''


class TestDescribeInstances(ACSMockServiceTestCase):
    connection_class = ECSConnection

    def default_body(self):
        return DESCRIBE_INSTANCE

    def test_instance_attribute(self):
        self.set_http_response(status_code=200, body=DESCRIBE_INSTANCE)
        filters = {}
        instance_ids = ["i-94dehop6n"]
        tag_key = 'xz_test'
        tag_value = '1.20'
        filters['tag:' + tag_key] = tag_value
        instances = self.service_connection.get_all_instances(instance_ids=instance_ids, filters=filters)
        self.assertEqual(len(instances), 1)
        instance = instances[0]
        self.assertEqual(instance.id, 'i-94dehop6n')
        print 'group_id:', instance.group_id
        self.assertEqual(instance.group_id, 'sg-94kd0cyg0')
        self.assertEqual(instance.public_ip, '120.25.13.106')
        self.assertEqual(instance.tags, {"xz_test": "1.20", "xz_test_2": "1.20"})
        self.assertFalse(instance.io_optimized)
        self.assertEqual(instance.status, 'running')
        self.assertEqual(instance.image_id, 'centos6u5_64_40G_cloudinit_20160427.raw')
        return instances

    def test_manage_instances(self):
        self.set_http_response(status_code=200, body=MANAGE_INSTANCE)
        instances = self.test_instance_attribute()
        for inst in instances:
            if inst.state == 'running':
                inst.stop()
            elif inst.state == 'stopped':
                inst.start()
            else:
                inst.reboot()


class TestManageInstances(ACSMockServiceTestCase):
    connection_class = ECSConnection
    instance_ids = ['i-94dehop6n', 'i-95dertop6m']

    def default_body(self):
        return MANAGE_INSTANCE

    def test_start_instance(self):
        self.set_http_response(status_code=200)
        result = self.service_connection.start_instances(instance_ids=self.instance_ids)
        self.assertEqual(len(result), len(self.instance_ids))
        self.assertIn(result[0], self.instance_ids)

    def test_stop_instance(self):
        self.set_http_response(status_code=200)
        result = self.service_connection.stop_instances(instance_ids=self.instance_ids, force=True)
        self.assertEqual(len(result), len(self.instance_ids))
        self.assertIn(result[0], self.instance_ids)

    def test_reboot_instance(self):
        self.set_http_response(status_code=200)
        result = self.service_connection.reboot_instances(instance_ids=self.instance_ids, force=True)
        self.assertEqual(len(result), len(self.instance_ids))
        self.assertIn(result[0], self.instance_ids)

    def test_terminate_instance(self):
        self.set_http_response(status_code=200)
        result = self.service_connection.terminate_instances(instance_ids=self.instance_ids, force=True)
        self.assertEqual(len(result), len(self.instance_ids))
        self.assertIn(result[0], self.instance_ids)


class TestCreateAuthorizeSecurityGroup(ACSMockServiceTestCase):
    connection_class = ECSConnection
    acs_access_key = 'LTAIYkF7vqzLz5Zz'
    acs_secret_access_key = 'jwibCDw18eD7SJHrGfasFcVGbjfdy5'
    region_id = "cn-beijing"

    group_tags = [
        {
            "tag_key": "create_test_1",
            "tag_value": "0.01"
        },
        {
            "tag_key": "create_test_2",
            "tag_value": "0.02"
        }
    ]
    inbound_rules = [
        {
            "proto": "all",
            "from_port": "-1",
            "to_port": "-1",
            "cidr_ip": "10.159.6.18/12",
        }
    ]

    outbound_rules = [
        {
            "proto": "tcp",
            "from_port": "2",
            "to_port": "100",
            "cidr_ip": "10.159.6.18/12",
        }
    ]

    def default_body(self):
        return Create_Security_Group

    def test_create_security_grp(self):
        self.set_http_response(status_code=200)
        changed, security_group_id, result = self.service_connection.create_security_group(group_name="Blue123",
                                                               group_description="TestDataforBlue",
                                                               group_tags=self.group_tags,
                                                               inbound_rules=self.inbound_rules,
                                                               outbound_rules=self.outbound_rules)

        self.assertEqual(security_group_id, u'sg-2ze95f8a2ni6bb2wql3b')
        rs = result[0]
        self.assertEqual(rs, u'Security Group Creation Successful')
        rs = result[1]
        self.assertEqual(rs, u'inbound rule authorization successful')
        rs = result[2]
        self.assertEqual(rs, u'outbound rule authorization successful')


class TestDeleteSecurityGroup(ACSMockServiceTestCase): 
    connection_class = ECSConnection
    acs_access_key = 'LTAIYkF7vqzLz5Zz'
    acs_secret_access_key = 'jwibCDw18eD7SJHrGfasFcVGbjfdy5'
    group_ids = [
                  'sg-rj9elk6bkehdlyxhm79f','sg-rj90ienb9kpbgqv6x4qe'
                 ]
    region = 'us-west-1'
    
    def default_body(self):
        return DELETE_SECURITY_GROUP
    
    def test_delete_security_grp(self):
        self.set_http_response(status_code=200)
        changed, result = self.service_connection.delete_security_group(group_ids=self.group_ids)
        self.assertEqual(result[0][u'RequestId'], "D8C42A44-7B92-40BC-9DAA-41B7EB733A6C")


class TestGetSecurityStatus(ACSMockServiceTestCase):
    connection_class = ECSConnection
   
    acs_access_key = 'N8cvD83K81USpn3u'
    acs_secret_access_key = 'fqbuZIKPxOdu36yhFvaBtihNqD2qQ2'
    region = 'cn-beijing'
    state = 'getinfo'

    def default_body(self):
        return GET_SECURITY_STATUS

    def test_get_security_status(self):
        self.set_http_response(status_code=200)
        changed, result = self.service_connection.get_security_status(vpc_id=None, group_id=None)
        
        self.assertEqual(result[u'RequestId'], "2076C42F-7E15-4F69-926F-C404E6A2F0DD")


class TestAuthorizeSecurityGroup(ACSMockServiceTestCase):
    connection_class = ECSConnection
    acs_access_key = 'LTAIYkF7vqzLz5Zz'
    acs_secret_access_key = 'jwibCDw18eD7SJHrGfasFcVGbjfdy5'
    region_id = "cn-beijing"
    security_group_id = 'sg-2ze95f8a2ni6bb2wql3b'


    inbound_rules = [
        {
            "proto": "all",
            "from_port": "-1",
            "to_port": "-1",
            "cidr_ip": "10.159.6.18/12",
        }
    ]

    outbound_rules = [
        {
            "proto": "tcp",
            "from_port": "2",
            "to_port": "100",
            "cidr_ip": "10.159.6.18/12",
        }
    ]

    def default_body(self):
        return Authorize_Security_Group

    def test_authorize_security_grp(self):
        self.set_http_response(status_code=200)
        result = self.service_connection.authorize_security_group(security_group_id = self.security_group_id, inbound_rules=self.inbound_rules,
                                                               outbound_rules=self.outbound_rules)
        rs = result[0]
        self.assertEqual(rs, u'inbound rule authorization successful')
        rs = result[1]
        self.assertEqual(rs, u'outbound rule authorization successful')


class TestCreateInstance(ACSMockServiceTestCase):
    connection_class = ECSConnection

    image_id = "win2012_64_datactr_r2_cn_40G_alibase_20160622.vhd"
    instance_type = "ecs.n1.small"
    group_id = "sg-2ze0ktjl4szwycum4q2b"
    zone_id = "cn-beijing-b"
    instance_name = "MyInstance"
    description = None
    internet_data = {
                        'charge_type': 'PayByTraffic',
                        'max_bandwidth_in': 200,
                        'max_bandwidth_out': 0
                    }

    host_name = None
    password = None
    io_optimized = True
    system_disk = {
        "disk_category": "cloud_efficiency",
        "disk_size": 50
    }
    disks = [
        {
            "disk_category": "cloud_efficiency",
            "disk_size": 20,
            "disk_name": "disk_1",
            "disk_description": "disk 1 description comes here"
        },
        {
            "disk_category": "cloud_efficiency",
            "disk_size": 20,
            "disk_name": "disk_2",
            "disk_description": "disk 2 description comes here"
        }
    ]

    vswitch_id = None
    private_ip = True
    allocate_public_ip = True
    bind_eip = False
    instance_charge_type = None
    period = None
    auto_renew = False
    auto_renew_period =None
    instance_tags = [
        {
            "tag_key": "create_test_1",
            "tag_value": "0.01"
        },
        {
            "tag_key": "create_test_2",
            "tag_value": "0.02"
        }
    ]
    ids = None
    count = 1
    wait = True
    wait_timeout = 60    
    
    def default_body(self):
        return CREATE_INSTANCE
                                                                    
    def test_create_instance(self):
        self.set_http_response(status_code=200)
        result = self.service_connection.create_instance(image_id=self.image_id, instance_type=self.instance_type,
                                                         group_id=self.group_id, zone_id=self.zone_id,
                                                         instance_name=self.instance_name, description=self.description,
                                                         internet_data=self.internet_data, host_name=self.host_name,
                                                         password=self.password, io_optimized=self.io_optimized,
                                                         system_disk=self.system_disk, disks=self.disks,
                                                         vswitch_id=self.vswitch_id, private_ip=self.private_ip,
                                                         count=self.count, allocate_public_ip=self.allocate_public_ip,
                                                         bind_eip=self.bind_eip,
                                                         instance_charge_type=self.instance_charge_type,
                                                         period=self.period, auto_renew=self.auto_renew,
                                                         auto_renew_period=self.auto_renew_period,
                                                         instance_tags=self.instance_tags, ids=self.ids, wait=self.wait,
                                                         wait_timeout=self.wait_timeout)
        self.assertEqual(len(result[1]), self.count)
        self.assertEqual(result[1][0]['InstanceId'], u'i-2zeg0900kzwn7dpo7zrb')


class TestModifyInstance(ACSMockServiceTestCase):
    connection_class = ECSConnection
    attributes = [
        {
            "description": "volume attribute",
            "host_name": "hostcomes",
            "id": "i-rj97hhf9ue16ewoged75",
            "name": "aspen",
            "password": "Pass@123"
        }
    ]

    def default_body(self):
        return MODIFY_INSTANCE

    def test_modify_instance(self):
        self.set_http_response(status_code=200)
        changed, result = self.service_connection.modify_instance(attributes=self.attributes)                  
        self.assertEqual(result[0]['instance_ids'], [u'i-rj97hhf9ue16ewoged75'])


class TestGetInstance(ACSMockServiceTestCase):
    connection_class = ECSConnection
   
    region_id = "cn-beijing"
    pagenumber = 1
    pagesize = 5

    def default_body(self):
        return GET_INSTANCE

    def test_get_instance(self):
        self.set_http_response(status_code=200)
        result = self.service_connection.get_instance_status(zone_id=None, pagenumber=self.pagenumber,
                                                             pagesize=self.pagesize)
        
        self.assertEqual(result[1][u'PageNumber'], self.pagenumber)
        self.assertEqual(result[1][u'PageSize'], self.pagesize)


class TestJoinSecGrp(ACSMockServiceTestCase): 
    connection_class = ECSConnection
    acs_access_key = 'LTAIV7yukr6Csf14'
    acs_secret_access_key = 'it9TEJcJvnDyL5uB830fx1BQwzdNdd'
    instance_ids = ["i-2zehfxz81ar5kvptw8b1"]
    group_id = 'sg-2zeewmie535ht7d90cki'
    region = 'cn-beijing'
    state = 'join'
    changed = False

    def default_body(self):
        return JOIN_GROUP

    def test_join_grp(self):
        self.set_http_response(status_code=200)
        changed, result = self.service_connection.join_security_group(instance_ids=self.instance_ids, group_id=self.group_id)
        ###self.assertEqual(len(result), len(self.attributes))
        #self.assertEqual(result[0], "success")
        res=''
        if len(result) == 1:
            res = "success"
        else:
            res = "fail"


class TestLeaveSecGrp(ACSMockServiceTestCase): 
    connection_class = ECSConnection
    acs_access_key = 'LTAIV7yukr6Csf14'
    acs_secret_access_key = 'it9TEJcJvnDyL5uB830fx1BQwzdNdd'
    instance_ids = ["i-j6c5txh3q0wivxt5m807"]
    group_id = 'sg-j6c34iujuqbw29zpd53u'
    region = 'cn-hongkong'
    state = 'remove'
    changed = False

    def default_body(self):
        return LEAVE_GROUP

    def test_leave_grp(self):
        self.set_http_response(status_code=200)
        changed, result = self.service_connection.leave_security_group(instance_ids=self.instance_ids, group_id=self.group_id)
        ###self.assertEqual(len(result), len(self.attributes))
        #self.assertEqual(result[0], "success")
        res=''
        if len(result) == 1:
            res = "success"
        else:
            res = "fail"




