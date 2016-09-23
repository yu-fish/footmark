#!/usr/bin/env python
# import sys
# sys.path.append("../../..")
from footmark.ecs.connection import ECSConnection
from tests.unit import ACSMockServiceTestCase

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

#
# if __name__ == '__main__':
#     unittest.main()
