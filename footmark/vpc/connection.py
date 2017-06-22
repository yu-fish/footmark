# encoding: utf-8
import warnings

import six
import time
import json
from functools import wraps

from footmark.connection import ACSQueryConnection
from footmark.vpc.regioninfo import RegionInfo
from footmark.exception import VPCResponseError
from footmark.resultset import ResultSet
from footmark.vpc.vpc import Vpc
from footmark.vpc.vswitch import VSwitch
from aliyunsdkcore.acs_exception.exceptions import ServerException

# from aliyunsdkecs.request.v20140526.DeleteVSwitchRequest import

class VPCConnection(ACSQueryConnection):
    SDKVersion = '2014-05-26'
    DefaultRegionId = 'cn-hangzhou'
    DefaultRegionName = u'杭州'.encode("UTF-8")
    ResponseError = VPCResponseError

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

        self.VPCSDK = 'aliyunsdkecs.request.v' + self.SDKVersion.replace('-', '')

        super(VPCConnection, self).__init__(acs_access_key_id,
                                            acs_secret_access_key,
                                            self.region, self.VPCSDK, security_token)

    def build_filter_params(self, params, filters):
        if not isinstance(filters, dict):
            return

        flag = 1
        for key, value in filters.items():
            acs_key = key
            if acs_key.startswith('tag:'):
                while ('set_Tag%dKey' % flag) in params:
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

    def create_vpc(self, cidr_block=None, user_cidr=None, vpc_name=None, description=None, wait_timeout=None, wait=None):

        """
        Create a ECS VPC (virtual private cloud) in Aliyun Cloud
        :type cidr_block: String
        :param cidr_block: The cidr block representing the VPC, e.g. 10.0.0.0/8
        :type user_cidr: String
        :param user_cidr: User custom cidr in the VPC
        :type vpc_name: String
        :param vpc_name: A VPC name
        :type description: String
        :param description: Description about VPC
        :type wait: string
        :param wait: An optional bool value indicating wait for instance to be running before running
        :type wait_timeout: int
        :param wait_timeout: An optional int value indicating how long to wait, default 300
        :return: Returns details of created VPC
        """

        params = {}

        if cidr_block:
            self.build_list_params(params, cidr_block, 'CidrBlock')

        if user_cidr:
            self.build_list_params(params, user_cidr, 'UserCidr')

        if vpc_name:
            self.build_list_params(params, vpc_name, 'VpcName')

        if description:
            self.build_list_params(params, description, 'Description')

        response = self.get_object('CreateVpc', params, ResultSet)
        vpc_id = str(response.vpc_id)
        changed = self.wait_for_vpc_status(vpc_id, 'Available')

        # if str(wait).lower() in ['yes', 'true'] and wait_timeout:
        #     time.sleep(wait_timeout)

        return changed, self.get_vpc_attribute(vpc_id)

    def get_vpc_attribute(self, vpc_id):
        """
        method to get all vpcId of particular region 
        :return: Return All vpcs in the region
        """
        params = {}

        self.build_list_params(params, vpc_id, 'VpcId')
        response = self.get_list('DescribeVpcs', params, ['Vpcs', Vpc])
        if response:
            return response[0]

        return None

    def get_all_vpcs(self, vpc_id=None, is_default=None, pagenumber=1, pagesize=10):
        """
        Find Vpc
        :type vpc_id: string
        :param vpc_id: Vpc Id of the targeted Vpc to terminate
        :type is_default: bool
        :param is_default: The vpc created by system if it is True
        :type pagenumber: integer
        :param pagenumber: Page number of the instance status list. The start value is 1. The default value is 1
        :type pagesize: integer
        :param pagesize: Sets the number of lines per page for queries per page. The maximum value is 50.
        The default value is 10
        :rtype: list
        :return: Returns VPC list if vpcs found along with Vpc details.
        """
        params = {}

        if vpc_id:
            self.build_list_params(params, vpc_id, 'VpcId')

        if is_default is not None:
            self.build_list_params(params, is_default, 'IsDefault')

        self.build_list_params(params, pagenumber, 'PageNumber')
        self.build_list_params(params, pagesize, 'PageSize')

        return self.get_list('DescribeVpcs', params, ['Vpcs', Vpc])

    def delete_vpc(self, vpc_id):
        """
        Delete Vpc
        :type vpc_id: string
        :param vpc_id: Vpc Id of the targeted Vpc to terminate
        :rtype: bool
        :return: Return result of deleting.
       """
        changed = False

        params = {}

        self.build_list_params(params, vpc_id, 'VpcId')

        if self.wait_for_vpc_status(vpc_id, 'Available'):
            changed = self.get_status('DeleteVpc', params)

        return changed

    def create_vswitch(self, zone_id, vpc_id, cidr_block, vswitch_name=None, description=None):
        """
        :type zone_id: String
        :param zone_id: Required parameter. ID of the zone to which an VSwitch belongs
        :type vpc_id: String
        :param vpc_id: Required parameter. The VPC ID of the new VSwitch
        :type cidr_block: String
        :param cidr_block: Required parameter. The cidr block representing the VSwitch, e.g. 10.0.0.0/8
        :type vswitch_name: String
        :param vswitch_name: A VSwitch name
        :type description: String
        :param description: Description about VSwitch
        
        :return: Return the operation result and details of created VSwitch
        """
        params = {}

        self.build_list_params(params, vpc_id, 'VpcId')
        self.build_list_params(params, zone_id, 'ZoneId')
        self.build_list_params(params, cidr_block, 'CidrBlock')

        if vswitch_name:
            self.build_list_params(params, vswitch_name, 'VSwitchName')

        if description:
                self.build_list_params(params, description, 'Description')

        response = self.get_object('CreateVSwitch', params, ResultSet)
        vsw_id = str(response.vswitch_id)
        changed = self.wait_for_vswitch_status(vsw_id, 'Available')
        return changed, self.get_vswitch_attribute(vsw_id)

    def get_all_vswitches(self, vpc_id=None, vswitch_id=None, zone_id=None, is_default=None, pagenumber=1, pagesize=10):
        """
        Find Vpc
        :type vpc_id: String
        :param vpc_id: The VPC ID of the VSwitch
        :type vswitch_id: String
        :param vswitch_id: ID of the specified VSwitch
        :type zone_id: String
        :param zone_id: ID of the zone to which an VSwitch belongs
        :type is_default: bool
        :param is_default: The vswitch created by system if it is True
        :type pagenumber: integer
        :param pagenumber: Page number of the instance status list. The start value is 1. The default value is 1
        :type pagesize: integer
        :param pagesize: Sets the number of lines per page for queries per page. The maximum value is 50.
        The default value is 10
        :rtype: list
        :return: Return VSwitch list if VSwitches found along with VSwitch details.
        """
        params = {}

        if vpc_id:
            self.build_list_params(params, vpc_id, 'VpcId')

        if vswitch_id:
            self.build_list_params(params, vswitch_id, 'VSwitchId')

        if zone_id:
            self.build_list_params(params, zone_id, 'ZoneId')

        if is_default is not None:
            self.build_list_params(params, is_default, 'IsDefault')

        self.build_list_params(params, pagenumber, 'PageNumber')
        self.build_list_params(params, pagesize, 'PageSize')

        return self.get_list('DescribeVSwitches', params, ['VSwitches', VSwitch])

    def get_vswitch_attribute(self, vswitch_id):
        """
        method to get specified vswitch attribute 
        :return: Return vswitch with its attribute
        """

        response = self.get_all_vswitches(vswitch_id=vswitch_id)
        if response:
            return response[0]

        return None

    def delete_vswitch(self, vswitch_id):
        """
        Delete VSwitch
        :type vswitch_id : str
        :param vswitch_id: The Id of vswitch
        :rtype bool
        :return: return result of deleting
        """

        changed = False

        params = {}

        self.build_list_params(params, vswitch_id, 'VSwitchId')

        if self.wait_for_vswitch_status(vswitch_id, 'Available'):
            changed = self.get_status('DeleteVSwitch', params)

        return changed

    def delete_vswitch_with_vpc(self, vpc_id):
        """
        Delete VSwitches in the specified VPC
        :type vpc_id : str
        :param vpc_id: The Id of vpc to which vswitch belongs
        :rtype list
        :return: return list ID of deleted VSwitch
        """

        vswitch_ids = []
        if not vpc_id:
                raise Exception(msg="It must be specify vpc_id.")

        vswitches = self.get_all_vswitches(vpc_id=vpc_id)
        for vsw in vswitches:
            vsw_id = str(vsw.id)
            if self.delete_vswitch(vsw_id):
                vswitch_ids.append(vsw_id)

        return vswitch_ids

    def get_instance_info(self):
        """
        method to get all Instances of particular region 
        :return: Return All Instances in the region
        """
        params = {}
        results = []

        try:
            v_ids = {}
            response = self.get_status('DescribeInstances', params)
            results.append(response)
            
        except Exception as ex:        
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return results

    def describe_vswitch(self, purge_vswitches, vpc_id):
        """
        method to check vswitch present or not       
        :type vpc_id : str
        :param vpc_id: The Id of vpc in which switch is present
        :type purge_vswitches :str
        :param purge_vswitches: The Id of vswitch to be describe
        :return: Return the status of the vswitch
        """
        params = {}
        results = []

        try:     
                             
            self.build_list_params(params, purge_vswitches, 'VSwitchId')
            self.build_list_params(params, vpc_id, 'VpcId')
            response = self.get_status('DescribeVSwitches', params)
            results.append(response)
            
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return results

    def requesting_eip_addresses(self, bandwidth, internet_charge_type):
        """
        method to query eip addresses in the region
        :type bandwidth : str
        :param bandwidth : bandwidth of the eip address
        :type internet_charge_type : str
        :param internet_charge_type : paybytraffic or paybybandwidth types
        :return: Return the allocationId , requestId and EIP address
        """
        params = {}
        results = []
        changed = False
        try:
            if bandwidth:
                self.build_list_params(params, bandwidth, 'Bandwidth')
            
            if internet_charge_type:
                self.build_list_params(params, internet_charge_type, 'InternetChargeType')
                  
            results = self.get_status('AllocateEipAddress', params)
            changed = True
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results

    def bind_eip(self, allocation_id, instance_id):
        """
        :type allocation_id:string
        :param allocation_id:The instance ID of the EIP
        :type instance_id:string
        :param instance_id:The ID of an ECS instance
        :return:Returns the status of operation
        """
        params = {}
        results = []
        
        self.build_list_params(params, allocation_id, 'AllocationId')
        self.build_list_params(params, instance_id, 'InstanceId')
       
        try:
            results = self.get_status('AssociateEipAddress', params)
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})
       
        return results

    def unbind_eip(self, allocation_id, instance_id):
        """
        :type allocation_id:string
        :param allocation_id:The instance ID of the EIP
        :type instance_id:string
        :param instance_id:The ID of an ECS instance
        :return:Request Id
        """
        params = {}
        results = []
        changed = False
        if allocation_id:
            self.build_list_params(params, allocation_id, 'AllocationId')
        if instance_id:
            self.build_list_params(params, instance_id, 'InstanceId')
        try:
            results = self.get_status('UnassociateEipAddress', params)
            changed = True
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results
        
    def modifying_eip_attributes(self, allocation_id, bandwidth):
        """
        :type allocation_id:string
        :param allocation_id:The instance ID of the EIP
        :type bandwidth:string
        :param bandwidth:Bandwidth of the EIP instance
        :return:Request Id
        """
        params = {}
        results = []
        changed = False

        if allocation_id:
            self.build_list_params(params, allocation_id, 'AllocationId')
        if bandwidth:
            self.build_list_params(params, bandwidth, 'Bandwidth')
        try:
            results = self.get_status('ModifyEipAddressAttribute', params)
            changed = True
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results

    def get_all_vrouters(self, vrouter_id=None, pagenumber=None, pagesize=None):
        """
        Querying vrouter
        :param vrouter_id: VRouter_Id to be fetched
        :type vrouter_id: str
        :type pagenumber: integer
        :param pagenumber: Page number of the instance status list. The start value is 1. The default value is 1
        :type pagesize: integer
        :param pagesize: Sets the number of lines per page for queries per page. The maximum value is 50.
        The default value is 10
        :return: VRouters in json format
        """
        params = {}
        results = []

        try:
            if vrouter_id is not None :
                self.build_list_params(params, vrouter_id, 'VRouterId')

            if pagenumber is not None :
                self.build_list_params(params, pagenumber, 'PageNumber')

            if pagesize is not None :
                self.build_list_params(params, pagesize, 'PageSize')

            results = self.get_status('DescribeVRouters', params)
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return False, results

    def delete_custom_route(self, purge_routes, vpc_id):
        """
        Deletes the specified RouteEntry for the vpc
        :type purge_routes: Dict
        :param purge_routes:
            - route_table_id: Id of the route table
            - destination_cidr_block: The RouteEntry's target network segment
            - next_hop_id: The route entry's next hop
        :type vpc_id: str
        :param vpc_id: Id of VPC
        :return: Return status of operation
        """
        params = {}
        results = []
        vrouter_table_id = None
        changed = False

        # Describe Vpc for getting VRouterId            
        desc_vpc_param = {}
        self.build_list_params(desc_vpc_param, vpc_id, 'VpcId')
        desc_vpc_response = self.get_status('DescribeVpcs', desc_vpc_param)
        if int(desc_vpc_response[u'TotalCount']) > 0:
            vrouter_id = str(desc_vpc_response[u'Vpcs'][u'Vpc'][0][u'VRouterId']) 
        
            # Describe Route Tables for getting RouteTable Id                    
            desc_route_table_param = {}
            self.build_list_params(desc_route_table_param, vrouter_id, 'VRouterId')
            desc_route_table_response = self.get_status('DescribeRouteTables', desc_route_table_param)
            if int(desc_route_table_response[u'TotalCount']) > 0:
                vrouter_table_id = str(desc_route_table_response[u'RouteTables'][u'RouteTable'][0][u'RouteTableId'])

        if 'route_table_id' in purge_routes:
            if 'next_hop_id' in purge_routes:
                if vrouter_table_id == purge_routes["route_table_id"]:                
                    self.build_list_params(params, purge_routes["route_table_id"], 'RouteTableId')        
                    fixed_dest_cidr_block = None
                    if 'dest' in purge_routes:
                        fixed_dest_cidr_block = purge_routes["dest"]
                    if 'destination_cidrblock' in purge_routes:
                        fixed_dest_cidr_block = purge_routes["destination_cidrblock"]
                    if fixed_dest_cidr_block:
                        self.build_list_params(params, fixed_dest_cidr_block, 'DestinationCidrBlock')
        
                    self.build_list_params(params, purge_routes["next_hop_id"], 'NextHopId')

                    try:
                        results = self.get_status('DeleteRouteEntry', params)
                        changed = True
                    except Exception as ex:
                        error_code = ex.error_code
                        error_msg = ex.message
                        results.append({"Error Code": error_code, "Error Message": error_msg})
                else:
                    changed = False
                    results.append({ "Error Message": "RouteTableId or VpcId does not exist"})
            else:
                results.append({"Error Message": "next_hop_id is required to delete route entry"})
        else:
            results.append({"Error Message": "route_table_id is required to delete route entry"})

        return changed, results

    def releasing_eip(self, allocation_id):
        """
        To release Elastic Ip
        :type allocation_id: string
        :param allocation_id: To release the allocation ID,allocation ID uniquely identifies the EIP
        :return: Return status of operation
        """
        params = {}
        results = []
        describe_eip = []
        flag = False

        try:
            self.build_list_params(params, allocation_id, 'AllocationId')
            results = self.get_status('ReleaseEipAddress', params)

        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return results

    def describe_eip_address(self, eip_address=None, allocation_id=None, eip_status=None,
                             page_number=1, page_size=50):
        """
        Get EIP details for a region
        :param eip_address:
        :param allocation_id:
        :param eip_status:
        :return:
        """
        params = {}
        results = []
        eip_details=None

        if allocation_id:
            self.build_list_params(params, allocation_id, 'AllocationId')
        if eip_address:
            self.build_list_params(params, eip_address, 'EipAddress')
        if eip_status:
            self.build_list_params(params, eip_status, 'Status')

        self.build_list_params(params, page_number, 'PageNumber')
        self.build_list_params(params, page_size, 'PageSize')

        try:
            response = self.get_status('DescribeEipAddresses', params)
            eip_details = response['EipAddresses']['EipAddress']
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return eip_details, results


    def create_route_entry(self, route_tables, vpc_id):
        """
        Create RouteEntry for VPC
        :type route_tables: dict
        :param route_tables:
         - route_table_id: ID of VPC route table
         - dest: It must be a legal CIDR or IP address, such as: 192.168.0.0/24 or 192.168.0.1
         - next_hop_type: The next hop type. Available value options: Instance or Tunnel
         - next_hop_id: The route entry's next hop
         :param vpc_id: Id of vpc
        :return: Returns details of RouteEntry
        """
        params = {}
        results = []
        changed = False        
        vrouter_table_id = None

        # Describe Vpc for getting VRouterId            
        desc_vpc_param = {}
        self.build_list_params(desc_vpc_param, vpc_id, 'VpcId')
        desc_vpc_response = self.get_status('DescribeVpcs', desc_vpc_param)
        if int(desc_vpc_response[u'TotalCount']) > 0:
            vrouter_id = str(desc_vpc_response[u'Vpcs'][u'Vpc'][0][u'VRouterId']) 

            # Describe Route Tables for getting RouteTable Id                    
            desc_route_table_param = {}
            self.build_list_params(desc_route_table_param, vrouter_id, 'VRouterId')
            desc_route_table_response = self.get_status('DescribeRouteTables', desc_route_table_param)
            if int(desc_route_table_response[u'TotalCount']) > 0:
                vrouter_table_id = str(desc_route_table_response[u'RouteTables'][u'RouteTable'][0][u'RouteTableId'])

            for vroute in route_tables:
                self.build_list_params(params, vrouter_table_id , 'RouteTableId')              
                if "next_hop_id" in vroute:
                    if ("dest" in vroute) or ("destination_cidrblock" in vroute):
                        fixed_dest_cidr_block = None
                        if 'dest' in vroute:
                            fixed_dest_cidr_block = vroute["dest"]
                        if 'destination_cidrblock' in vroute:
                            fixed_dest_cidr_block = vroute["destination_cidrblock"]
                        if fixed_dest_cidr_block:
                            self.build_list_params(params, fixed_dest_cidr_block, 'DestinationCidrBlock')

                        if 'next_hop_type' in vroute:
                            self.build_list_params(params, vroute["next_hop_type"], 'NextHopType')

                        if 'next_hop_id' in vroute:
                            self.build_list_params(params, vroute["next_hop_id"], 'NextHopId')
                    
                        try:
                            instance_result = self.get_instance_info()
                            flag = False
                            if instance_result:
                                for instances in instance_result[0][u'Instances'][u'Instance']:
                                    if vroute["next_hop_id"] == instances['InstanceId']:
                                        flag = True
                                        break
                            if flag:    
                                response = self.get_status('CreateRouteEntry', params)
                                results.append(response)
                                changed = True
                                time.sleep(10)
                            else:
                                results.append({"Error Message": str(vroute["next_hop_id"])+" Instance not found"})
                        except Exception as ex:
                            error_code = ex.error_code
                            error_msg = ex.message
                            results.append({"Error Code": error_code, "Error Message": error_msg})
                    else:
                        results.append({"Error Message": "destination_cidrblock is required to create custom route entry"})
                else:
                    results.append({"Error Message": "next_hop_id is required to create custom route entry"})
        else:
            results.append({"Error Message": "vpc_id is not valid"})
        
        return changed, results

    def get_vswitch_status(self, vpc_id, zone_id=None, vswitch_id=None, pagenumber=None, pagesize=None):
        """
        List VSwitches of VPC with their status
        :type vpc_id: string
        :param vpc_id: ID of Vpc from which VSwitch belongs
        :type zone_id: string
        :param zone_id: ID of the Zone
        :type vswitch_id: string
        :param vswitch_id: The ID of the VSwitch to be queried
        :type pagenumber: integer
        :param pagenumber: Page number of the instance status list. The start value is 1. The default value is 1
        :type pagesize: integer
        :param pagesize: The number of lines per page set for paging query. The maximum value is 50 and default
        value is 10
        :return: Returns list of vswitches in VPC with their status
        """
        params = {}
        results = []

        self.build_list_params(params, vpc_id, 'VpcId')
        if zone_id:
            self.build_list_params(params, zone_id, 'ZoneId')
        if vswitch_id:
            self.build_list_params(params, vswitch_id, 'VSwitchId')
        if pagenumber:
            self.build_list_params(params, pagenumber, 'PageNumber')
        if pagesize:
            self.build_list_params(params, pagesize, 'PageSize')

        try:
            results = self.get_status('DescribeVSwitches', params)
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return False, results

    # retry decorator
    def retry(ExceptionToCheck, tries=10, delay=30, backoff=2, logger=None):

        def deco_retry(f):

            @wraps(f)
            def f_retry(*args, **kwargs):
                mtries, mdelay = tries, delay
                while mtries > 1:
                    try:
                        return f(*args, **kwargs)
                    except ExceptionToCheck, e:
                        time.sleep(mdelay)
                        mtries -= 1
                        mdelay *= backoff
                return f(*args, **kwargs)

            return f_retry  # true decorator

        return deco_retry

    # Use retry decorator
    @retry(Exception, tries=4)
    def wait_for_vpc_status(self, vpc_id, status):
        try:
            vpc = self.get_vpc_attribute(vpc_id)
            if vpc:
                # wait until vpc status is expected
                while vpc.status not in [status, str(status).lower()]:
                    time.sleep(5)
                    vpc = self.get_vpc_attribute(vpc_id)
                return True
        except Exception:
            raise Exception

    # Use retry decorator
    @retry(Exception, tries=5)
    def wait_for_vswitch_status(self, vswitch_id, status):
        try:
            vpc = self.get_vswitch_attribute(vswitch_id)
            if vpc:
                # wait until vpc status is expected
                while vpc.status not in [status, str(status).lower()]:
                    time.sleep(3)
                    vpc = self.get_vswitch_attribute(vswitch_id)
                return True
        except Exception:
            raise Exception