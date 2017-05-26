# encoding: utf-8
import warnings

import six
import time
import json

from footmark.connection import ACSQueryConnection
from footmark.vpc.regioninfo import RegionInfo
from footmark.exception import VPCResponseError
from footmark.ecs.vrouter import VRouterList


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

    def delete_vswitch(self, vpc_id, purge_vswitches):
        """
        Delete multiple VSwitched
        :type vpc_id : str
        :param vpc_id: The Id of vpc
        :type purge_vswitches: str
        :param purge_vswitches: The ID of the VSwitch to be deleted
        :return: return result of VSwitchIds
        """
        results = []
        instance_conn_vswitch = []
        changed = False
        params = {}
        vswitch_to_delete = []
        try:
            response = self.get_vpc_info(vpc_id=vpc_id)
            if response[0][u'TotalCount'] > 0:                
                if response[0][u'Vpcs'][u'Vpc'][0][u'VSwitchIds'][u'VSwitchId']:
                    for purge in purge_vswitches:
                        flag = False
                        for response_vswitch in response[0][u'Vpcs'][u'Vpc'][0][u'VSwitchIds'][u'VSwitchId']:
                            if str(purge) == str(response_vswitch):
                                flag = True
                                vswitch_to_delete.append(purge)
                        if not flag:
                            results.append({"status": purge+" VSwitch not found to delete", "flag": False})
                    if purge_vswitches:
                        for purge_vswitche in vswitch_to_delete:
                            params = {}
                            self.build_list_params(params, purge_vswitche, 'VSwitchId')
                            del_result = self.get_status('DeleteVSwitch', params)
                            results.append({"status": purge_vswitche+" deleted", "flag": True})
                            changed = True
                    else:
                        results.append({"status": "Vswitchs is not found in specified vpc", "flag": False})
            else:
                results.append({"status": "VPC not found", "flag": False})

        except Exception as ex:                       
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results

    def get_vpc_info(self, vpc_id):
        """
        method to get all vpcId of particular region 
        :return: Return All vpcs in the region
        """
        params = {}
        results = []

        try:
            v_ids = {}
            self.build_list_params(params, vpc_id, 'VpcId')
            response = self.get_status('DescribeVpcs', params)
            results.append(response)
            
        except Exception as ex:        
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return results

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

    def create_vpc(self, cidr_block=None, user_cidr=None, vpc_name=None, description=None, vswitches=None,
                   wait_timeout=None, wait=None):

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
        :type vswitches: List
        :param vswitches: List of Dictionary of Parameters for creating subnet(vswitch)
        :type wait: string
        :param wait: An optional bool value indicating wait for instance to be running before running
        :type wait_timeout: int
        :param wait_timeout: An optional int value indicating how long to wait, default 300
        :return: Returns details of created VPC
        """

        params = {}
        results = []
        changed = False

        if cidr_block:
            self.build_list_params(params, cidr_block, 'CidrBlock')

        if user_cidr:
            self.build_list_params(params, user_cidr, 'UserCidr')

        if vpc_name:
            self.build_list_params(params, vpc_name, 'VpcName')

        if description:
            self.build_list_params(params, description, 'Description')

        try:
            response = self.get_status('CreateVpc', params)
            vpc_id = str(response['VpcId'])
            route_table_id = str(response['RouteTableId'])
            results.append(response)
            changed = True
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})
        else:
            # creating vswitch(subnet) after creation of VPC
            time.sleep(30)

            if vswitches:
                vswitch_response = self.create_vswitch(vpc_id=vpc_id, vswitches=vswitches)
                if 'error code' in str(vswitch_response).lower() and 'error message' in str(vswitch_response).lower():
                    results.append(vswitch_response[1][0]['Error Message'])
                else:
                     results.append(vswitch_response[1])

        if str(wait).lower() in ['yes', 'true'] and wait_timeout:
            time.sleep(wait_timeout)

        return changed, results

    def create_vswitch(self, vpc_id, vswitches):
        """
        :type vpc_id: String
        :param vpc_id: The VPC of the new VSwitch
        :type vswitches: dict
        :param vswitches:
         - zone_id: Zone Id is specific zone inside region that we worked
         - cidr_block: The network address allocated to the new VSwitch
         - vswitch_name: The VSwitch name. The default value is blank. [2, 128] English or Chinese characters,
         must begin with an uppercase/lowercase letter or Chinese character. Can contain numbers, "_" and "-".
         This value will appear on the console.It cannot begin with http:// or https://.
         - description: The VSwitch description. The default value is blank. [2, 256] English or Chinese characters.
         Cannot begin with http:// or https://.
        :return: VSwitchId The system allocated VSwitchID
        """
        params = {}
        results = []
        changed = False
        VSwitchId = []
        
        self.build_list_params(params, vpc_id, 'VpcId')

        for vswitch in vswitches:
            fix_zone_id = None
            if 'zone' in vswitch:
                fix_zone_id =  vswitch["zone"]
            if 'az' in vswitch:
                fix_zone_id = vswitch["az"]
            if 'zone_id' in vswitch:
                fix_zone_id = vswitch["zone_id"]
            if fix_zone_id:
                self.build_list_params(params, fix_zone_id, 'ZoneId')            

            fix_cidr_block = None
            if 'cidr' in vswitch:
                fix_cidr_block =  vswitch["cidr"]
            if 'cidr_block' in vswitch:
                fix_cidr_block = vswitch["cidr_block"]
            if fix_cidr_block:
                self.build_list_params(params, fix_cidr_block, 'CidrBlock')            

            fix_vswitch_name = None
            if 'name' in vswitch:
                fix_vswitch_name = vswitch["name"]
            if 'vswitch_name' in vswitch:
                fix_vswitch_name = vswitch["vswitch_name"]
            if fix_vswitch_name:
                self.build_list_params(params, fix_vswitch_name, 'VSwitchName')

            if 'description' in vswitch:
                self.build_list_params(params, vswitch["description"], 'Description')      

            try:
                response = self.get_status('CreateVSwitch', params)
                results.append(response)
                VSwitchId.append(response[u'VSwitchId'])
                changed = True
                time.sleep(10)
            except Exception as ex:
                error_code = ex.error_code
                error_msg = ex.message
                results.append({"Error Code": error_code, "Error Message": error_msg})
        
        return changed, results, VSwitchId

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

    def delete_vpc(self, vpc_id=None):
        """
        Delete Vpc
        :type vpc_id: string
        :param vpc_id: Vpc Id of the targeted Vpc to terminate
        :rtype: dict
        :return: Returns a dictionary of Vpc Details that is targeted. If the Vpc was not deleted or found,
        "changed" will be set to False.
       """
        results = []
        changed = False

        params = {}

        if vpc_id:
            self.build_list_params(params, vpc_id, 'VpcId')

        try:
            response = self.get_status('DeleteVpc', params)
            changed = True
            results.append("Vpc with Id " + vpc_id + " successfully deleted.")
        except Exception as ex:
            error_code = ex.error_code
            msg = ex.message
            error_dict = {
                'DependencyViolation.RouteEntry': 'Custom route rules still exist for the current VPC.'
                                                  ' VPC deletion failed',
                'DependencyViolation.Instance': 'Cloud product instances still exist for the current VPC.'
                                                ' VPC deletion failed',
                'DependencyViolation.VSwitch': 'VSwitches still exist for the current VPC. VPC deletion failed',
                'DependencyViolation.SecurityGroup': 'Security groups still exist for the current VPC.'
                                                     ' VPC deletion failed',
                'IncorrectVpcStatus': 'The current VPC status does not support this operation',
                'SDK.InvalidRegionId': 'Invalide Region Id'}

            results.append("Following error occurred while deleting Vpc with Id "+vpc_id)
            results.append("Error Code: " + error_code)
            if error_code in error_dict:
                results.append("Message: " + str(error_dict[error_code]))
            else:
                results.append("Message: " + str(msg))

        return changed, results

    def get_vpcs(self, vpc_id=None, region_id=None):
        """
        Find Vpc
        :type vpc_id: string
        :param vpc_id: Vpc Id of the targeted Vpc to terminate
        :type region_id: string
        :param region_id: Region Id to locate Vpc in
        :rtype: bool
        :return: Returns True if vpc found along with Vpc details else False with possible reason.
        """
        params = {}

        if region_id:
            self.build_list_params(params, region_id, 'RegionId')

        if vpc_id:
            self.build_list_params(params, vpc_id, 'VpcId')

        try:
            response = self.get_status('DescribeVpcs', params)
            vpc_result = response['Vpcs']['Vpc']
            if len(vpc_result) > 0:
                return True, vpc_result
            else:
                return False, "Vpc does not exist"
        except Exception as ex:
            if len(ex.args):
                msg, stack = ex.args
                return False, "error occurred while finding Vpc :" + str(msg) + " " + str(stack)
            else:
                return False, "error occurred while finding Vpc :" + str(ex.error_code) + " " + str(ex.message)


