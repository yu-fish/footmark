# encoding: utf-8
"""
Represents a connection to the SLB service.
"""                    

import warnings

import six
import time
import json
 
from footmark.connection import ACSQueryConnection
from footmark.slb.regioninfo import RegionInfo
from footmark.exception import SLBResponseError


class SLBConnection(ACSQueryConnection):
    SDKVersion = '2014-05-15'
    DefaultRegionId = 'cn-hangzhou'
    DefaultRegionName = u'杭州'.encode("UTF-8")
    ResponseError = SLBResponseError

    def __init__(self, acs_access_key_id=None, acs_secret_access_key=None,
                 region=None, sdk_version=None, security_token=None):
        """
        Init method to create a new connection to SLB.
        """
        if not region:
            region = RegionInfo(self, self.DefaultRegionName,
                                self.DefaultRegionId)
        self.region = region
        if sdk_version:
            self.SDKVersion = sdk_version

        self.SLBSDK = 'aliyunsdkslb.request.v' + self.SDKVersion.replace('-', '')

        super(SLBConnection, self).__init__(acs_access_key_id,
                                            acs_secret_access_key,
                                            self.region, self.SLBSDK, security_token)

    def create_load_balancer(self, load_balancer_name=None, address_type=None, vswitch_id=None,
                             internet_charge_type=None, master_zone_id=None, slave_zone_id=None, bandwidth=None,
                             listeners=None, instance_ids=None, validate_cert=None, tags=None, wait=None,
                             wait_timeout=None):
        """
        Creates a Server Load Balancer
        :type load_balancer_name: string
        :param load_balancer_name: Name to the server load balancer
        :type address_type: string
        :param address_type:  Address type. value: internet or intranet
        :type vswitch_id: string
        :param vswitch_id: The vswitch id of the VPC instance. This option is invalid if address_type parameter is
         provided as internet.
        :type internet_charge_type: string
        :param internet_charge_type: Charging mode for the public network instance
         Value: paybybandwidth or paybytraffic
        :type master_zone_id: string
        :param master_zone_id: Name of of availability zones to enable on this SLB
        :type slave_zone_id: string
        :param slave_zone_id: Name of of availability zones to enable on this SLB
        :type bandwidth: string
        :param bandwidth: Bandwidth peak of the public network instance charged per fixed bandwidth
        :type listeners: dict
        :param listeners: List of ports/protocols for this SLB to listen on
        :type instance_ids: list
        :param instance_ids: A list of identifier for this instance or set of instances, so that the module will be
        :type validate_cert: string
        :param validate_cert: When set to "no", SSL certificates will not be validated. default: "yes"
        :type tags: list
        :param tags: A list of hash/dictionaries of load balancer tags, '[{tag_key:"value", tag_value:"value"}]',
         tag_key must be not null when tag_value isn't null
        :type wait: string
        :param wait: after execution of method whether it has to wait for some time interval
        :type wait_timeout: int
        :param wait_timeout: time interval of waiting
        :return: return the created load balancer details
        """

        params = {}
        results = []
        changed = False

        if load_balancer_name:
            self.build_list_params(params, load_balancer_name, 'LoadBalancerName')
        if address_type:
            self.build_list_params(params, address_type, 'AddressType')
        if vswitch_id:
            self.build_list_params(params, vswitch_id, 'VSwitchId')
        if internet_charge_type:
            self.build_list_params(params, internet_charge_type, 'InternetChargeType')
        if master_zone_id:
            self.build_list_params(params, master_zone_id, 'MasterZoneId')
        if slave_zone_id:
            self.build_list_params(params, slave_zone_id, 'SlaveZoneId')
        if bandwidth:
            self.build_list_params(params, bandwidth, 'Bandwidth')
                                       
        try:
            response = self.get_status('CreateLoadBalancer', params)
            results.append(response)
            changed = True
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            if (str(ex.error_code) == "InvalidParameter") and (str(ex.message) == "The site is not exist. "):
                results.append({"Error Code": error_code,
                                "Error Message": "Specified master_zone_id or slave_zone_id is not exist."})
            else:
                results.append({"Error Code": error_code, "Error Message": error_msg})
        else:
            slb_id = str(results[0][u'LoadBalancerId'])
            # if listener param is available then create listener
            if slb_id and listeners:
                for listener in listeners:
                    if listener:
                        if 'protocol' in listener:
                            protocol = str(listener['protocol']).lower()
                            # Add HTTP Listener to Load Balancer
                            if protocol in ['http']:
                                listener_result = self.create_load_balancer_http_listener(slb_id, listener)
                                if listener_result:
                                    results.append({"http_listener_result": listener_result[1]})

                            # Add HTTPS Listener to Load Balancer
                            elif protocol in ['https']:
                                listener_result = self.create_load_balancer_https_listener(slb_id, listener)
                                if listener_result:
                                    results.append({"https_listener_result": listener_result[1]})

                            # Add TCP Listener to Load Balancer
                            elif protocol in ['tcp']:
                                listener_result = self.create_load_balancer_tcp_listener(slb_id, listener)
                                if listener_result:
                                    results.append({"tcp_listener_result": listener_result[1]})

                            # Add UDP Listener to Load Balancer
                            elif protocol in ['udp']:
                                listener_result = self.create_load_balancer_udp_listener(slb_id, listener)
                                if listener_result:
                                    results.append({"udp_listener_result": listener_result[1]})
                            else:
                                results.append({"Error Message": "Invalid Listener Protocol " + listener['protocol']})

                if instance_ids:
                    if len(instance_ids) > 0:     
                        backend_servers = []

                        # Add Backend Serves to Load Balancer
                        for backend_server_id in instance_ids:
                            backend_servers.append({"server_id": backend_server_id, "weight": 100})

                        backend_server_result = self.add_backend_servers(slb_id, backend_servers)

                        if backend_server_result:
                            results.append({"backend_server_result": backend_server_result})

        if str(wait).lower() in ['yes', 'true'] and wait_timeout > 0:
            time.sleep(wait_timeout)

        return changed, results

    def add_listeners(self, load_balancer_id, purge_listener=None, listeners=None):
        """
        Add Listeners to existing ServerLoadBalancer
        :type load_balancer_id: str
        :param load_balancer_id: Id of ServerLoadBalancer
        :type purge_listener: bool
        :param purge_listener:  Whether to remove existing Listener or not
        :type listeners: dict
        :param listeners: List of ports/protocols for this SLB to listen on
        :return: returns RequestId id of request
        """
        params = {}
        results = []
        deleted_listener = []
        changed = False

        try:
            # find out all listeners of the load balancer
            self.build_list_params(params, load_balancer_id, 'LoadBalancerId')
            slb_details = self.get_status('DescribeLoadBalancerAttribute', params)

            # if purge_listener is true then delete existing listeners
            if purge_listener:
                if slb_details:
                    if len(slb_details[u'ListenerPortsAndProtocal'][u'ListenerPortAndProtocal']) > 0:
                        for slb_listener in slb_details[u'ListenerPortsAndProtocal'][u'ListenerPortAndProtocal']:
                            params = {}
                            self.build_list_params(params, load_balancer_id, 'LoadBalancerId')
                            self.build_list_params(params, slb_listener[u'ListenerPort'], 'ListenerPort')
                            response = self.get_status('DeleteLoadBalancerListener', params)
                            deleted_listener.append(response)
                            changed = True
                            
            # add listeners to load balancer
            if listeners:
                for listener in listeners:
                    if listener:
                        if 'protocol' in listener:
                            protocol = str(listener['protocol']).lower()
                            # Add HTTP Listener to Load Balancer
                            if protocol in ['http']:
                                listener_result = self.create_load_balancer_http_listener(load_balancer_id, listener)
                                if listener_result:                                    
                                    results.append({"http_listener_result": listener_result[1]})
                                    # modify changed param according to listener result
                                    if changed is False:
                                        changed = listener_result[0]

                            # Add HTTPS Listener to Load Balancer
                            elif protocol in ['https']:
                                listener_result = self.create_load_balancer_https_listener(load_balancer_id, listener)
                                if listener_result:
                                    results.append({"https_listener_result": listener_result[1]})
                                    # modify changed param according to listener result
                                    if changed is False:
                                        changed = listener_result[0]

                            # Add TCP Listener to Load Balancer
                            elif protocol in ['tcp']:
                                listener_result = self.create_load_balancer_tcp_listener(load_balancer_id, listener)
                                if listener_result:
                                    results.append({"tcp_listener_result": listener_result[1]})
                                    # modify changed param according to listener result
                                    if changed is False:
                                        changed = listener_result[0]

                            # Add UDP Listener to Load Balancer
                            elif protocol in ['udp']:
                                listener_result = self.create_load_balancer_udp_listener(load_balancer_id, listener)
                                if listener_result:
                                    results.append({"udp_listener_result": listener_result[1]})
                                    # modify changed param according to listener result
                                    if changed is False:
                                        changed = listener_result[0]
                            else:
                                results.append({"Error Message": "Invalid Listener Protocol " + listener['protocol']})

        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results     

    def create_load_balancer_http_listener(self, slb_id, listener):
        """
        Create HTTP Listener; create Listeners based on the HTTP protocol for the Server Load Balancer instance,
        including policies and health check configurations based on the HTTP protocol
        :type slb_id: dict
        :param slb_id:  ID of Server Load Balancer
        :type listener: dict
        :param listener:
         - listener_port/load_balancer_port: Server Load Balancer instance’s frontend port. Value: 1-65535
         - backend_server_port/instance_port: Server Load Balancer instance’s backend port. Value: 1-65535
         - bandwidth: Listener’s peak bandwidth. Value: -1 / 1-1000 Mbps
         - scheduler: Scheduling algorithm. Value: wrr / wlc / rr Default value: wrr
         - gzip: Whether to open the Gzip compression
         - health_check:
            - domain: Health check domain name
            - uri/ping_path: Health check URI.When HealthCheck is On, this parameter is required.
               When HealthCheck is Off, this parameter is ignored.
            - connect_port/ping_port: Port used for health checks
            - healthy_threshold: Threshold value for determining health check results as Success
            - unhealthy_threshold: Threshold value for determining health check results as Fail
            - timeout/response_timeout: Maximum timeout time for each health check response
            - interval: Interval between health checks
            - http_code: Normal health check HTTP status codes. Separate multiple status codes with ','
         - stickiness:
            - enabled: Whether to enable session persistence
            - type/session_type: Mode for handling the cookie. Value：insert / server
            - cookie: The cookie configured on the server
            - expiration/cookie_timeout: Cookie timeout
        :return: returns RequestId of request
        """

        params = {}
        results = []
        changed = False
        listener_port = None

        if listener:              
            self.build_list_params(params, slb_id, 'LoadBalancerId')

            if 'load_balancer_port' in listener:
                listener_port = listener['load_balancer_port']
            if 'listener_port' in listener:
                listener_port = listener['listener_port']
            if listener_port:
                self.build_list_params(params, listener_port, 'ListenerPort')                                                 

            backend_server_port = None
            if 'instance_port' in listener:
                backend_server_port = listener['instance_port']
            if 'backend_server_port' in listener:
                backend_server_port = listener['backend_server_port']
            if backend_server_port:
                self.build_list_params(params, backend_server_port, 'BackendServerPort')

            if 'bandwidth' in listener:
                self.build_list_params(params, listener['bandwidth'], 'Bandwidth')
            if 'scheduler' in listener:
                self.build_list_params(params, listener['scheduler'], 'Scheduler')
            if 'gzip' in listener:
                self.build_list_params(params, listener['gzip'], 'Gzip')

            if 'health_check' in listener:
                health_check = listener['health_check']                  
                self.build_list_params(params, "on", 'HealthCheck')
                if 'domain' in health_check:
                    self.build_list_params(params, health_check['domain'], 'HealthCheckDomain')

                health_check_uri = None
                if 'ping_path' in health_check:
                    health_check_uri = health_check['ping_path']
                if 'uri' in health_check:
                    health_check_uri = health_check['uri']
                if health_check_uri:
                    self.build_list_params(params, health_check_uri, 'HealthCheckURI')

                health_check_connect_port = None
                if 'ping_port' in health_check:
                    health_check_connect_port = health_check['ping_port']
                if 'connect_port' in health_check:
                    health_check_connect_port = health_check['connect_port']
                if health_check_connect_port:
                    self.build_list_params(params, health_check_connect_port, 'HealthCheckConnectPort')

                if 'healthy_threshold' in health_check:
                    self.build_list_params(params, health_check['healthy_threshold'], 'HealthyThreshold')
                if 'unhealthy_threshold' in health_check:
                    self.build_list_params(params, health_check['unhealthy_threshold'], 'UnhealthyThreshold')

                health_check_timeout = None
                if 'response_timeout' in health_check:
                    health_check_timeout = health_check['response_timeout']
                if 'timeout' in health_check:
                    health_check_timeout = health_check['timeout']
                if health_check_timeout:
                    self.build_list_params(params, health_check_timeout, 'HealthCheckTimeout')

                if 'interval' in health_check:
                    self.build_list_params(params, health_check['interval'], 'HealthCheckInterval')
                if 'http_code' in health_check:
                    self.build_list_params(params, health_check['http_code'], 'HealthCheckHttpCode')   

            if 'stickiness' in listener:
                stickiness = listener['stickiness']
                if 'enabled' in stickiness:
                    self.build_list_params(params, stickiness['enabled'], 'StickySession')

                sticky_session_type = None
                if 'session_type' in stickiness:
                    sticky_session_type = stickiness['session_type']
                if 'type' in stickiness:
                    sticky_session_type = stickiness['type']
                if sticky_session_type:
                    self.build_list_params(params, sticky_session_type, 'StickySessionType')

                if 'cookie' in stickiness:
                    self.build_list_params(params, stickiness['cookie'], 'Cookie')
                    
                cookie_timeout = None
                if 'cookie_timeout' in stickiness:
                    cookie_timeout = stickiness['cookie_timeout']
                if 'expiration' in stickiness:
                    cookie_timeout = stickiness['expiration']
                if cookie_timeout:
                    self.build_list_params(params, cookie_timeout, 'CookieTimeout')

        try:
            results = self.get_status('CreateLoadBalancerHTTPListener', params)
            changed = True
            # Start http Listener
            params = {}
            self.build_list_params(params, slb_id, 'LoadBalancerId')
            self.build_list_params(params, listener_port, 'ListenerPort')
            self.get_status('StartLoadBalancerListener', params)
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results

    def create_load_balancer_https_listener(self, slb_id, listener):
        """
        Configures an HTTPS Listener, including Scheduler, SticySession, HealthCheck, ServerCertificateId, etc
        :type slb_id: dict
        :param slb_id:  ID of Server Load Balancer
        :type listener: dict
        :param listener:
         - listener_port/load_balancer_port: Server Load Balancer instance’s frontend port. Value: 1-65535
         - backend_server_port/instance_port: Server Load Balancer instance’s backend port. Value: 1-65535
         - bandwidth: Listener’s peak bandwidth. Value: -1 / 1-1000 Mbps
         - scheduler: Scheduling algorithm. Value: wrr / wlc / rr Default value: wrr
         - ssl_certificate_id: Security certificate ID
         - gzip: Whether to open the Gzip compression
         - health_check:
            - domain: Health check domain name
            - uri/ping_path: Health check URI.When HealthCheck is On, this parameter is required.
               When HealthCheck is Off, this parameter is ignored.
            - connect_port/ping_port: Port used for health checks
            - healthy_threshold: Threshold value for determining health check results as Success
            - unhealthy_threshold: Threshold value for determining health check results as Fail
            - timeout/response_timeout: Maximum timeout time for each health check response
            - interval: Interval between health checks
            - http_code: Normal health check HTTP status codes. Separate multiple status codes with ','
         - stickiness:
            - enabled: Whether to enable session persistence
            - type/session_type: Mode for handling the cookie. Value：insert / server
            - cookie: The cookie configured on the server
            - expiration/cookie_timeout: Cookie timeout
        :return: returns RequestId of request
        """

        params = {}
        results = []
        changed = False
        listener_port = None

        if listener:              
            self.build_list_params(params, slb_id, 'LoadBalancerId')

            if 'load_balancer_port' in listener:
                listener_port = listener['load_balancer_port']
            if 'listener_port' in listener:
                listener_port = listener['listener_port']
            if listener_port:
                self.build_list_params(params, listener_port, 'ListenerPort')

            backend_server_port = None
            if 'instance_port' in listener:
                backend_server_port = listener['instance_port']
            if 'backend_server_port' in listener:
                backend_server_port = listener['backend_server_port']
            if backend_server_port:
                self.build_list_params(params, backend_server_port, 'BackendServerPort')

            if 'bandwidth' in listener:
                self.build_list_params(params, listener['bandwidth'], 'Bandwidth')
            if 'scheduler' in listener:
                self.build_list_params(params, listener['scheduler'], 'Scheduler')
            if 'ssl_certificate_id' in listener:
                self.build_list_params(params, listener['ssl_certificate_id'], 'ServerCertificateId')
            if 'gzip' in listener:
                self.build_list_params(params, listener['gzip'], 'Gzip')

            if 'health_check' in listener:
                health_check = listener['health_check']                  
                self.build_list_params(params, "on", 'HealthCheck')
                if 'domain' in health_check:
                    self.build_list_params(params, health_check['domain'], 'HealthCheckDomain')

                health_check_uri = None
                if 'ping_path' in health_check:
                    health_check_uri = health_check['ping_path']
                if 'uri' in health_check:
                    health_check_uri = health_check['uri']
                if health_check_uri:
                    self.build_list_params(params, health_check_uri, 'HealthCheckURI')

                health_check_connect_port = None
                if 'ping_port' in health_check:
                    health_check_connect_port = health_check['ping_port']
                if 'connect_port' in health_check:
                    health_check_connect_port = health_check['connect_port']
                if health_check_connect_port:
                    self.build_list_params(params, health_check_connect_port, 'HealthCheckConnectPort')

                if 'healthy_threshold' in health_check:
                    self.build_list_params(params, health_check['healthy_threshold'], 'HealthyThreshold')
                if 'unhealthy_threshold' in health_check:
                    self.build_list_params(params, health_check['unhealthy_threshold'], 'UnhealthyThreshold')

                health_check_timeout = None
                if 'response_timeout' in health_check:
                    health_check_timeout = health_check['response_timeout']
                if 'timeout' in health_check:
                    health_check_timeout = health_check['timeout']
                if health_check_timeout:
                    self.build_list_params(params, health_check_timeout, 'HealthCheckTimeout')

                if 'interval' in health_check:
                    self.build_list_params(params, health_check['interval'], 'HealthCheckInterval')
                if 'http_code' in health_check:
                    self.build_list_params(params, health_check['http_code'], 'HealthCheckHttpCode')   

            if 'stickiness' in listener:
                stickiness = listener['stickiness']
                if 'enabled' in stickiness:
                    self.build_list_params(params, stickiness['enabled'], 'StickySession')

                sticky_session_type = None
                if 'session_type' in stickiness:
                    sticky_session_type = stickiness['session_type']
                if 'type' in stickiness:
                    sticky_session_type = stickiness['type']
                if sticky_session_type:
                    self.build_list_params(params, sticky_session_type, 'StickySessionType')

                if 'cookie' in stickiness:
                    self.build_list_params(params, stickiness['cookie'], 'Cookie')

                cookie_timeout = None
                if 'cookie_timeout' in stickiness:
                    cookie_timeout = stickiness['cookie_timeout']
                if 'expiration' in stickiness:
                    cookie_timeout = stickiness['expiration']
                if cookie_timeout:
                    self.build_list_params(params, cookie_timeout, 'CookieTimeout')

        try:
            results = self.get_status('CreateLoadBalancerHTTPSListener', params)
            changed = True
            # Start https Listener
            params = {}
            self.build_list_params(params, slb_id, 'LoadBalancerId')
            self.build_list_params(params, listener_port, 'ListenerPort')
            self.get_status('StartLoadBalancerListener', params)
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results

    def create_load_balancer_tcp_listener(self, slb_id, listener):
        """
        Configures an TCP Listener, including Scheduler, HealthCheck etc
        :type slb_id: dict
        :param slb_id:  ID of Server Load Balancer
        :type listener: dict
        :param listener:
         - listener_port/load_balancer_port: Server Load Balancer instance’s frontend port. Value: 1-65535
         - backend_server_port/instance_port: Server Load Balancer instance’s backend port. Value: 1-65535
         - bandwidth: Listener’s peak bandwidth. Value: -1 / 1-1000 Mbps
         - scheduler: Scheduling algorithm. Value: wrr / wlc / rr Default value: wrr
         - health_check:
            - domain: Health check domain name
            - uri/ping_path: Health check URI.When HealthCheck is On, this parameter is required.
               When HealthCheck is Off, this parameter is ignored.
            - connect_port/ping_port: Port used for health checks
            - healthy_threshold: Threshold value for determining health check results as Success
            - unhealthy_threshold: Threshold value for determining health check results as Fail
            - timeout/response_timeout: Maximum timeout time for each health check response
            - interval: Interval between health checks
            - http_code: Normal health check HTTP status codes. Separate multiple status codes with ','
        :return: returns RequestId of request
        """

        params = {}
        results = []
        changed = False
        listener_port = None

        if listener:              
            self.build_list_params(params, slb_id, 'LoadBalancerId')

            if 'load_balancer_port' in listener:
                listener_port = listener['load_balancer_port']
            if 'listener_port' in listener:
                listener_port = listener['listener_port']
            if listener_port:
                self.build_list_params(params, listener_port, 'ListenerPort')

            backend_server_port = None
            if 'instance_port' in listener:
                backend_server_port = listener['instance_port']
            if 'backend_server_port' in listener:
                backend_server_port = listener['backend_server_port']
            if backend_server_port:
                self.build_list_params(params, backend_server_port, 'BackendServerPort')

            if 'bandwidth' in listener:
                self.build_list_params(params, listener['bandwidth'], 'Bandwidth')
            if 'scheduler' in listener:
                self.build_list_params(params, listener['scheduler'], 'Scheduler')

            if 'health_check' in listener:
                health_check = listener['health_check']                  
                self.build_list_params(params, "on", 'HealthCheck')
                if 'domain' in health_check:
                    self.build_list_params(params, health_check['domain'], 'HealthCheckDomain')

                health_check_uri = None
                if 'ping_path' in health_check:
                    health_check_uri = health_check['ping_path']
                if 'uri' in health_check:
                    health_check_uri = health_check['uri']
                if health_check_uri:
                    self.build_list_params(params, health_check_uri, 'HealthCheckURI')

                health_check_connect_port = None
                if 'ping_port' in health_check:
                    health_check_connect_port = health_check['ping_port']
                if 'connect_port' in health_check:
                    health_check_connect_port = health_check['connect_port']
                if health_check_connect_port:
                    self.build_list_params(params, health_check_connect_port, 'HealthCheckConnectPort')

                if 'healthy_threshold' in health_check:
                    self.build_list_params(params, health_check['healthy_threshold'], 'HealthyThreshold')
                if 'unhealthy_threshold' in health_check:
                    self.build_list_params(params, health_check['unhealthy_threshold'], 'UnhealthyThreshold')

                health_check_timeout = None
                if 'response_timeout' in health_check:
                    health_check_timeout = health_check['response_timeout']
                if 'timeout' in health_check:
                    health_check_timeout = health_check['timeout']
                if health_check_timeout:
                    self.build_list_params(params, health_check_timeout, 'HealthCheckTimeout')

                if 'interval' in health_check:
                    self.build_list_params(params, health_check['interval'], 'HealthCheckInterval')
                if 'http_code' in health_check:
                    self.build_list_params(params, health_check['http_code'], 'HealthCheckHttpCode')    

        try:
            results = self.get_status('CreateLoadBalancerTCPListener', params)
            changed = True
            # Start tcp Listener
            params = {}
            self.build_list_params(params, slb_id, 'LoadBalancerId')
            self.build_list_params(params, listener_port, 'ListenerPort')
            self.get_status('StartLoadBalancerListener', params)
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results

    def create_load_balancer_udp_listener(self, slb_id, listener):
        """
        Configures an UDP Listener, including Scheduler, HealthCheck etc
        :type slb_id: dict
        :param slb_id:  ID of Server Load Balancer
        :type listener: dict
        :param listener:
         - listener_port/load_balancer_port: Server Load Balancer instance’s frontend port. Value: 1-65535
         - backend_server_port/instance_port: Server Load Balancer instance’s backend port. Value: 1-65535
         - bandwidth: Listener’s peak bandwidth. Value: -1 / 1-1000 Mbps
         - scheduler: Scheduling algorithm. Value: wrr / wlc / rr Default value: wrr
         - health_check:
            - connect_port/ping_port: Port used for health checks
            - healthy_threshold: Threshold value for determining health check results as Success
            - unhealthy_threshold: Threshold value for determining health check results as Fail
            - timeout/response_timeout: Maximum timeout time for each health check response
            - interval: Interval between health checks
        :return: returns RequestId of request
        """

        params = {}
        results = []
        changed = False
        listener_port = None

        if listener:              
            self.build_list_params(params, slb_id, 'LoadBalancerId')

            if 'load_balancer_port' in listener:
                listener_port = listener['load_balancer_port']
            if 'listener_port' in listener:
                listener_port = listener['listener_port']
            if listener_port:
                self.build_list_params(params, listener_port, 'ListenerPort')

            backend_server_port = None
            if 'instance_port' in listener:
                backend_server_port = listener['instance_port']
            if 'backend_server_port' in listener:
                backend_server_port = listener['backend_server_port']
            if backend_server_port:
                self.build_list_params(params, backend_server_port, 'BackendServerPort')

            if 'bandwidth' in listener:
                self.build_list_params(params, listener['bandwidth'], 'Bandwidth')
            if 'scheduler' in listener:
                self.build_list_params(params, listener['scheduler'], 'Scheduler')

            if 'health_check' in listener:
                health_check = listener['health_check']                  
                self.build_list_params(params, "on", 'HealthCheck')

                health_check_connect_port = None
                if 'ping_port' in health_check:
                    health_check_connect_port = health_check['ping_port']
                if 'connect_port' in health_check:
                    health_check_connect_port = health_check['connect_port']
                if health_check_connect_port:
                    self.build_list_params(params, health_check_connect_port, 'HealthCheckConnectPort')

                if 'healthy_threshold' in health_check:
                    self.build_list_params(params, health_check['healthy_threshold'], 'HealthyThreshold')
                if 'unhealthy_threshold' in health_check:
                    self.build_list_params(params, health_check['unhealthy_threshold'], 'UnhealthyThreshold')

                health_check_timeout = None
                if 'response_timeout' in health_check:
                    health_check_timeout = health_check['response_timeout']
                if 'timeout' in health_check:
                    health_check_timeout = health_check['timeout']
                if health_check_timeout:
                    self.build_list_params(params, health_check_timeout, 'HealthCheckTimeout')

                if 'interval' in health_check:
                    self.build_list_params(params, health_check['interval'], 'HealthCheckInterval')

        try:
            results = self.get_status('CreateLoadBalancerUDPListener', params)
            changed = True
            # Start udp Listener
            params = {}
            self.build_list_params(params, slb_id, 'LoadBalancerId')
            self.build_list_params(params, listener_port, 'ListenerPort')
            self.get_status('StartLoadBalancerListener', params)
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results

    def add_backend_servers(self, load_balancer_id, backend_servers=None):
        """
        Add BackendServer to existing LoadBalancer
        :type load_balancer_id: str
        :param load_balancer_id: ID of server load balancer
        :type backend_servers: list
        :param backend_servers: list of dictionary containing server Id and weight of  backend server instance
        :return: return changed status, current_backend_servers and message with descriptive information
        """

        params = {}
        results = []
        current_backend_servers = []
        changed = False

        self.build_list_params(params, load_balancer_id, 'LoadBalancerId')

        backend_servers_list = []

        for backend_server in backend_servers:
            backend_servers_list.append({"ServerId": backend_server['server_id'],
                                         "Weight": str(backend_server['weight'])})

        backend_servers_json = json.dumps(backend_servers_list)
        self.build_list_params(params, backend_servers_json, 'BackendServers')

        try:
            response = self.get_status('AddBackendServers', params)
            changed = True
            results.append("Added Backend Server(s) successfully.")
            current_backend_servers = response['BackendServers']['BackendServer']

        except Exception as ex:
            error_code = str(ex.error_code)
            msg = str(ex.message)
            results.append("Failed to add backend servers with error code " + error_code +
                           " and message: " + msg)

        return changed, current_backend_servers, results
    
    def purge_add_backend_server(self, load_balancer_id, instance_ids=None, purge_instance_ids=None):
        """
        Remove existing Instances or Backend Server and Add new instances or Backend Server to Load Balancer
        :type load_balancer_id: str
        :param load_balancer_id: Id of ServerLoadBalancer
        :type instance_ids:list
        :param instance_ids: Id of Instances or Backend Server
        :type purge_instance_ids: bool
        :param purge_instance_ids: Whether to remove existing Instances or Backend Servers
        :return: Returns Id of newly added Load Balancer
        """
        params = {}
        results = []
        instances = []
        changed = False

        try:
            # List all Backend Servers
            self.build_list_params(params, load_balancer_id, 'LoadBalancerId')
            response = self.get_status('DescribeLoadBalancerAttribute', params)
            for instance in response[u'BackendServers'][u'BackendServer']:
                # append id of all Backend Servers to list
                instances.append(str(instance[u'ServerId']))

            # Remove instances only when purge_instance_ids is True
            if len(instances) > 0 and (purge_instance_ids is True):
                # Remove all Backend Servers
                response = self.remove_backend_servers(load_balancer_id=load_balancer_id, backend_server_ids=instances)
                if 'error' in (''.join(str(response))).lower():
                    results.append(response[2])
                else:
                    results.append(response[2][0])
                    changed = True

            # Add Backend Server to Load Balancer
            if instance_ids:
                if len(instance_ids) > 0:
                    backend_servers = []
                    for backend_server_id in instance_ids:
                        backend_servers.append({"server_id": backend_server_id, "weight": 100})

                    response = self.add_backend_servers(load_balancer_id, backend_servers)
                    if 'error' in (''.join(str(response))).lower():
                        results.append({"backend_server_result": response[2]})
                    else:
                        results.append({"backend_server_result": response[1][0]})
                        changed = True
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results    

    def remove_backend_servers(self, load_balancer_id=None, backend_server_ids=None):
        """
        :type load_balancer_id: str
        :param load_balancer_id: ID of server load balancer
        :type backend_server_ids: list
        :param backend_server_ids: list of IDs of backend server instance
        :return: return changed status, current_backend_servers and message with descriptive information
        """
        params = {}
        results = []
        current_backend_servers = []
        changed = False

        self.build_list_params(params, load_balancer_id, 'LoadBalancerId')

        backend_servers_json = json.dumps(backend_server_ids)

        self.build_list_params(params, backend_servers_json, 'BackendServers')

        try:
            response = self.get_status('RemoveBackendServers', params)
            changed = True
            results.append("Removal of Backend Server(s) successful.")
            current_backend_servers = response['BackendServers']['BackendServer']

        except Exception as ex:
            error_code = str(ex.error_code)
            msg = str(ex.message)
            results.append("Failed to remove backend servers with error code " + error_code +
                           " and message: " + msg)

        return changed, current_backend_servers, results

    def set_backend_servers(self, load_balancer_id=None, backend_servers=None):
        """
        Set Backend Server to Load Balancer
        :type load_balancer_id: str
        :param load_balancer_id: ID of server load balancer
        :type backend_servers: list
        :param backend_servers: list of dictionary containing server Id and weight of  backend server instance
        :return: return changed status, current_backend_servers and message with descriptive information
        """

        params = {}
        results = []
        current_backend_servers = []
        changed = False

        self.build_list_params(params, load_balancer_id, 'LoadBalancerId')

        backend_servers_list = []

        for backend_server in backend_servers:
            backend_servers_list.append({"ServerId": backend_server['server_id'],
                                         "Weight": str(backend_server['weight'])})

        backend_servers_json = json.dumps(backend_servers_list)
        self.build_list_params(params, backend_servers_json, 'BackendServers')

        try:
            response = self.get_status('SetBackendServers', params)
            changed = True
            results.append("Updated Backend Server(s) successfully.")
            current_backend_servers = response['BackendServers']['BackendServer']

        except Exception as ex:
            error_code = str(ex.error_code)
            msg = str(ex.message)
            results.append("Failed to update backend servers with error code " + error_code +
                           " and message: " + msg)

        return changed, current_backend_servers, results

    def describe_backend_servers_health_status(self, load_balancer_id=None, port=None):
        """
        :type load_balancer_id: str
        :param load_balancer_id: ID of server load balancer
        :type port: list
        :param port: list of Ports used by the Server Load Balancer instance frontend for health check
        :return: return backend servers with health status and message with descriptive information
        """
        params = {}
        results = []
        backend_servers_health_status = []

        self.build_list_params(params, load_balancer_id, 'LoadBalancerId')

        if port:
            self.build_list_params(params, port, 'ListenerPort')

        try:
            response = self.get_status('DescribeHealthStatus', params)

            if len(response['BackendServers']['BackendServer']) > 0:
                backend_servers_health_status.extend(response['BackendServers']['BackendServer'])
            elif port:
                results.append("No backend servers available for port " + str(port))
            else:
                results.append("No listener or backend servers available for slb id " + load_balancer_id)

        except Exception as ex:
            error_code = str(ex.error_code)
            msg = str(ex.message)
            if port:
                results.append("Failed to retrieve backend servers' health status for port " + str(port) +
                               " with error code " + error_code + " and message '" + msg + "'")
            else:
                results.append("Failed to retrieve backend servers' health status for slb id " + load_balancer_id +
                               " with error code " + error_code + " and message '" + msg + "'")

        return backend_servers_health_status, results

    def set_load_balancer_status(self, load_balancer_id, load_balancer_status):
        """
        Method added to Set Load Balancer Status
        :type load_balancer_id: List
        :param load_balancer_id: ID of server load balancer
        :type load_balancer_status: String
        :param load_balancer_status: Status of an Server Load Balancer instance
            Value：inactive | active
        :return: return name of the operating interface, which is
            specified in the system
        """

        params = {}
        results = []
        changed = False
       
        self.build_list_params(params, load_balancer_id, 'LoadBalancerId')        
        
        self.build_list_params(params, load_balancer_status, 'LoadBalancerStatus')
        
        try:
            result = self.get_status('SetLoadBalancerStatus', params)
            results.append(result)
            changed = True
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results

    def set_load_balancer_name(self, load_balancer_id, load_balancer_name):
        """
        Set name or alias to the ServerLoadBalancer
        Method added to Set Load Balancer Name
        :type load_balancer_id: str
        :param load_balancer_id: ID of a Server Load Balancer instance
        :type load_balancer_id: str
        :param load_balancer_name: Displayed name of an Server Load Balancer instance. When the parameter is not
         specified, an instance name is allocated by the system by default.
        :return: returns the request_id of request
        """
        results = []
        changed = False
        params = {}
        self.build_list_params(params, load_balancer_id, 'LoadBalancerId')
        self.build_list_params(params, load_balancer_name, 'LoadBalancerName')
        try:
            result = self.get_status('SetLoadBalancerName', params)
            results.append(result)
            changed = True
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results

    def delete_load_balancer(self, slb_id):
        """
        Method added to Delete Load Balancer
        :type slb_id: string
        :param slb_id: Id of the server load balancer
        :return: Return status of Operation
        """
        params = {}
        results = []
        changed = False

        self.build_list_params(params, slb_id, 'LoadBalancerId')
        try:
            results = self.get_status('DeleteLoadBalancer', params)
            changed = True
            
        except Exception as ex:
            error_code = ex.error_code
            msg = ex.message            
            results.append("Error Code: " + error_code)
            results.append("Message: " + msg)

        return changed, results    
    
    def modify_slb_internet_spec(self, load_balancer_id, internet_charge_type=None, bandwidth=None):
        """
        Modify internet specifications of existing LoadBalancer, like internet_charge_type or bandwidth
        :type load_balancer_id: str
        :param load_balancer_id: The unique ID of an Server Load Balancer instance

        :type internet_charge_type: str
        :param internet_charge_type: Charging mode for the public network instance

        :type bandwidth: str
        :param bandwidth: Bandwidth peak of the public network instance charged per fixed bandwidth

        :return: returns the request_id of request
        """

        params = {}
        results = []
        changed = False

        self.build_list_params(params, load_balancer_id, 'LoadBalancerId')

        if internet_charge_type:
            self.build_list_params(params, internet_charge_type, 'InternetChargeType')

        if bandwidth:
            self.build_list_params(params, bandwidth, 'Bandwidth')

        try:
            response = self.get_status('ModifyLoadBalancerInternetSpec', params)
            changed = True
            results.append(response)
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results

    def describe_load_balancer_attribute(self, load_balancer_id):
        """
        Describe attributes of Load Balancer
        :type load_balancer_id: string
        :param load_balancer_id: id of the load balancer
        :return: load balance attributes in dictionary format if found else None
        """

        params = {}

        self.build_list_params(params, load_balancer_id, 'LoadBalancerId')

        try:
            response = self.get_status('DescribeLoadBalancerAttribute', params)
        except Exception as ex:
            return None

        return response

    def create_vserver_group(self, load_balancer_id, vserver_group_name, backend_servers):
        """
        Create a VServer Group
        :type load_balancer_id: string
        :param load_balancer_id: Virtual server LoadBalancer Id
        :type vserver_group_name: string
        :param vserver_group_name: Virtual server group name, where you can rename it
        :param backend_servers:
          - List of hash/dictionary of backend servers to add in
          - '[{"key":"value", "key":"value"}]', keys allowed:
            - server_id (required:true, description: Unique id of Instance to add)
            - port (required:true, description: The back-end server using the port, range: 1-65535)
            - weight (required:true; default: 100, description: Weight of the backend server, in the range of 1-100 )

        :return: it return public parameters with ,VServerGroupId The unique identifier for the virtual server.
                 and BackendServers Array format, list of back-end servers in the virtual server group.
                 and VServerGroupName	String	Virtual server group name
                 The structure of the elements in the list is detailed in BackendServer
        """
        params = {}
        results = []
        backend_serverlist = []       
        changed = False
        if load_balancer_id:
            self.build_list_params(params, load_balancer_id, 'LoadBalancerId')
        if vserver_group_name:
            self.build_list_params(params, vserver_group_name, 'VServerGroupName')
        if backend_servers:
            for servers in backend_servers:
                backend_serverlist.append({
                        'ServerId': servers['server_id'],
                        'Port': servers['port'],
                        'Weight': servers['weight']
                    })
                                    
        self.build_list_params(params, json.dumps(backend_serverlist), 'BackendServers')
                
        try:     
            results = self.get_status('CreateVServerGroup', params)           
            changed = True
        except Exception as ex:
            error_code = str(ex.error_code)
            error_msg = str(ex.message)
            results.append("Error Code:" + error_code + " ,Error Message:" + error_msg)

        return changed, results

    def set_vservergroup_attribute(self, vserver_group_id, vserver_group_name=None, backend_servers=None):
        """
        Set a virtual server group, change the name for an existing virtual server group, or change the  weight of
            an existing back-end server.
        :type vserver_group_id: string
        :param vserver_group_id: The virtual server group ID
        :type vserver_group_name: string
        :param vserver_group_name: Virtual server group name, where you can rename it
        :param backend_servers:  - List of hash/dictionary of backend servers to add in
          - '[{"key":"value", "key":"value"}]', keys allowed:
            - server_id (required:true, description: Unique id of Instance to add)
            - port (required:true, description: The back-end server using the port, range: 1-65535)
            - weight (required:true; default: 100, description: Weight of the backend server, in the range of 1-100 )
        :return: VServerGroupId	String	The unique identifier for the virtual server group
                 VServerGroupName	String	Virtual server group name
                 BackendServers	List	Array format, returns the operation is successful,
                 the virtual server group all the back-end server list,
                 the list of elements in the structure see BackendServer
        """
        params = {}
        results = []
        backend_serverlist = []
        changed = False      
        if vserver_group_id:
            self.build_list_params(params, vserver_group_id, 'VServerGroupId')
        if vserver_group_name:
            self.build_list_params(params, vserver_group_name, 'VServerGroupName')
        if backend_servers:
            for servers in backend_servers:
                backend_serverlist.append({
                    'ServerId': servers['server_id'],
                    'Port': servers['port'],
                    'Weight': servers['weight']
                })
        
            self.build_list_params(params, json.dumps(backend_serverlist), 'BackendServers')
        try:
            results = self.get_status('SetVServerGroupAttribute', params)
            if results:
                for result in results["BackendServers"]["BackendServer"]:
                    for backend_server in backend_servers:
                        if result["ServerId"] == backend_server["server_id"] and \
                                        result["Port"] == backend_server["port"]:
                            changed = True                        
        except Exception as ex:
            error_code = str(ex.error_code)
            error_msg = str(ex.message)
            results.append("Error Code:" + error_code + " ,Error Message:" + error_msg)

        return changed, results

    def add_vservergroup_backend_server(self, vserver_group_id, backend_servers):
        """
        Add a back-end server in a virtual server group, add a set of back-end servers to a specific virtual server
            group in the SLB,
        and return a list of back-end servers in that virtual server group.
        :type vserver_group_id: string
        :param vserver_group_id: The unique identifier for the virtual server group
        :param backend_servers:  - List of hash/dictionary of backend servers to add in
          - '[{"key":"value", "key":"value"}]', keys allowed:
            - server_id (required:true, description: Unique id of Instance to add)
            - port (required:true, description: The back-end server using the port, range: 1-65535)
            - weight (required:true; default: 100, description: Weight of the backend server, in the range of 1-100 )
        :return: VServerGroupId	String	The unique identifier for the virtual server group
                 BackendServers	List	Array format, returns the operation is successful,
                 the virtual server group all the back-end server list, the list of elements in the structure see
                 BackendServer
        """
        params = {}
        changed = False
        results = []
        backend_serverlist = []       
        if vserver_group_id:
            self.build_list_params(params, vserver_group_id, 'VServerGroupId')
        if backend_servers:
            for servers in backend_servers:
                backend_serverlist.append({'ServerId': servers['server_id'],
                                           'Port': servers['port'],
                                           'Weight': servers['weight']})
                
            self.build_list_params(params, json.dumps(backend_serverlist), 'BackendServers')
        try:
            results = self.get_status('AddVServerGroupBackendServers', params)           
            changed = True
        except Exception as ex:
            error_code = str(ex.error_code)
            error_msg = str(ex.message)
            results.append("Error Code:" + error_code + " ,Error Message:" + error_msg)

        return changed, results

    def remove_vserver_group_backend_server(self, vserver_group_id, purge_backend_servers):
        """        
        Method to Remove Vserver Group Backend server
        :type vserver_group_id: string
        :param vserver_group_id: Virtual server group Id
        :type purge_backend_servers:  List of hash/dictionary
        :param purge_backend_servers:
          - List of hash/dictionary of backend servers to remove
          - '[{"key":"value", "key":"value"}]', keys allowed:
            - server_id (required:true, description: Unique id of Instance to remove)
            - port (required:true, description: The back-end server using the port, range: 1-65535)          
                               
        :return: it return public parameters with ,VServerGroupId The unique identifier for the virtual server.
                 and BackendServers Array format, list of back-end servers in the virtual server group.
                 The structure of the elements in the list is detailed in BackendServer
        """
        
        params = {}
        results = []
        changed = False
        backend_serverlist = []
           
        if vserver_group_id:
            self.build_list_params(params, vserver_group_id, 'VServerGroupId')
        if purge_backend_servers:
            for servers in purge_backend_servers:
                backend_serverlist.append({'ServerId': servers['server_id'], 'Port': servers['port']})
            self.build_list_params(params, json.dumps(backend_serverlist), 'BackendServers')

        try: 
            results = self.get_status('RemoveVServerGroupBackendServers', params)
            changed = True 
        except Exception as ex:
            error_code = str(ex.error_code)
            error_msg = str(ex.message)
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results

    def modify_vserver_group_backend_server(self, vserver_group_id, purge_backend_servers, backend_servers):
        '''
        Modify VServer Group Backend Server
        :type vserver_group_id: string
        :param vserver_group_id:Virtual server group Id
        :type purge_backend_servers:  List of hash/dictionary
        :param purge_backend_servers:
          - List of hash/dictionary of backend servers to add in
          - '[{"key":"value", "key":"value"}]', keys allowed:
            - server_id (required:true, description: Unique id of Instance to add)
            - port (required:true, description: The back-end server using the port, range: 1-65535)
        :type backend_servers:  List of hash/dictionary
        :param backend_servers:
          - List of hash/dictionary of backend servers to add in
          - '[{"key":"value", "key":"value"}]', keys allowed:
            - server_id (required:true, description: Unique id of Instance to add)
            - port (required:true, description: The back-end server using the port, range: 1-65535)
            - weight (required:true; default: 100, description: Weight of the backend server, in the range of 1-100 )

        :return: Change the virtual back-end servers in the server group, in a particular SLB virtual server
                 group by adding / deleting the back-end server to replace the current server group, the group returned
                 to the virtual server back-end server list.
        '''
        params = {}
        results = []
        set_results = []
        add_results = []
        set_server_attribute = []
        add_backend_server = []
        delete_backend_servers = []
        delete_backend_servers_id = []
        filter_backend_servers_id = []
        final_backend_servers_id = []
        changed = False
        serverid_param = 'server_id'
        try: 

            self.build_list_params(params, vserver_group_id, 'VServerGroupId')
            result_all_backend_servers = self.get_status('DescribeVServerGroupAttribute', params)
            all_backend_servers = result_all_backend_servers['BackendServers']['BackendServer']
            if all_backend_servers:
                for purge_backend_server in purge_backend_servers:                    
                    for all_backend_server in all_backend_servers:
                        if purge_backend_server[serverid_param] in all_backend_server['ServerId']:
                            delete_backend_servers.append(purge_backend_server)
                            delete_backend_servers_id.append(purge_backend_server[serverid_param])
                            break
                
                for backend_server in backend_servers:
                    flag = False
                    for all_backend_server in all_backend_servers:
                        if backend_server[serverid_param] == all_backend_server['ServerId'] \
                                and backend_server[serverid_param] not in delete_backend_servers_id:
                            set_server_attribute.append(backend_server)
                            flag = True
                            break                       
                    if not flag:   
                        add_backend_server.append(backend_server)
            else:
                 add_backend_server.append(backend_servers[0])             
           
            if delete_backend_servers:
               changed, result = self.remove_vserver_group_backend_server(vserver_group_id, delete_backend_servers)
            
            if set_server_attribute:
                changed, set_results = self.set_vservergroup_attribute(vserver_group_id, vserver_group_name=None,
                                                                       backend_servers=set_server_attribute)
    
            if add_backend_server:
                changed, add_results = self.add_vservergroup_backend_server(vserver_group_id, add_backend_server)
            changed = True
            
            if set_results:
                results = set_results
                filter_backend_servers_id = set_results['BackendServers']['BackendServer']
            
            if add_results:
                results = add_results
                filter_backend_servers_id += add_results['BackendServers']['BackendServer']

            for backend_server in backend_servers:
                flag = False
                for filter_backend_servers in filter_backend_servers_id:
                    if filter_backend_servers["ServerId"] == backend_server[serverid_param] and\
                                    filter_backend_servers["Port"] == backend_server["port"] and not flag:
                        flag = True
                        final_backend_servers_id.append(filter_backend_servers)
            if final_backend_servers_id:
                results['BackendServers']['BackendServer'] = final_backend_servers_id
            if 'VServerGroupName' in results:
                del results['VServerGroupName']
        except Exception as ex:
            error_code = str(ex.error_code)
            error_msg = str(ex.message)
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results

    def describe_vservergroup_attributes(self, vserver_group_id):
        """
        describe vserver group attributes 
        and return a list of back-end servers in that virtual server group.
        :type vserver_group_id: string
        :param vserver_group_id: The unique identifier for the virtual server group       
        :return: VServerGroupId	String	The unique identifier for the virtual server group
                 BackendServers	List	Array format, returns the operation is successful,
                 the virtual server group all the back-end server list, the list of elements in the structure
                 see BackendServer
        """
        params = {}
        changed = False
        results = []      
        if vserver_group_id:
            self.build_list_params(params, vserver_group_id, 'VServerGroupId')  
        try:
            results = self.get_status('DescribeVServerGroupAttribute', params)           
            changed = True
        except Exception as ex:
            error_code = str(ex.error_code)
            error_msg = str(ex.message)
            results.append("Error Code:" + error_code + " ,Error Message:" + error_msg)

        return changed, results

    def describe_vservergroup_backendserver(self, vserver_group_id, backend_servers):
        """
        describe vserver group backend server      
        :type vserver_group_id: string
        :param vserver_group_id: The unique identifier for the virtual server group
        :type backend_servers:  List of hash/dictionary
        :param backend_servers:
          - List of hash/dictionary of backend servers to add in
          - '[{"key":"value", "key":"value"}]', keys allowed:
            - server_id (required:true, description: Unique id of Instance to add)
            - port (required:true, description: The back-end server using the port, range: 1-65535)
            - weight (required:true; default: 100, description: Weight of the backend server, in the range of 1-100 )
        :return: VServerGroupId	String	The unique identifier for the virtual server group
                 BackendServers	List	Array format, returns the operation is successful,
                 the virtual server group all the back-end server list, the list of elements in the structure
                 see BackendServer
        """
        changed_flag = True
        results = []   
        try:
            changed_vsg, result_vsgs = self.describe_vservergroup_attributes(vserver_group_id=vserver_group_id)
            if result_vsgs and changed_vsg:
                for backend_server in backend_servers:
                    final_check =False
                    for result_vsg in result_vsgs["BackendServers"]["BackendServer"]:
                        if backend_server["server_id"] == result_vsg["ServerId"] and backend_server["port"] \
                                == result_vsg["Port"]:
                            final_check = True  
                            break              
                    if not final_check: 
                        results.append(str(backend_server["server_id"])+" ECS with "
                                                                        "the port "+str(backend_server["port"])+" not "
                                                                        "match to perform operation")
                        changed_flag = False
            else:
                changed_flag = False
                results = result_vsgs
        except Exception as ex:
            error_code = str(ex.error_code)
            error_msg = str(ex.message)
            results.append("Error Code:" + error_code + " ,Error Message:" + error_msg)

        return changed_flag, results

    def describe_vservergroup_backendserver_to_add(self, vserver_group_id, backend_servers):
        """
        describe vserver group backend server to add
        and return a list of back-end servers in that virtual server group.
        :type vserver_group_id: string
        :param vserver_group_id: The unique identifier for the virtual server group
        :type backend_servers:  List of hash/dictionary
        :param backend_servers:
          - List of hash/dictionary of backend servers to add in
          - '[{"key":"value", "key":"value"}]', keys allowed:
            - server_id (required:true, description: Unique id of Instance to add)
            - port (required:true, description: The back-end server using the port, range: 1-65535)
            - weight (required:true; default: 100, description: Weight of the backend server, in the range of 1-100 )
        :return: VServerGroupId	String	The unique identifier for the virtual server group
                 BackendServers	List	Array format, returns the operation is successful,
                 the virtual server group all the back-end server list, the list of elements in the structure
                 see BackendServer
        """
        changed_flag = True
        results = []   
        try:
            changed_vsg, result_vsgs = self.describe_vservergroup_attributes(vserver_group_id=vserver_group_id)
            if result_vsgs and changed_vsg:
                for backend_server in backend_servers:
                    changed_flag = True
                    for result_vsg in result_vsgs["BackendServers"]["BackendServer"]:
                        if (str(backend_server["server_id"]) == str(result_vsg["ServerId"])) \
                                and (str(backend_server["port"]) == str(result_vsg["Port"])):
                            changed_flag = False
                            break

                    if changed_flag is False:
                        results.append(str(backend_server["server_id"])+" "
                                                                        "ECS with port "+str(backend_server["port"])+" "
                                                                        "is already present")
            else:
                changed_flag =False
                results = result_vsgs
        except Exception as ex:
            error_code = str(ex.error_code)
            error_msg = str(ex.message)
            results.append("Error Code:" + error_code + " ,Error Message:" + error_msg)

        return changed_flag, results

    def delete_vserver_group(self, load_balancer_id, vserver_group_id):
        """
        Delete specified by VServerGroupId virtual server group.
        :type vserver_group_id: string
        :param vserver_group_id:The unique identifier for the virtual server group
        :type load_balancer_id: string
        :param load_balancer_id: Uniquely identifies for the load balancer
        :return: This method returns success message string and boolean value, if virtual
         server group deleted successfully
        """
        params = {}
        results = []
        flag = False
        changed = False
        try:
            self.build_list_params(params, load_balancer_id, 'LoadBalancerId')
            vserver_groups = self.get_status('DescribeVServerGroups', params)
            for vserver_group in vserver_groups[u'VServerGroups'][u'VServerGroup']:
                if str(vserver_group[u'VServerGroupId']) == vserver_group_id:
                    flag = True
                    break
            if flag is True:
                params = {}
                self.build_list_params(params, vserver_group_id, 'VServerGroupId')
                response = self.get_status('DeleteVServerGroup', params)
                changed = True
                results.append({"Success Message": "VServer Group Deleted Successfully"})
            else:
                results.append({"Error Message": "Server Group Not Exist"})
        except Exception as ex:
            error_code = ex.error_code
            error_msg = ex.message
            results.append({"Error Code": error_code, "Error Message": error_msg})

        return changed, results
    # endregion



