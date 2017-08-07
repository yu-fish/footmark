"""
Represents an SLB Security Group
"""
from footmark.slb.slbobject import TaggedSLBObject

class VServerGroup(TaggedSLBObject):
    def __init__(self, connection=None, owner_id=None,
                 name=None, description=None, id=None):
        super(VServerGroup, self).__init__(connection)
        self.tags = {}

    def __repr__(self):
        return 'VServerGroup:%s' % self.id

    def __getattr__(self, name):
        if name == 'id':
            return self.vserver_group_id
        if name == 'name':
             return self.vserver_group_name

    def __setattr__(self, name, value):
        if name == 'id':
            self.vserver_group_id = value
        if name == 'name':
             self.vserver_group_name = value
        super(TaggedSLBObject, self).__setattr__(name, value)
    
    def set_attribute(self, vserver_group_name='', backend_servers = []):
        '''
        set attribute
        '''
        return self.connection.set_vserver_group_attribute(self.vserver_group_id, vserver_group_name, backend_servers)
    
    def add_backend_servers(self, backend_servers):
        '''
        add backend servers
        '''
        return self.connection.add_vserver_group_backend_servers(self.vserver_group_id, backend_servers)
    
    def remove_backend_servers(self, backend_servers):
        '''
        remove backend servers
        '''
        return self.connection.remove_vserver_group_backend_servers(self.vserver_group_id, backend_servers)
    
    def modify_backend_servers(self, old_backend_servers = [], new_backend_servers = []):
        '''
        modify backend servers
        '''
        return self.connection.modify_vserver_group_backend_servers(self.vserver_group_id, old_backend_servers, new_backend_servers)
    
    def delete(self):
        '''
        delete vserver group 
        '''
        return self.connection.delete_vserver_group(self.vserver_group_id)
    
    def describe_attribute(self):
        '''
        describe vserver group attribute 
        '''
        return self.connection.describe_vserver_group_attribute(self.vserver_group_id)


class LoadBalancer(TaggedSLBObject):
    def __init__(self, connection=None, owner_id=None,
                 name=None, description=None, id=None):
        super(LoadBalancer, self).__init__(connection)
        self.tags = {}

    def __repr__(self):
        return 'LoadBalancer:%s' % self.id

    def __getattr__(self, name):
        if name == 'id':
            return self.load_balancer_id
        if name == 'name':
             return self.load_balancer_name

    def __setattr__(self, name, value):
        if name == 'id':
            self.load_balancer_id = value
        if name == 'name':
             self.load_balancer_name = value
        super(TaggedSLBObject, self).__setattr__(name, value)
    
    def set_status(self, load_balancer_status):
        '''
        set load balancer status
        '''
        return self.connection.set_load_balancer_status(self.load_balancer_id, load_balancer_status)
    
    def modify_name(self, new_name):
        '''
        modify load balancer name
        '''
        return self.connection.set_load_balancer_name(self.load_balancer_id, new_name)
    
    def modify_spec(self, internet_charge_type=None, bandwidth=None):
        '''
        modify load balancer name
        '''
        return self.connection.modify_slb_internet_spec(self.load_balancer_id, internet_charge_type=internet_charge_type, bandwidth=bandwidth)
    
    def delete(self):
        '''
        delete load balance 
        '''
        return self.connection.delete_load_balancer(self.load_balancer_id)
    
class BackendServer(TaggedSLBObject):
    def __init__(self, connection=None, owner_id=None,
                 name=None, description=None, id=None):
        super(BackendServer, self).__init__(connection)
        self.tags = {}

    def __repr__(self):
        return 'BackendServer:%s' % self.id

    def __getattr__(self, name):
        if name in ['id', 'instance_id']:
            return self.server_id
        if name in ['status', 'health_status']:
            return self.server_health_status
        raise AttributeError('There is no ')

    def __setattr__(self, name, value):
        if name in ['id', 'instance_id']:
            self.server_id = value
        if name in ['status', 'health_status']:
            self.server_health_status = value
        super(TaggedSLBObject, self).__setattr__(name, value)
