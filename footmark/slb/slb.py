"""
Represents an SLB Security Group
"""
from footmark.slb.slbobject import TaggedSLBObject


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
        raise AttributeError

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
