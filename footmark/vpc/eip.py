"""
Represents an VPC Security Group
"""
from footmark.vpc.vpcobject import *


class Eip(TaggedVPCObject):
    def __init__(self, connection=None, owner_id=None,
                 name=None, description=None, id=None):
        super(Vpc, self).__init__(connection)
        self.tags = {}

    def __repr__(self):
        return 'eip:%s' % self.id

    def __getattr__(self, name):
        if name == 'id':
            return self.allocation_id
        if name == 'ip':
            return self.eip_address
        raise AttributeError

    def __setattr__(self, name, value):
        if name == 'id':
            self.allocation_id = value
        if name == 'ip':
            self.eip_address = value
        if name == 'tags' and value:
            v = {}
            for tag in value['tag']:
                v[tag.get('TagKey')] = tag.get('TagValue', None)
            value = v
        super(TaggedVPCObject, self).__setattr__(name, value)
    
    def bind(self, instance_id):
        """
        bind eip
        """
        return self.connection.bind_eip(self.id, instance_id)

    def unbind(self, instance_id):
        """
        unbind eip
        """
        return self.connection.unbind_eip(self, self.id, instance_id)
    
    def release(self):
        """
        release eip
        """
        return self.connection.release_eip(self.id)
    
    def modify(self, bandwidth):
        """
        modify eip
        """
        return self.connection.modifying_eip_attributes(self, self.id, bandwidth)
    
    
   
