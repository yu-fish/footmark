"""
Represents an VRouter object
"""
from footmark.ecs.ecsobject import *


class VRouterList(TaggedECSObject):
    def __init__(self, connection=None):
        super(VRouterList, self).__init__(connection)
        self.tags = {}

    def __repr__(self):
        return 'VRouterList'
        #return 'VRouterList:%s' % self.id

    #def __getattr__(self, name):
    #    if name == 'id':
    #        return self.v_router_id
        
    #    raise AttributeError

    def __setattr__(self, name, value):
        #if name == 'id':
        #    self.vrouter_id = value
#        if name == 'description':
#            self.vdescription = value
#        if name == 'region_id':
#            self.vregion_id = value
#        if name == 'creation_time':
#            self.vcreation_time = value
#        if name == 'vpc_id':
#            self.vvpc_id = value
#        if name == 'v_router_name':
#            self.vrouter_name = value
##RouteTableIds
#        if name == 'tags' and value:
#            v = {}
#            for tag in value['tag']:
#                v[tag.get('TagKey')] = tag.get('TagValue', None)
#            value = v
        super(TaggedECSObject, self).__setattr__(name, value)
