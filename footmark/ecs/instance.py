"""
Represents an ECS Instance
"""
from footmark.ecs.ecsobject import *


class Instance(TaggedECSObject):
    """
    Represents an instance.
    """

    def __init__(self, connection=None):
        super(Instance, self).__init__(connection)
        self.tags = {}

    def __repr__(self):
        return 'Instance:%s' % self.id

    def __getattr__(self, name):
        if name == 'id':
            return self.instance_id
        if name == 'state':
            return self.status
        if name in ('private_ip', 'inner_ip', 'inner_ip_address'):
            return self.inner_ip_address
        if name in ('public_ip', 'assign_public_ip'):
            return self.public_ip_address
        if name == 'vpc_private_ip':
            return self.private_ip_address
        if name in ('vpc_vswitch_id', 'vswitch_id', 'vpc_subnet_id', 'subnet_id'):
            return self.v_switch_id
        if name == 'eip' and self.eip_address:
            return self.eip_address.get('ip_address', None)
        if name in ('group_id', 'security_group_id'):
            return self.security_group_id
        if name in ('group_name', 'security_group_name') and self.security_groups:
            return self.security_groups[0].security_group_name
        if name == 'groups':
            return self.security_groups
        raise AttributeError

    def __setattr__(self, name, value):
        if name == 'id':
            self.instance_id = value
        if name == 'status':
            value = value.lower()
        if name == 'state':
            self.status = value
        if name in ('public_ip_address', 'inner_ip_address', 'private_ip_address'):
            if isinstance(value, dict) and value['ip_address']:
                value = value['ip_address'][0]
        if name in ('private_ip', 'inner_ip'):
            self.inner_ip_address = value
        if name in ('public_ip', 'assign_public_ip'):
            self.public_ip_address = value
        if name == 'vpc_private_ip':
            self.private_ip_address = value
        if name in ('vpc_vswitch_id', 'vswitch_id', 'vpc_subnet_id', 'subnet_id'):
            self.v_switch_id = value
        if name == 'eip' and self.eip_address:
            self.eip_address['ip_address'] = value
        if name in ('group_id', 'security_group_id'):
            if isinstance(value, list) and value:
                value = value[0]
        if name in ('group_name', 'security_group_name') and self.security_groups:
            self.security_groups[0].security_group_name = value
        if name == 'groups':
            self.security_groups = value
        if name == 'tags' and value:
            v = {}
            for tag in value['tag']:
                v[tag.get('TagKey')] = tag.get('TagValue', None)
            value = v
        super(TaggedECSObject, self).__setattr__(name, value)

    def _update(self, updated):
        self.__dict__.update(updated.__dict__)

    def update(self, validate=False):
        """
        Update the instance's state information by making a call to fetch
        the current instance attributes from the service.

        :type validate: bool
        :param validate: By default, if ECS returns no data about the
                         instance the update method returns quietly.  If
                         the validate param is True, however, it will
                         raise a ValueError exception if no data is
                         returned from ECS.
        """
        rs = self.connection.get_all_instances([self.id])
        if len(rs) > 0:
            for r in rs:
                if r.id == self.id:
                    self._update(r)
        elif validate:
            raise ValueError('%s is not a valid Instance ID' % self.id)
        return self.state

    def start(self):
        """
        Start the instance.
        """
        rs = self.connection.start_instances([self.id])
        # if len(rs) > 0:
        #     self._update(rs[0])

    def stop(self, force=False):
        """
        Stop the instance

        :type force: bool
        :param force: Forces the instance to stop

        :rtype: list
        :return: A list of the instances stopped
        """
        rs = self.connection.stop_instances([self.id], force)
        # if len(rs) > 0:
        #     self._update(rs[0])

    def reboot(self, force=False):
        """
        Restart the instance.

        :type force: bool
        :param force: Forces the instance to stop
        """
        return self.connection.reboot_instances([self.id], force)

    def terminate(self, force=False):
        """
        Terminate the instance

        :type force: bool
        :param force: Forces the instance to terminate
        """
        rs = self.connection.terminate_instances([self.id], force)
        # if len(rs) > 0:
        #     self._update(rs[0])
