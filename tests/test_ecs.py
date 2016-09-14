import footmark
import footmark.ecs
def build_conn(region_id, **connect_args):
    return footmark.ecs.connect_to_region(region_id, **connect_args)

def operate_instance(region_id, **connect_args):
    conn = build_conn(region_id, **connect_args)

    filters = {}
    instance_ids = ["XXXXXXX"]
    tag_key = 'xz_test'
    tag_value = '1.20'
    filters['tag:' + tag_key] = tag_value

    get_all_instances = conn.get_all_instances(instance_ids=instance_ids, filters=filters)
    for inst in get_all_instances:
        print 'state:', inst.state
        if inst.state == 'stopped':
            inst.start()
        if inst.status == 'running':
            inst.stop()
        print 'state:', inst.state

def run_instances(region_id, **connect_args):
    conn = build_conn(region_id, **connect_args)

    run_params = dict(zone_id='cn-shenzhen-a',
                      image_id='centos6u5_64_40G_cloudinit_20160427.raw',
                      instance_type='ecs.s1.small',
                      group_id='XXXXXXXXXX',
                      instance_name='test_footmark',
                      count=2)

    instances = conn.run_instances(**run_params)
    for inst in instances:
        print inst.id

def delete_instances(region_id, **connect_args):
    conn = build_conn(region_id, **connect_args)
    instance_ids = ["XXXXXXX"]
    force = False
    get_all_instances = conn.get_all_instances(instance_ids=instance_ids)
    for inst in get_all_instances:
        inst.terminate(force=force)

def main():
    connect_args = dict(acs_access_key_id='XXXXXXXXXXXX',
                        acs_secret_access_key='XXXXXXXXXXXXXXXX')
    region_id = 'cn-shenzhen'
    # test start stop restart instance
    operate_instance(region_id, **connect_args)

    # test delete instance
    delete_instances(region_id, **connect_args)

    # test create instance
    # run_instances(region_id, **connect_args)

main()