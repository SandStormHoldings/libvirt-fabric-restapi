# -*- coding: utf-8 -*-
"""
filedesc: default url mapping
"""
from routes import Mapper
from config import DEBUG
from noodles.utils.maputils import urlmap, include
from routes.route import Route
import os


def get_map():
    " This function returns mapper object for dispatcher "
    m = Mapper()
    # Add routes here
    urlmap(m, [
        ('/', 'controllers#index'),
        ('/dns', 'controllers#dns'),
        ('/hosts', 'controllers#hosts'),
        ('/groups', 'controllers#groups'),
        ('/images', 'controllers#images'),
    ])
    cn = 'controllers'
    m.connect('/sleep/{seconds:[\d]+}',controller=cn,action='slp')
    m.connect("/dns/{domain}",controller=cn,action='new_dns_record',conditions=dict(method=['POST']))
    m.connect("/dns/{domain}",controller=cn,action='del_dns_record',conditions=dict(method=['DELETE']))
    m.connect('/sessions',controller=cn,action='sessions',conditions=dict(method=['GET']))
    m.connect('/sessions/{host}/{node}/{name}',controller=cn,action='kill_session',conditions=dict(method=['DELETE']))
    m.connect("/nodes",controller=cn,action='nodes',conditions=dict(method=['GET']))
    m.connect("/nodes",controller=cn,action='new_node',conditions=dict(method=['POST']))
    m.connect('/nodes/{host}',controller=cn,action='nodes',conditions=dict(method=['GET']))
    m.connect('/nodes/{host}',controller=cn,action='new_node',conditions=dict(method=['POST']))
    m.connect('/nodes/{host}/{node}',controller=cn,action='node',conditions=dict(method=['GET']))
    m.connect('/nodes/{host}/{node}',controller=cn,action='update_node',conditions=dict(method=['PUT']))
    m.connect('/nodes/{host}/{node}',controller=cn,action='delete_node',conditions=dict(method=['DELETE']))
    m.connect('/nodes/{host}/{node}',controller=cn,action='migrate_node',conditions=dict(method=['POST']))
    m.connect('/nodes/{host}/{node}/disk',controller=cn,action='enlarge_disk',conditions=dict(method=['PUT']))

    m.connect('/nodes/{host}/{node}/memory',controller=cn,action='memory',conditions=dict(method=['GET']))
    m.connect('/nodes/{host}/{node}/memory',controller=cn,action='memory_update',conditions=dict(method=['PUT']))

    m.connect('/nodes/{host}/{node}/pubkey',controller=cn,action='host_auth_list',conditions=dict(method=['GET']))
    m.connect('/nodes/{host}/{node}/pubkey',controller=cn,action='host_auth_add',conditions=dict(method=['POST']))

    m.connect('/openvpn/',controller=cn,action='openvpn_list',conditions=dict(method=['GET']))
    m.connect('/openvpn/',controller=cn,action='openvpn_add',conditions=dict(method=['POST']))
    return m
