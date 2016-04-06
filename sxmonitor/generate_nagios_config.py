#!/usr/bin/env python
'''
Generate Nagios configuration files with SX-specific host, commands and
services.
'''

import argparse
import errno
import os
import shutil
import sys

import sxclient


TEMPLATE_DIR = 'templates'

DIRECTORIES = [
    'objects',
    'conf.d',
    'private'
]

ORDINARY_TEMPLATES = [
    'objects/contacts.cfg.template',
    'private/resource.cfg.template'
]

STATICS = [
    'objects/commands.cfg',
    'objects/timeperiods.cfg',
    'objects/templates.cfg',
    'cgi.cfg',
    'nagios.cfg'
]

PERMISSIONS = {
    '': 0o755,
    'private/resource.cfg': 0o640}


class ConfigGenerator(object):

    def __init__(self, fields, output_dir, verify_ssl=True, port=None):
        self.fields = fields
        self.verify_ssl = verify_ssl
        self.port = port

        curdir = os.getcwd()
        abs_output_dir = os.path.join(curdir, output_dir)
        abs_output_dir = os.path.normpath(abs_output_dir)
        self.output_dir = abs_output_dir

    def run(self):
        change_to_script_dir()
        self.create_directories()
        self.copy_static_files()
        self.generate_from_templates()
        self.generate_sx_cfg()
        self.set_permissions()

    def create_directories(self):
        for dir in DIRECTORIES:
            path = os.path.join(self.output_dir, dir)
            try:
                os.makedirs(path)
            except OSError as err:
                if err.errno == errno.EEXIST:
                    pass
                else:
                    raise

    def copy_static_files(self):
        for static_file in STATICS:
            source = os.path.join(TEMPLATE_DIR, static_file)
            destination = os.path.join(self.output_dir, static_file)
            shutil.copy2(source, destination)

    def generate_from_templates(self):
        for template_name in ORDINARY_TEMPLATES:
            source = os.path.join(TEMPLATE_DIR, template_name)
            destination_name = template_name.replace('.template', '')
            destination = os.path.join(self.output_dir, destination_name)
            with open(source, 'r') as fi, open(destination, 'w') as fo:
                template = fi.read()
                config = template.format(**self.fields)
                fo.write(config)
            shutil.copystat(source, destination)

        self.generate_sx_cfg()

    def generate_sx_cfg(self):
        nodelist = get_node_list(
            fields['host_address'], fields['sx_key_path'],
            verify_ssl=self.verify_ssl, port=self.port
        )

        node_template_source = os.path.join(
            TEMPLATE_DIR, 'objects/_sx_node_hosts.cfg.template'
        )
        ping_template_source = os.path.join(
            TEMPLATE_DIR, 'objects/_sx_ping_service.cfg.template'
        )
        template_source = os.path.join(
            TEMPLATE_DIR, 'objects/sx.cfg.template'
        )

        destination = os.path.join(
            self.output_dir, 'objects/sx.cfg'
        )

        with open(ping_template_source, 'r') as fi:
            ping_template = fi.read()
        with open(node_template_source, 'r') as fi:
            node_template = fi.read()
        with open(template_source, 'r') as fi:
            template = fi.read()

        node_configs = []
        ping_configs = []
        for ip in nodelist:
            tmp_fields = {'node_address': ip}
            tmp_fields.update(fields)
            conf = node_template.format(**tmp_fields)
            node_configs.append(conf)
            conf = ping_template.format(**tmp_fields)
            ping_configs.append(conf)
        node_config = '\n'.join(node_configs)
        ping_config = '\n'.join(ping_configs)

        sx_fields = {'node_hosts': node_config, 'node_services': ping_config}
        sx_fields.update(fields)
        config = template.format(**sx_fields)

        with open(destination, 'w') as fo:
            fo.write(config)

        shutil.copystat(template_source, destination)

    def set_permissions(self):
        permissions = {
            os.path.join(self.output_dir, key): value
            for key, value in PERMISSIONS.iteritems()
        }
        permissions = {
            os.path.normpath(key): value
            for key, value in permissions.iteritems()
        }

        for dir, subdirs, files in os.walk(self.output_dir):
            perms = permissions.get(dir, 0o750)
            os.chmod(dir, perms)
            for fl in files:
                path = os.path.join(dir, fl)
                perms = permissions.get(path, 0o644)
                os.chmod(path, perms)


def get_node_list(host_address, key_path, verify_ssl=True, port=None):
    cluster = sxclient.Cluster(
        host_address, verify_ssl_cert=verify_ssl, port=port
    )
    user_data = sxclient.UserData.from_key_path(key_path)
    sx = sxclient.SXController(cluster, user_data)
    nodelist = sx.listNodes.json_call()['nodeList']
    return nodelist


def change_to_script_dir():
    script_path = sys.path[0]
    os.chdir(script_path)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--host-address', required=True, metavar='ADDRESS',
        help='address of the SX Cluster'
    )
    parser.add_argument(
        '--key-path', required=True, metavar='PATH',
        help="path to the file with user's authentication key"
    )
    parser.add_argument(
        '--notify-address', required=True, metavar='EMAIL',
        help="email address of nagiosadmin (for email notifications)"
    )
    parser.add_argument(
        '--port', type=int, default=None, metavar='PORT',
        help="cluster destination port"
    )
    parser.add_argument(
        '--no-ssl-verification', dest='verify_ssl', action='store_false',
        default=True,
        help="don't verify SSL certificates"
    )
    parser.add_argument(
        'output_dir', metavar='OUTPUT_DIR',
        help="output directory for Nagios configuration"
    )
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    fields = {
        'host_address': args.host_address,
        'sx_key_path': args.key_path,
        'notify_address': args.notify_address,
        'ssl_verf_switch': '--no-verify' if args.verify_ssl is False else '',
        'port_switch': '--port %i' % args.port if args.port else ''
    }
    generator = ConfigGenerator(
        fields, args.output_dir, args.verify_ssl, args.port
    )
    generator.run()
