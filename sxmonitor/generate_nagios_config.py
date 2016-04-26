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

import jinja2
import sxclient


TEMPLATE_DIR = 'templates'

DIRECTORIES = [
    'objects',
    'conf.d',
    'private'
]

TEMPLATES = [
    'objects/sx.cfg.j2',
    'objects/contacts.cfg.j2',
    'private/resource.cfg.j2'
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

        curdir = os.getcwd()
        abs_output_dir = os.path.join(curdir, output_dir)
        abs_output_dir = os.path.normpath(abs_output_dir)
        self.output_dir = abs_output_dir

    def run(self):
        change_to_script_dir()
        self.create_directories()
        self.copy_static_files()
        self.generate_from_templates()
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
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR))

        for template_name in TEMPLATES:
            source = os.path.join(TEMPLATE_DIR, template_name)
            destination_name = template_name.replace('.j2', '')
            destination = os.path.join(self.output_dir, destination_name)

            template = env.get_template(template_name)
            config = template.render(**self.fields)
            with open(destination, 'w') as fo:
                fo.write(config)
            shutil.copystat(source, destination)

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


def prepare_fields(args):
    nodelist = get_node_list(
        args.host_address, args.key_path,
        verify_ssl=args.verify_ssl, port=args.port
    )
    nodelist.sort()
    fields = {
        'host_address': args.host_address,
        'node_addresses': nodelist,
        'sx_key_path': args.key_path,
        'notify_address': args.notify_address,
        'ssl_verf_switch': '--no-verify' if args.verify_ssl is False else '',
        'port_switch': '--port %i' % args.port if args.port else ''
    }
    return fields


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
    fields = prepare_fields(args)
    generator = ConfigGenerator(
        fields, args.output_dir, args.verify_ssl, args.port
    )
    generator.run()
