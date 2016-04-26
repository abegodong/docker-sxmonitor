#!/usr/bin/env python
# Copyright 2012-2016 Skylable Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Nagios plugin to check SX Cluster node's space usage."""

import argparse
import logging

import nagiosplugin
import sxclient


__version__ = '0.2.0'

_log = logging.getLogger('nagiosplugin')


class NodeUsage(nagiosplugin.Resource):

    def __init__(
            self, cluster_name, key_path, node_address, is_secure=True,
            verify_ssl=True, port=None,
            timeout=sxclient.controller.DEFAULT_REQUEST_TIMEOUT
    ):
        cluster = sxclient.Cluster(
            cluster_name, node_address, is_secure=is_secure,
            verify_ssl_cert=verify_ssl, port=port
        )
        user_data = sxclient.UserData.from_key_path(key_path)
        self.sx = sxclient.SXController(
            cluster, user_data, request_timeout=timeout
        )
        self.node_address = node_address

    def probe(self):
        avail, total = self.get_node_info(self.node_address)

        usage = self.calculate_filesystem_usage(avail, total)

        yield nagiosplugin.Metric(
            'Node %s filesystem usage' % self.node_address, usage, uom='%',
            context='usage'
        )

    def get_node_info(self, node):
        _log.info('Getting node information for node %s' % node)
        try:
            data = self.sx.getNodeStatus.json_call(node)
        except sxclient.exceptions.SXClusterNonFatalError as exc:
            msg = 'Cannot connect to node %s: connection refused' % node
            self._raise_connection_error(exc, msg)

        return data['fsAvailBlocks'], data['fsTotalBlocks']

    def _raise_connection_error(
            self, exc, msg='Cannot connect to the cluster: connection refused'
    ):
        if 'connection refused' in str(exc).lower():
            err_msg = msg
            raise ConnectionError(err_msg)
        else:
            raise exc

    def calculate_filesystem_usage(self, avail, total):
        _log.debug(
            'Total blocks on node\'s filesystem: %i' % total
        )
        used = total - avail
        _log.debug(
            'Used blocks on node\'s filesystem: %i' % used
        )

        try:
            usage = float(used) / total * 100
        except ZeroDivisionError:
            usage = 0

        return usage


class ConnectionError(Exception):
    '''
    Should be raised in case of a connection problem or unavailability
    of a cluster or one of its nodes.
    '''


@nagiosplugin.guarded
def main():
    args = parse_arguments()
    check = nagiosplugin.Check(
        NodeUsage(
            args.hostname, args.key_path, args.node_address, args.is_secure,
            args.verify, args.port, timeout=args.timeout
        ),
        nagiosplugin.ScalarContext('usage', args.warning, args.critical)
    )
    check.main(verbose=args.verbose, timeout=args.timeout)


def parse_arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '-V', '--version', action='version',
        version=' '.join(['%(prog)s', __version__])
    )
    parser.add_argument(
        '-H', '--hostname', metavar='NAME', required=True,
        help='name of the cluster'
    )
    parser.add_argument(
        '-n', '--node-address', metavar='ADDRESS', dest='node_address',
        required=True, help='IP address of the node to check'
    )
    parser.add_argument(
        '-p', '--port', type=int, default=None,
        help='cluster destination port'
    )
    parser.add_argument(
        '-k', '--key-path', required=True, dest='key_path',
        help="path to the file with user's authentication key"
    )
    parser.add_argument(
        '--no-ssl', dest='is_secure', action='store_false', default=True,
        help="disable secure communication"
    )
    parser.add_argument(
        '--no-verify', dest='verify', action='store_false', default=True,
        help="don't verify the SSL certificate"
    )

    parser.add_argument(
        '-w', '--warning', metavar='RANGE', default='',
        help='return warning if percentage node usage is outside RANGE'
    )
    parser.add_argument(
        '-c', '--critical', metavar='RANGE', default='',
        help='return critical if percentage node usage is outside RANGE'
    )
    parser.add_argument(
        '-v', '--verbose', action='count', default=0,
        help='increase output verbosity (use up to 3 times)'
    )
    parser.add_argument(
        '-t', '--timeout', type=int, metavar='TIMEOUT', default=10,
        help='set plugin timeout to %(metavar)s; '
        'it is %(default)s by default; '
        'set to 0 or less for no timeout'
    )

    return parser.parse_args()


if __name__ == '__main__':
    main()
