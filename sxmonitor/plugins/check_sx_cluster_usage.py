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

"""Nagios plugin to check SX Cluster space usage."""

import argparse
import logging
import shlex

import nagiosplugin
import sxclient


__version__ = '0.1.0'

_log = logging.getLogger('nagiosplugin')


class ClusterUsage(nagiosplugin.Resource):

    def __init__(
            self, cluster_name, key_path, cluster_address=None, is_secure=True,
            verify_ssl=True, port=None
    ):
        cluster = sxclient.Cluster(
            cluster_name, cluster_address, is_secure=is_secure,
            verify_ssl_cert=verify_ssl, port=port
        )
        user_data = sxclient.UserData.from_key_path(key_path)
        self.sx = sxclient.SXController(cluster, user_data)

    def probe(self):
        node_info = self.get_node_info()

        virtual_usage = self.calculate_virtual_usage(node_info)
        filesystem_usages = self.calculate_filesystem_usages(node_info)

        yield nagiosplugin.Metric(
            'Virtual usage', virtual_usage, uom='%', context='usage'
        )
        for node, usage in filesystem_usages.iteritems():
            yield nagiosplugin.Metric(
                'Node %s filesystem usage' % node, usage, uom='%',
                context='usage'
            )

    def get_node_info(self):
        _log.debug('Getting node list from the cluster')
        try:
            nodes = self.sx.listNodes.json_call()['nodeList']
        except sxclient.exceptions.SXClusterNonFatalError as exc:
            self._raise_connection_error(exc)

        capacities = self.get_node_capacities()

        node_info = dict()
        for node in nodes:
            _log.info('Getting node information for node %s' % node)
            try:
                data = self.sx.getNodeStatus.json_call(node)
            except sxclient.exceptions.SXClusterNonFatalError as exc:
                msg = 'Cannot connect to node %s: connection refused' % node
                self._raise_connection_error(exc, msg)

            node_info[data['address']] = dict(
                fsAvailBlocks=data['fsAvailBlocks'],
                fsTotalBlocks=data['fsTotalBlocks'],
                storageAllocated=data['storageAllocated'],
                capacity=capacities[data['address']]
            )
        return node_info

    def get_node_capacities(self):
        _log.info('Getting node capacities from the cluster')
        try:
            cluster_info = self.sx.getClusterStatus.json_call()
        except sxclient.exceptions.SXClusterNonFatalError as exc:
            self._raise_connection_error(exc)

        capacities = dict(
            (item['nodeAddress'], item['nodeCapacity']) for item in
            cluster_info['clusterStatus']['distributionModels'][0]
        )
        return capacities

    def _raise_connection_error(
            self, exc, msg='Cannot connect to the cluster: connection refused'
    ):
        if 'connection refused' in str(exc).lower():
            err_msg = msg
            raise ConnectionError(err_msg)
        else:
            raise exc

    def calculate_virtual_usage(self, node_info):
        virtual_size = sum(
            elt['capacity'] for elt in node_info.itervalues()
        )
        _log.debug(
            'Total virtual size (total capacity) is %i' % virtual_size
        )

        virtual_used = sum(
            elt['storageAllocated'] for elt in node_info.itervalues()
        )
        _log.debug(
            'Used virtual size (total allocated storage) is %i' % virtual_used
        )

        try:
            virtual_usage = float(virtual_used) / virtual_size * 100
        except ZeroDivisionError:
            virtual_usage = 0
        return virtual_usage

    def calculate_filesystem_usages(self, node_info):
        usages = dict()

        for node, data in node_info.iteritems():
            available_blocks = data['fsAvailBlocks']
            total_blocks = data['fsTotalBlocks']
            _log.debug(
                'Total blocks on node\'s %s filesystem: %i' %
                (node, total_blocks)
            )
            used_blocks = total_blocks - available_blocks
            _log.debug(
                'Used blocks on node\'s %s filesystem: %i' %
                (node, used_blocks)
            )

            try:
                usages[node] = float(used_blocks) / total_blocks * 100
            except ZeroDivisionError:
                usages[node] = 0

        return usages


class ConnectionError(Exception):
    '''
    Should be raised in case of a connection problem or unavailability
    of a cluster or one of its nodes.
    '''


@nagiosplugin.guarded
def main():
    args = parse_arguments()
    check = nagiosplugin.Check(
        ClusterUsage(
            args.hostname, args.key_path, args.ip_addresses, args.is_secure,
            args.verify, args.port
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
        '-i', '--ip-addresses', metavar='ADDRESS', dest='ip_addresses',
        default=None, type=comma_separated_list,
        help='comma-separated list of SX hosts (IP addresses)'
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
        help='return warning if percentage cluster usage is outside RANGE'
    )
    parser.add_argument(
        '-c', '--critical', metavar='RANGE', default='',
        help='return critical if percentage cluster usage is outside RANGE'
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


def comma_separated_list(string):
    lexer = shlex.shlex(string, posix=True)
    lexer.whitespace = ','
    lexer.whitespace_split = True
    elts = [token.decode('utf-8') for token in lexer]
    return elts


if __name__ == '__main__':
    main()
