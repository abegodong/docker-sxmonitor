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

"""Nagios plugin to check the number of dead nodes of an SX Cluster."""

import argparse
import logging
import shlex

import nagiosplugin
import sxclient


__version__ = '0.2.0'

_log = logging.getLogger('nagiosplugin')


class DeadNodes(nagiosplugin.Resource):

    def __init__(
            self, cluster_name, key_path, cluster_address=None, is_secure=True,
            verify_ssl=True, port=None,
            timeout=sxclient.controller.DEFAULT_REQUEST_TIMEOUT
    ):
        cluster = sxclient.Cluster(
            cluster_name, cluster_address, is_secure=is_secure,
            verify_ssl_cert=verify_ssl, port=port
        )
        user_data = sxclient.UserData.from_key_path(key_path)
        self.sx = sxclient.SXController(
            cluster, user_data, request_timeout=timeout
        )

    def probe(self):
        try:
            nodes = self.sx.listNodes.json_call()['nodeList']
        except sxclient.exceptions.SXClusterNonFatalError as exc:
            self._raise_connection_error(exc)

        node_num = len(nodes)
        _log.info('Number of nodes: %i' % node_num)

        if node_num >= 3:
            node_states = self.get_node_states()
            dead_num = sum(
                1 for node in node_states.itervalues()
                if node['state'] != 'alive'
            )
        else:
            dead_num = 0

        yield nagiosplugin.Metric('number of dead nodes', dead_num, min=0)
        yield nagiosplugin.Metric('number of nodes', node_num, min=0)

    def _raise_connection_error(
            self, exc, msg='Cannot connect to the cluster: connection refused'
    ):
        if 'connection refused' in str(exc).lower():
            err_msg = msg
            raise ConnectionError(err_msg)
        else:
            raise exc

    def get_node_states(self):
        _log.debug('Querying the cluster for the Raft status.')
        try:
            cluster_status = self.sx.getClusterStatus.json_call()
        except sxclient.exceptions.SXClusterNonFatalError as exc:
            self._raise_connection_error(exc)
        try:
            role = cluster_status['raftStatus']['role']
        except KeyError as exc:
            if 'raftStatus' in str(exc):
                err_msg = (
                    "Failed to get information about cluster's Raft status; "
                    "cluster version may be too low."
                )
                raise KeyError(err_msg)
            else:
                raise

        if role != 'leader':
            _log.debug('Queried node is not a Raft leader.')
            uuid_to_addr = dict(
                (node['nodeUUID'], node['nodeAddress']) for node in
                cluster_status['clusterStatus']['distributionModels'][0]
            )
            leader_uuid = cluster_status['raftStatus']['leader']
            try:
                leader_addr = uuid_to_addr[leader_uuid]
            except KeyError:
                err_msg = 'Cannot find the location of the Raft leader'
                raise ConnectionError(err_msg)

            _log.debug("Querying the Raft leader '%s' directly." % leader_addr)
            try:
                cluster_status = (
                    self.sx.getClusterStatus.call_on_node(leader_addr).json()
                )
            except sxclient.exceptions.SXClusterNonFatalError as exc:
                err_msg = 'Cannot connect to the Raft leader'
                self._raise_connection_error(exc, err_msg)

        node_states = cluster_status['raftStatus']['nodeStates']
        return node_states


class NodesContext(nagiosplugin.Context):

    def __init__(
            self, name, fmt_metric="{name} is {valueunit}",
            result_cls=nagiosplugin.Result
    ):
        super(NodesContext, self).__init__(name, fmt_metric, result_cls)

    def evaluate(self, metric, resource):
        if metric.value >= 3:
            return self.result_cls(nagiosplugin.state.Ok, metric=metric)
        else:
            hint = (
                'you need at least 3 nodes to enable Raft consensus algorithm'
            )
            return self.result_cls(
                nagiosplugin.state.Warn, hint=hint, metric=metric
            )


class ConnectionError(Exception):
    '''
    Should be raised in case of a connection problem or unavailability
    of a cluster or one of its nodes.
    '''


@nagiosplugin.guarded
def main():
    args = parse_arguments()
    check = nagiosplugin.Check(
        DeadNodes(
            args.hostname, args.key_path, args.ip_addresses, args.is_secure,
            args.verify, args.port, timeout=args.timeout
        ),
        nagiosplugin.ScalarContext(
            'number of dead nodes', args.warning, args.critical
        ),
        NodesContext('number of nodes')
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
        help='return warning if number of dead nodes is outside RANGE'
    )
    parser.add_argument(
        '-c', '--critical', metavar='RANGE', default='',
        help='return critical if number of dead nodes is outside RANGE'
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
