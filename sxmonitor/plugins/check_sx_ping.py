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

"""Nagios plugin to check response latency of an SX Cluster node."""

import argparse
import logging
import time

import nagiosplugin
import sxclient


__version__ = '0.1.0'

_log = logging.getLogger('nagiosplugin')


class ResponseLatency(nagiosplugin.Resource):

    def __init__(
            self, cluster_name, key_path, node_address, is_secure=True,
            verify_ssl=True, port=None
    ):
        cluster = sxclient.Cluster(
            cluster_name, node_address, is_secure=is_secure,
            verify_ssl_cert=verify_ssl, port=port
        )
        user_data = sxclient.UserData.from_key_path(key_path)
        self.sx = sxclient.SXController(cluster, user_data)
        self.node_address = node_address

    def probe(self):

        time_start = time.time()
        _log.info('Time before querying node: %f' % time_start)

        try:
            self.sx.getNodeStatus.call(self.node_address)
            node_responded = True
        except sxclient.exceptions.SXClusterNonFatalError as exc:
            if 'connection refused' in str(exc).lower():
                node_responded = False
                log_msg = ''.join([
                    'Node cannot be reached because of ',
                    exc.__class__.__name__,
                    ': ',
                    str(exc)
                ])
                _log.info(log_msg)
            else:
                raise

        time_end = time.time()
        _log.info('Time after querying node: %f' % time_end)

        latency = time_end - time_start

        yield nagiosplugin.Metric('latency', latency, min=0)
        yield nagiosplugin.Metric('node responded', node_responded)


class BooleanContext(nagiosplugin.Context):

    def __init__(
            self, name, fmt_metric="'{name}' is {valueunit}",
            result_cls=nagiosplugin.Result
    ):
        super(BooleanContext, self).__init__(name, fmt_metric, result_cls)

    def evaluate(self, metric, resource):
        if metric.value:
            return self.result_cls(nagiosplugin.state.Ok, metric=metric)
        else:
            return self.result_cls(nagiosplugin.state.Critical, metric=metric)


class ConnectionError(Exception):
    '''
    Should be raised in case of a connection problem or unavailability
    of a cluster or one of its nodes.
    '''


@nagiosplugin.guarded
def main():
    args = parse_arguments()
    check = nagiosplugin.Check(
        ResponseLatency(
            args.hostname, args.key_path, args.node_address, args.is_secure,
            args.verify, args.port
        ),
        nagiosplugin.ScalarContext('latency', args.warning, args.critical),
        BooleanContext('node responded')
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
        help='return warning if response latency is outside RANGE'
    )
    parser.add_argument(
        '-c', '--critical', metavar='RANGE', default='',
        help='return critical if response latency is outside RANGE'
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
