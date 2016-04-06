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

"""Nagios plugin to check volume space usage on an SX Cluster."""

import argparse
import logging
import shlex

import nagiosplugin
import sxclient


__version__ = '0.1.0'

_log = logging.getLogger('nagiosplugin')


class VolumeUsage(nagiosplugin.Resource):

    def __init__(
            self, volumes, cluster_name, key_path, cluster_address=None,
            is_secure=True, verify_ssl=True, port=None
    ):
        cluster = sxclient.Cluster(
            cluster_name, cluster_address, is_secure=is_secure,
            verify_ssl_cert=verify_ssl, port=port
        )
        user_data = sxclient.UserData.from_key_path(key_path)
        self.sx = sxclient.SXController(cluster, user_data)
        self.volumes = volumes

        if len(self.volumes) == 1 and 'ALL' in self.volumes:
            self.check_all_volumes = True
        else:
            self.check_all_volumes = False

    def probe(self):
        _log.debug('Getting volume information from the cluster')
        try:
            resp_json = self.sx.listVolumes.json_call()
        except sxclient.exceptions.SXClusterNonFatalError as exc:
            self._raise_connection_error(exc)

        usages = dict()
        if self.check_all_volumes:
            volumes = resp_json['volumeList'].keys()
        else:
            volumes = self.volumes

        _log.info(
            'Number of checked volumes: %i' % len(volumes)
        )
        _log.debug(
            'These volumes will be checked: ' +
            ', '.join(repr(vol) for vol in volumes)
        )

        for volume in volumes:
            try:
                usages[volume] = self.calculate_usage(volume, resp_json)
            except KeyError:
                raise LookupError(
                    "No such volume: '%s'" % volume
                )

        for volume, usage in usages.iteritems():
            label = '%r usage' % volume
            label = label.replace("'", '"')
            yield nagiosplugin.Metric(
                label, usage, uom='%',
                context='usage'
            )

    def _raise_connection_error(
            self, exc, msg='Cannot connect to the cluster: connection refused'
    ):
        if 'connection refused' in str(exc).lower():
            err_msg = msg
            raise ConnectionError(err_msg)
        else:
            raise exc

    def calculate_usage(self, volume, json):
        volume_data = json['volumeList'][volume]
        _log.debug('Calculating %r usage' % volume)
        used_size = volume_data['usedSize']
        size_bytes = volume_data['sizeBytes']
        try:
            usage = float(used_size) / size_bytes * 100
        except ZeroDivisionError:
            usage = 0
        return usage


class UsageSummary(nagiosplugin.Summary):

    def ok(self, results):
        if len(results) == 1:
            return super(UsageSummary, self).ok(results)
        else:
            metric_tuples = [
                (result.metric.value, result.metric) for result in results
            ]
            max_value, max_metric = max(metric_tuples)
            return 'The largest volume usage is %s' % str(max_metric)


class ConnectionError(Exception):
    '''
    Should be raised in case of a connection problem or unavailability
    of a cluster or one of its nodes.
    '''


@nagiosplugin.guarded
def main():
    args = parse_arguments()
    check = nagiosplugin.Check(
        VolumeUsage(
            args.vols, args.hostname, args.key_path, args.ip_addresses,
            args.is_secure, args.verify, args.port
        ),
        nagiosplugin.ScalarContext('usage', args.warning, args.critical),
        UsageSummary()
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
        '--vols', metavar='VOLUMES', required=True, type=comma_separated_list,
        help='comma-separated list of volumes to check; '
        'if %(metavar)s is ALL, all volumes will be checked'
    )

    parser.add_argument(
        '-w', '--warning', metavar='RANGE', default='',
        help=(
            'return warning if percentage usage of any volume is outside RANGE'
        )
    )
    parser.add_argument(
        '-c', '--critical', metavar='RANGE', default='',
        help=(
            'return critical if percentage usage of any volume is outside '
            'RANGE'
        )
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
