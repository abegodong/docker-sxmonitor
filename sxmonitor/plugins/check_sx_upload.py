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

"""Nagios plugin to check upload-download latency of an SX Cluster."""

import argparse
import io
import logging
import random
import shlex
import time

import nagiosplugin
import sxclient


__version__ = '0.1.0'

_log = logging.getLogger('nagiosplugin')

CONTENT_LENGTH = 4096
SUFFIX_LENGTH = 8
SUFFIX_CHARACTERS = (
    'abcdefghijklmnopqrstuvwxyz'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    '0123456789'
)


class UploadLatency(nagiosplugin.Resource):

    def __init__(
            self, remote_path, cluster_name, key_path, cluster_address=None,
            is_secure=True, verify_ssl=True, port=None, delete_after=False
    ):
        cluster = sxclient.Cluster(
            cluster_name, cluster_address, is_secure=is_secure,
            verify_ssl_cert=verify_ssl, port=port
        )
        user_data = sxclient.UserData.from_key_path(key_path)
        self.sx = sxclient.SXController(cluster, user_data)
        remote_path = remote_path.decode('utf-8')
        self.volume, self.filename = self.split_remote_path(remote_path)
        self.delete_after = delete_after

    def split_remote_path(self, path):
        if '/' not in path:
            raise ValueError('Invalid remote path: %s' % path)
        volume, filename = path.split('/', 1)
        if not volume or not filename:
            raise ValueError('Invalid remote path: %s' % path)
        return volume, filename

    def probe(self):
        content = self.generate_random_content()
        stream = io.BytesIO(content)

        _log.debug('Volume used for testing: %s' % self.volume)
        _log.debug('Test file name: %s' % self.filename)

        time_start = time.time()
        _log.info('Started uploading at %f' % time_start)

        try:
            uploader = sxclient.SXFileUploader(self.sx)
            uploader.upload_stream(
                self.volume, CONTENT_LENGTH, self.filename, stream
            )
            downloader = sxclient.SXFileCat(self.sx)
            downloaded_content = downloader.get_file_content(
                self.volume, self.filename
            )
        except sxclient.exceptions.SXClusterNonFatalError as exc:
            self._raise_connection_error(exc)

        time_end = time.time()
        _log.info('Ended downloading at %f' % time_end)
        latency = time_end - time_start

        if self.delete_after:
            try:
                self.sx.deleteFile.call(self.volume, self.filename)
            except sxclient.exceptions.SXClusterNonFatalError as exc:
                self._raise_connection_error(exc)
            _log.debug('Test file deleted')
        else:
            _log.debug('Test file was not deleted')

        yield nagiosplugin.Metric(
            'latency', latency, min=0, uom='s'
        )
        yield nagiosplugin.Metric(
            'file contents identical', content == downloaded_content
        )

    def _raise_connection_error(
            self, exc, msg='Cannot connect to the cluster: connection refused'
    ):
        if 'connection refused' in str(exc).lower():
            err_msg = msg
            raise ConnectionError(err_msg)
        else:
            raise exc

    def generate_random_content(self):
        content = bytearray(
            random.getrandbits(8) for byte in range(CONTENT_LENGTH)
        )
        return content


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
        UploadLatency(
            args.remote_path, args.hostname, args.key_path, args.ip_addresses,
            args.is_secure, args.verify, args.port,
            delete_after=args.delete_after
        ),
        nagiosplugin.ScalarContext('latency', args.warning, args.critical),
        BooleanContext('file contents identical')
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
        '--remote-path', required=True, dest='remote_path',
        help='path for the test file to be created by the plugin; '
        'should contain volume name as its first component'
    )
    parser.add_argument(
        '--delete-after', action='store_true', default=False,
        dest='delete_after',
        help='delete the test file after the upload; '
        'it is not deleted by default'
    )

    parser.add_argument(
        '-w', '--warning', metavar='RANGE', default='',
        help='return warning if upload-download latency is outside RANGE'
    )
    parser.add_argument(
        '-c', '--critical', metavar='RANGE', default='',
        help='return critical if upload-download latency is outside RANGE'
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
