# Copyright 2015 Google, Inc.
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

"""Contains an example of using Google Cloud Storage Signed URLs."""

from six.moves import urllib
import argparse
from oauth2client.client import GoogleCredentials
import time


def sign_string(credentials, s):
    # TODO add IAM workaround, will raise NotImplementedError in GCE
    return credentials.sign_blob(s)


def make_signature_string(method,
                          resource,
                          expiration,
                          extension_header_string='',
                          content='',
                          content_type=''):
    """Creates the signature string for signing according to GCS docs."""
    return "\n".join([
        method,
        content,
        content_type,
        expiration,
        extension_header_string,
        resource
    ])


def make_resource_string(parsed):
    query_string = ''
    if parsed.query:
        queries = urllib.parse.parse_qs(parsed.query)
        for key in ['prefix', 'max-keys', 'marker', 'delimiter']:
            queries.remove(key)

        query_string = '?{qs}'.format(qs=urllib.urlencode(queries))

    return '{path}{query_string}'.format(
        path=parsed.path,
        query_string=query_string,
    )


def make_header_string(**custom_headers):
    return '\n'.join([
        ':'.join([header.lower(), value.lower()])
        for header, value in custom_headers.iteritems().sort()
    ])


def main(url=None,
         duration=3600,
         content_file=None,
         content_type='',
         method='GET',
         **kwargs):
    parsed = urllib.parse.urlparse(url)

    credentials = GoogleCredentials.get_application_default()

    if content_file:
        with open(content_file, 'r') as content_f:
            content = content_f.read()
    else:
        content = ''

    expiration = time.time() + duration

    signature_string = make_signature_string(
        method,
        make_resource_string(parsed),
        expiration,
        extension_header_stirng=make_header_string(**headers),
        content=content,
        content_type=content_type
    )

    signed_string = sign_string(credentials, signature_string)

    query_params = urllib.parse.parse_qs(parsed.query)
    query_params.update(
        GoogleAccessId=credentials.email,
        Expires=expiration,
        Signature=signed_string
    )
    new_query_string = urllib.parse.urlencode(query_params)
    parsed[3] = new_query_string

    print(urllib.parse.urlunparse(parsed))


if __name__ == '__main__':
    parser = argparse.ArgumentParser('Arguments for signing a url')
    parser.add_argument('url', required=True, help='A fully qualified url')
    parser.add_argument(
        '--method',
        default='GET',
        help='HTTP Method for the request'
    )
    parser.add_argument('--content-file', help='File name for request content')
    parser.add_argument(
        '--content-type',
        help='MIME type for the content'
    )
    parser.add_argument(
        '--headers',
        nargs='*',
        help="A list of headers of the form \"header1:value1 header2:value2\""
    )
    parser.add_argument(
        '--duration',
        type=int,
        default=3600,
        help="Duration in seconds of the signed url"
    )

    parsed = vars(parser.parse_args())

    headers = dict()
    if parsed.get('headers'):
        headers = dict(
            header_str.split(":") for header_str in parsed['headers']
        )
        parsed.update(headers)
    main(**parsed)
