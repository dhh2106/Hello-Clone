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
import time
import httplib2
import base64


def sign_gae(b):
    from oauth2client.contrib import appengine
    creds = appengine.AppAssertionCredentials([])
    return creds.service_account_email, creds.sign_blob(b)[1]


def sign_from_file(filename, b):
    from oauth2client.service_account import ServiceAccountCredentials
    creds = ServiceAccountCredentials.from_json_keyfile_name(filename)
    return creds.service_account_email, creds.sign_blob(b)[1]


def sign_gce(b):
    from googleapiclient.discovery import build
    from oauth2client.contrib import gce

    creds = gce.AppAssertionCredentials()
    iam = build('iam', 'v1', credentials=creds)
    resp = iam.projects().serviceAccounts().signBlob(
        name="projects/{project_id}/serviceAccounts/{sa_email}".format(
            project_id=_project_id_from_metadata(),
            sa_email=creds.service_account_email
        ),
        body={
            "bytesToSign": b
        }
    ).execute()
    return creds.service_account_email, resp['signature']


def _project_id_from_metadata():
    http_request = httplib2.Http().request
    response, content = http_request(
        ('http://metadata.google.internal/computeMetadata/'
         'v1/project/project-id'),
        headers={'Metadata-Flavor': 'Google'}
    )
    return None, content.decode('utf-8')


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
        str(expiration),
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
        for header, value in sorted(custom_headers.items())
    ])


def main(url=None,
         duration=3600,
         content_file=None,
         content_type='',
         method='GET',
         credentials=None,
         **kwargs):
    parsed = urllib.parse.urlparse(url)

    if content_file:
        with open(content_file, 'r') as content_f:
            content = content_f.read()
    else:
        content = ''

    expiration = int(time.time() + duration)

    signature_string = make_signature_string(
        method,
        make_resource_string(parsed),
        expiration,
        extension_header_string=make_header_string(**headers),
        content=content,
        content_type=content_type
    )

    print(signature_string)

    if credentials == 'gae':
        email, signed_string = sign_gae(signature_string)
    elif credentials == 'gce':
        email, signed_string = sign_gce(signature_string)
    else:
        email, signed_string = sign_from_file(credentials, signature_string)

    sig_bytes = base64.b64encode(signed_string)

    query_params = urllib.parse.parse_qs(parsed.query)
    query_params.update(
        GoogleAccessId=email,
        Expires=expiration,
        Signature=sig_bytes
    )
    url_tuple = list(parsed)
    url_tuple[4] = urllib.parse.urlencode(query_params, doseq=True)

    print(urllib.parse.urlunparse(url_tuple))


if __name__ == '__main__':
    parser = argparse.ArgumentParser('Arguments for signing a url')
    parser.add_argument('url', help='A fully qualified url')
    parser.add_argument(
        '--method',
        default='GET',
        help='HTTP Method for the request'
    )
    parser.add_argument(
        '--credentials',
        required=True,
        help="Either the string \"gae\" the string \"gce\" or a filename"
    )
    parser.add_argument('--content-file', help='File name for request content')
    parser.add_argument(
        '--content-type',
        default='',
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
