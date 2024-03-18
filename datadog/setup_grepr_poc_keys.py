#!/bin/env python
#
# This script is used to create a limited-access service account for
# running the Grepr POC. It will do the following:
# 1. Create a custom role with only log reading permissions
# 2. Create a data access filter limited to the filter specified by the user
# 3. Limit the custom role log access using the data access filter
# 4. Create a service account with the custom role
# 5. Create an App key for the service account
# 6. Create an API key for the service account
# 7. Write the App key and API key to a file

import argparse
import os
import json
import time
import typing
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from email.message import Message


class Response(typing.NamedTuple):
    body: str
    headers: Message
    status: int
    error_count: int = 0

    def json(self) -> typing.Any:
        """
        Decode body's JSON.

        Returns:
            Pythonic representation of the JSON object
        """
        return json.loads(self.body)


def request(
        url: str,
        data: dict = None,
        params: dict = None,
        headers: dict = None,
        method: str = "GET",
        data_as_json: bool = True,
        error_count: int = 0,
) -> Response:
    if not url.casefold().startswith("http"):
        raise urllib.error.URLError("Incorrect and possibly insecure protocol in url")
    method = method.upper()
    request_data = None
    headers = headers or {}
    data = data or {}
    params = params or {}
    headers = {"Accept": "application/json", **headers}

    if method == "GET":
        params = {**params, **data}
        data = None

    if params:
        url += "?" + urllib.parse.urlencode(params, doseq=True, safe="/")

    if data:
        if data_as_json:
            request_data = json.dumps(data).encode()
            headers["Content-Type"] = "application/json; charset=UTF-8"
        else:
            request_data = urllib.parse.urlencode(data).encode()

    httprequest = urllib.request.Request(
        url, data=request_data, headers=headers, method=method
    )

    try:
        with urllib.request.urlopen(httprequest) as httpresponse:
            response = Response(
                headers=httpresponse.headers,
                status=httpresponse.status,
                body=httpresponse.read().decode(
                    httpresponse.headers.get_content_charset("utf-8")
                ),
            )
    except urllib.error.HTTPError as e:
        response = Response(
            body=str(e.read(), "utf-8"),
            headers=e.headers,
            status=e.code,
            error_count=error_count + 1,
        )

    return response


class DatadogClient:
    def __init__(self, api_key, app_key, site='datadoghq.com'):
        self.api_key = api_key
        self.app_key = app_key
        self.site = site

    def _exec_request(self, method, path, body=None):
        if path.startswith('/'):
            path = path[1:]
        resp = request(
            url=f'https://api.{self.site}/{path}',
            data=body,
            headers={
                'DD-API-KEY': self.api_key,
                'DD-APPLICATION-KEY': self.app_key,
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            method=method,
        )
        if resp.status < 200 or resp.status >= 300:
            raise ValueError(f'Error {resp.status} executing request: {resp.body}.')

        return resp

    def list_permissions(self):
        resp = self._exec_request(
            method='GET',
            path='/api/v2/permissions'
        )

        perms = resp.json()['data']

        return {perm['attributes']['name']: perm['id'] for perm in perms}

    def create_custom_role(self, role_name, permission_ids):
        resp = self._exec_request(
            method='POST',
            path='/api/v2/roles',
            body={
                'data': {
                    'type': 'roles',
                    'attributes': {
                        'name': role_name,
                    },
                    'relationships': {
                        'permissions': {
                            'data': [
                                {
                                    'type': 'permissions',
                                    'id': perm_id
                                } for perm_id in permission_ids
                            ]
                        }
                    }
                }
            }
        )
        return resp.json()['data']['id']

    def delete_custom_role(self, role_id):
        try:
            self._exec_request(
                method='DELETE',
                path=f'/api/v2/roles/{role_id}'
            )
        except ValueError as e:
            print(f'Error deleting custom role: {e}')

    def create_restriction_query(self, query: str):
        resp = self._exec_request(
            method='POST',
            path='/api/v2/logs/config/restriction_queries',
            body={
                'data': {
                    'type': 'logs_restriction_queries',
                    'attributes': {
                        'restriction_query': query
                    }
                }
            }
        )
        return resp.json()['data']['id']

    def delete_restriction_query(self, restriction_query_id):
        try:
            self._exec_request(
                method='DELETE',
                path=f'/api/v2/logs/config/restriction_queries/{restriction_query_id}'
            )
        except ValueError as e:
            print(f'Error deleting restriction query: {e}')

    def limit_custom_role_log_access(self, role_id, restriction_query_id):
        self._exec_request(
            method='POST',
            path=f'/api/v2/logs/config/restriction_queries/{restriction_query_id}/roles',
            body={
                'data': {
                    'type': 'roles',
                    'id': role_id,
                }
            }
        )

    def delete_custom_role_log_access(self, role_id, restriction_query_id):
        try:
            self._exec_request(
                method='DELETE',
                path=f'/api/v2/logs/config/restriction_queries/{restriction_query_id}/roles',
                body={
                    'data': {
                        'type': 'roles',
                        'id': role_id,
                    }
                }
            )
        except ValueError as e:
            print(f'Error deleting custom role log access: {e}')

    def create_service_account(self, service_account_email, service_account_name, role_id):
        resp = self._exec_request(
            method='POST',
            path='/api/v2/service_accounts',
            body={
                'data': {
                    'type': 'users',
                    'attributes': {
                        'email': service_account_email,
                        'name': service_account_name,
                        'service_account': True,
                    },
                    'relationships': {
                        'roles': {
                            'data': [
                                {
                                    'type': 'roles',
                                    'id': role_id
                                }
                            ]
                        }
                    }
                }
            }
        )
        return resp.json()['data']['id']

    def delete_user(self, user_id):
        try:
            self._exec_request(
                method='DELETE',
                path=f'/api/v2/users/{user_id}'
            )
        except ValueError as e:
            print(f'Error deleting user: {e}')

    def create_app_key(self, service_account_id, app_key_name):
        resp = self._exec_request(
            method='POST',
            path=f'/api/v2/service_accounts/{service_account_id}/application_keys',
            body={
                'data': {
                    'type': 'application_keys',
                    'attributes': {
                        'name': app_key_name,
                    },
                }
            }
        )
        return resp.json()['data']['attributes']['key'], resp.json()['data']['id']

    def delete_app_key(self, service_account_id, app_key_id):
        try:
            self._exec_request(
                method='DELETE',
                path=f'/api/v2/service_accounts/{service_account_id}/application_keys/{app_key_id}'
            )
        except ValueError as e:
            print(f'Error deleting App key: {e}')

    def create_api_key(self, api_key_name):
        resp = self._exec_request(
            method='POST',
            path='/api/v2/api_keys',
            body={
                'data': {
                    'type': 'api_keys',
                    'attributes': {
                        'name': api_key_name,
                    }
                }
            }
        )
        return resp.json()['data']['attributes']['key'], resp.json()['data']['id']

    def delete_api_key(self, api_key_id):
        try:
            self._exec_request(
                method='DELETE',
                path=f'/api/v2/api_keys/{api_key_id}'
            )
        except ValueError as e:
            print(f'Error deleting API key: {e}')


def main():
    timestamp = round(time.time() * 1000)

    parser = argparse.ArgumentParser(
        description='Create a limited-access service account and keys for running the Grepr POC'
    )
    parser.add_argument(
        "-k", "--api_key",
        help='Specify the API key to use for executing the script. If not specified, the script will attempt to use'
             ' the environment variable DD_API_KEY and fail if not specified. For details on creating an API key, see'
             ' https://docs.datadoghq.com/account_management/api-app-keys/'
    )
    parser.add_argument(
        "-a", "--app_key",
        help='Specify the app key to use for executing the script. If not specified, the script will attempt to use'
             ' the environment variable DD_APP_KEY and fail if not specified. For details on creating an application'
             ' key, see https://docs.datadoghq.com/account_management/api-app-keys/'
    )

    subparsers = parser.add_subparsers(dest='command', title="Commands", help="Actions to take", required=True)

    setup_parser = subparsers.add_parser("setup", help="Create the limited-access service account and keys")

    setup_parser.add_argument(
        'query',
        help='The query to use for the data access filter. Example "env:staging".'
    )
    setup_parser.add_argument(
        'service_account_email',
        help='The email address to use for the service account.'
    )
    setup_parser.add_argument(
        '-s', '--site',
        help='The site to use for the API endpoint',
        default='datadoghq.com'
    )
    setup_parser.add_argument(
        "-o", "--output_file",
        help='Specify the file to write the App key and API key to',
        default=f'grepr_setup_script_results_{timestamp}.json'
    )
    setup_parser.add_argument(
        "-r", "--role_name",
        help='Specify the name of the custom role to create',
        default=f'grepr_poc_role_{timestamp}'
    )
    setup_parser.add_argument(
        "-n", "--service_account_name",
        help='Specify the name of the service account to create',
        default=f'grepr_poc_service_account_{timestamp}'
    )
    setup_parser.add_argument(
        '--new_app_key_name',
        help='Specify the name of the App key to create',
        default=f'grepr_poc_app_key_{timestamp}'
    )
    setup_parser.add_argument(
        '--new_api_key_name',
        help='Specify the name of the API key to create',
        default=f'grepr_poc_api_key_{timestamp}'
    )
    setup_parser.set_defaults(func=create)

    revert_parser = subparsers.add_parser("revert", help="Revert the changes made by the setup command")
    revert_parser.add_argument(
        "input_file",
        help="The file to read the App key and API key from",
    )
    revert_parser.set_defaults(func=revert)

    args = parser.parse_args()

    if args.api_key is None:
        if 'DD_API_KEY' in os.environ:
            args.api_key = os.environ['DD_API_KEY']
        else:
            raise ValueError(
                'API key must be specified with -k or --api_key '
                'or set as the environment variable DD_API_KEY'
            )

    if args.app_key is None:
        if 'DD_APP_KEY' in os.environ:
            args.app_key = os.environ['DD_APP_KEY']
        else:
            raise ValueError(
                'Application key must be specified with -a or --app_key '
                'or set as the environment variable DD_APP_KEY'
            )

    args.func(args)


def create(args):

    client = DatadogClient(args.api_key, args.app_key)

    print(f'Writing results to {args.output_file}')

    perms = client.list_permissions()
    if 'logs_read_data' not in perms or 'logs_read_index_data' not in perms:
        raise ValueError('The logs_read_data and logs_read_index_data permissions are required to run this script.')

    read_data_perm_id = perms['logs_read_data']
    read_index_data_perm_id = perms['logs_read_index_data']

    # Create the custom role
    print(f'Creating custom role {args.role_name}')
    role_id = client.create_custom_role(args.role_name, [read_data_perm_id, read_index_data_perm_id])
    output = {
        "role_id": role_id,
    }
    with open(args.output_file, 'w') as f:
        json.dump(output, f, indent=2)

    # Create the data access filter
    print(f'Creating data access filter for {args.query}')
    restriction_query_id = client.create_restriction_query(args.query)
    output = {
        "role_id": role_id,
        "restriction_query_id": restriction_query_id,
    }
    with open(args.output_file, 'w') as f:
        json.dump(output, f, indent=2)

    # Limit the custom role log access using the data access filter
    print(f'Limiting custom role log access using data access filter {args.query}')
    client.limit_custom_role_log_access(role_id, restriction_query_id)

    # Create the service account
    print(f'Creating service account {args.service_account_name}')
    service_account_id = client.create_service_account(
        args.service_account_email, args.service_account_name, role_id)
    output = {
        "role_id": role_id,
        "restriction_query_id": restriction_query_id,
        "service_account_id": service_account_id,
    }
    with open(args.output_file, 'w') as f:
        json.dump(output, f, indent=2)

    # Create an App key for the service account
    print(f'Creating App key {args.new_app_key_name} for service account {args.service_account_name}')
    app_key, app_key_id = client.create_app_key(service_account_id, args.new_app_key_name)
    output = {
        "role_id": role_id,
        "restriction_query_id": restriction_query_id,
        "service_account_id": service_account_id,
        'app_key': app_key,
        'app_key_id': app_key_id,
    }
    with open(args.output_file, 'w') as f:
        json.dump(output, f, indent=2)

    # Create an API key
    print(f'Creating API key {args.new_api_key_name}')
    api_key, api_key_id = client.create_api_key(args.new_api_key_name)
    output = {
        "role_id": role_id,
        "restriction_query_id": restriction_query_id,
        "service_account_id": service_account_id,
        'app_key': app_key,
        'app_key_id': app_key_id,
        'api_key': api_key,
        'api_key_id': api_key_id,
    }
    with open(args.output_file, 'w') as f:
        json.dump(output, f, indent=2)


def revert(args):
    with open(args.input_file, 'r') as f:
        input_data = json.load(f)

    client = DatadogClient(args.api_key, args.app_key)

    # Delete the App key
    if ('app_key_id' not in input_data) or ('service_account_id' not in input_data):
        print("Skipping App key deletion because it was not created in the setup command")
    else:
        print(f'Deleting App key {input_data["app_key_id"]}')
        client.delete_app_key(input_data['service_account_id'], input_data['app_key_id'])

    # Delete the API key
    if 'api_key_id' not in input_data:
        print("Skipping API key deletion because it was not created in the setup command")
    else:
        print(f'Deleting API key {input_data["api_key_id"]}')
        client.delete_api_key(input_data['api_key_id'])

    # Delete the service account
    if 'service_account_id' not in input_data:
        print("Skipping service account deletion because it was not created in the setup command")
    else:
        print(f'Deleting service account {input_data["service_account_id"]}')
        client.delete_user(input_data['service_account_id'])

    # Delete the custom role log access
    if ('role_id' not in input_data) or ('restriction_query_id' not in input_data):
        print("Skipping custom role log access deletion because it was not created in the setup command")
    else:
        print(f'Deleting custom role log access {input_data["role_id"]} {input_data["restriction_query_id"]}')
        client.delete_custom_role_log_access(input_data['role_id'], input_data['restriction_query_id'])

    # Delete the data access filter
    if 'restriction_query_id' not in input_data:
        print("Skipping data access filter deletion because it was not created in the setup command")
    else:
        print(f'Deleting data access filter {input_data["restriction_query_id"]}')
        client.delete_restriction_query(input_data['restriction_query_id'])

    # Delete the custom role
    if 'role_id' not in input_data:
        print("Skipping custom role deletion because it was not created in the setup command")
    else:
        print(f'Deleting custom role {input_data["role_id"]}')
        client.delete_custom_role(input_data['role_id'])

    print(f'Reverted changes made by setup command using input file {args.input_file}')


if __name__ == '__main__':
    main()
