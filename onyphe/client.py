from urllib.parse import urljoin
from onyphe.exception import APIError

import requests


class Onyphe:

    def __init__(self, api_key, version='v1'):
        self.api_key = api_key
        self.base_url = 'https://www.onyphe.io/api/'
        self.version = version
        self._session = requests.Session()

        self.methods = {
            'get': self._session.get,
            'post': self._session.post,
        }

    def _choose_url(self, uri):

        self.url = urljoin(self.base_url, uri)

    def _request(self, method, payload):

        data = None

        try:
            response = self.methods[method](self.url, params=payload)
        except:
            raise APIError('Unable to connect to Onyphe')

        if response.status_code == requests.codes.NOT_FOUND:

            raise APIError('Page Not found %s' % self.url)
        elif response.status_code == requests.codes.FORBIDDEN:
            raise APIError('Access Forbidden')
        elif response.status_code != requests.codes.OK:
            try:
                error = response.json()['message']
            except Exception as e:
                error = 'Invalid API key'

            raise APIError(error)
        try:

            data = response.json()

        except:
            raise APIError('Unable to parse JSON')

        return data

    def _prepare_request(self, uri):
        payload = {
            'apikey': self.api_key
        }

        self._choose_url(uri)

        data = self._request('get', payload)
        if data:
            return data

    def synscan(self, ip):
        return self._prepare_request('/'.join([self.version, 'synscan', ip]))

    def pastries(self, ip):
        return self._prepare_request('/'.join([self.version, 'pastries', ip]))

    def geoloc(self, ip):
        return self._prepare_request('/'.join([self.version, 'geoloc', ip]))

    def inetnum(self, ip):
        return self._prepare_request('/'.join([self.version, 'inetnum', ip]))

    def threatlist(self, ip):
        return self._prepare_request('/'.join([self.version, 'threatlist', ip]))

    def forward(self, ip):
        return self._prepare_request('/'.join([self.version, 'forward', ip]))

    def reverse(self, ip):
        return self._prepare_request('/'.join([self.version, 'reverse', ip]))

    def ip(self, ip):
        return self._prepare_request('/'.join([self.version, 'ip', ip]))

    def datascan(self, data):
        return self._prepare_request('/'.join([self.version, 'datascan', data]))
