import logging
from urllib.parse import urljoin
from onyphe.exception import APIError


"""
onyphe.client
~~~~~~~~~~~~~

This module implements the Onyphe API.

:copyright: (c) 2017- by Sebastien Larinier
"""
import requests
from requests.utils import quote

class Onyphe:
    """Wrapper around the Onyphe REST

        :param key: The Onyphe API key that can be obtained from your account page (https://www.onyphe.io)
        :type key: str
    """

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

    def _prepare_request(self, uri, **kwargs):
        payload = {
            'apikey': self.api_key
        }

        if 'page' in kwargs:
            payload['page'] = kwargs['page']

        self._choose_url(uri)

        data = self._request('get', payload)
        if data:
            return data

    def __search(self,query, endpoint, **kwargs):
        return self._prepare_request(quote('/'.join([self.version, 'search',
                                               endpoint, query])), **kwargs)

    def synscan(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/synscan/<IP>

            :param ip: IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing the results of the search about synscans.
        """
        return self._prepare_request('/'.join([self.version, 'synscan', ip]))

    def pastries(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/pastries/<IP>

            :param ip: IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing the results of the search in pasties recorded by the service.
        """
        return self._prepare_request('/'.join([self.version, 'pastries', ip]))

    def geoloc(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/geoloc/<IP>

                :param ip: IPv4 or IPv6 address
                :type ip: str
                :returns: dict -- a dictionary containing the results of geolocation of IP
        """
        return self._prepare_request('/'.join([self.version, 'geoloc', ip]))

    def inetnum(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/inetnum/<IP>

            :param ip: IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing the results of inetnum of IP
        """
        return self._prepare_request('/'.join([self.version, 'inetnum', ip]))

    def threatlist(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/threatlist/<IP>

            :param ip: IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing the results of the IP in threatlists
        """
        return self._prepare_request('/'.join([self.version, 'threatlist', ip]))

    def forward(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/forward/<IP>

            :param ip: IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing the results of forward of IP
        """
        return self._prepare_request('/'.join([self.version, 'forward', ip]))

    def reverse(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/reverse/<IP>

            :param ip: IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing the domains of reverse DNS of IP
        """
        return self._prepare_request('/'.join([self.version, 'reverse', ip]))

    def ip(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/ip/<IP>

            :param ip: IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing all informations of IP
        """
        return self._prepare_request('/'.join([self.version, 'ip', ip]))

    def datascan(self, data):
        """Call API Onyphe https://www.onyphe.io/api/v1/datascan/<IP>

            :param data: IPv4/IPv6 address
            :type data: str
            :returns: dict -- a dictionary containing Information scan on IP or string
        """
        return self._prepare_request('/'.join([self.version, 'datascan', data]))

    def search_datascan(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/datascan/<query>
        :param query: example product:Apache port:443 os:Windows.
        :type: str
        :return: dict -- a dictionary with result
        """

        return self.__search(query, 'datascan', **kwargs)

    def search_synscan(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/syscan/<query>
        :param query: example ip:46.105.48.0/21 os:Linux port:23.
        :type: str
        :return: dict -- a dictionary with result
        """
        return self.__search(query, 'synscan', **kwargs)

    def search_inetnum(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/inetnum/<query>
        :param query: example organization:"OVH SAS"
        :type: str
        :return: dict -- a dictionary with result
        """
        return self.__search(query, 'inetnum', **kwargs)

    def search_threatlist(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/threatlist/<query>
        :param query: example: country:RU or ip:94.253.102.185
        :type: str
        :return: dict -- a dictionary with result
        """
        return self.__search(query, 'threatlist', **kwargs)

    def search_pastries(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/pastries/<query>
        :param query: example: domain:amazonaws.com or ip:94.253.102.185
        :type: str
        :return: dict -- a dictionary with result
        """
        return self.__search(query, 'pastries', **kwargs)

    def search_resolver(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/resolver/<query>
                :param query: example: domain:amazonaws.com
                :type: str
                :return: dict -- a dictionary with result
                """
        return self.__search(query, 'resolver', **kwargs)



