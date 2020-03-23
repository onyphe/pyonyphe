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

    def __init__(self, api_key, version='v2'):
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
        elif response.status_code == requests.codes.too_many_requests:
            raise APIError('Too Many Requests')
        elif response.status_code != requests.codes.OK:
            try:
                error = response.json()['text']
            except Exception as e:
                error = 'Unknown error'

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

    def __search(self, query, endpoint, **kwargs):
        return self._prepare_request(quote('/'.join([self.version, 'search',
                                                     endpoint, query])),
                                     **kwargs)

    def synscan(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/synscan/<IP>

            :param ip: IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing the results of the search about synscans.
        """
        return self._prepare_request('/'.join([self.version, 'synscan', ip]))

    def summary_ip(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/summary/ip/<IP>

            :param ip: IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing all informations of IP
        """
        return self._prepare_request('/'.join([self.version, 'summary/ip', ip]))

    def summary_domain(self, domain):
        """Call API Onyphe https://www.onyphe.io/api/v2/summary/domain/<domain>

                    :param domain: domain
                    :type domain: str
                    :returns: dict -- a dictionary containing the results of the summary of domain.
                """
        return self._prepare_request(
            '/'.join([self.version, 'summary/domain', domain]))

    def summary_hostname(self, hostname):
        """Call API Onyphe https://www.onyphe.io/api/v2/summary/hostname/<hostname>

                    :param hostname: hostname
                    :type hostname: str
                    :returns: dict -- a dictionary containing the results of the summary of hostname.
                """
        return self._prepare_request(
            '/'.join([self.version, 'summary/hostname', hostname]))

    def simple_synscan(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/synscan/<IP>

            :param ip: IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing the results of synscan of IP
        """
        return self._prepare_request(
            '/'.join([self.version, 'simple/synscan', ip]))

    def simple_onionshot(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/onionshot/<IP>

            :param ip: IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing the results of onionshot of IP
        """
        return self._prepare_request(
            '/'.join([self.version, 'simple/onionshot', ip]))

    def simple_ctl(self, data):
        """Call API Onyphe https://www.onyphe.io/api/v2/ctl/{<IP>,<str}

            :param data: domain or hostname
            :type data: str
            :returns: dict -- a dictionary containing Information on ctl on domain or hostname
        """
        return self._prepare_request(
            '/'.join([self.version, 'simple/ctl', data]))

    def simple_onionscan(self, data):
        """Call API Onyphe https://www.onyphe.io/api/v2/onionscan/{<IP>,<str}

            :param data: data or hostname
            :type data: str
            :returns: dict -- a dictionary containing Information onionscan on domain or hostname
        """
        return self._prepare_request(
            '/'.join([self.version, 'simple/onionscan', data]))

    def simple_datascan_datamd5(self, data_md5):
        """Call API Onyphe https://www.onyphe.io/api/v2/datascan/datamd5/<data_md5>

           :param data_md5: category of information we have for the given domain or hostname
           :type data_md5: str
           :returns: dict -- a dictionary containing Information onionscan on domain or hostname
        """
        return self._prepare_request(
            '/'.join([self.version, 'simple/datascan/datamd5', data_md5]))

    def simple_resolver_forward(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/resolver/forward/<IP>
             :param ip: IPv4 or IPv6 address
             :type ip: str
             :returns: dict -- a dictionary containing the results of forward of IP
         """
        return self.__resolver(ip, 'forward')

    def simple_resolver_reverse(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/resolver/reverse/<IP>

             :param ip: IPv4 or IPv6 address
             :type ip: str
             :returns: dict -- a dictionary containing the results of reverse of IP
         """
        return self.__resolver(ip, 'reverse')

    def __resolver(self, ip, type_resolv):
        return self._prepare_request(
            '/'.join([self.version, 'simple/resolver/%s' % type_resolv, ip]))

    def search(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v2/search/<query>
        :param query: example product:Apache port:443 os:Windows.
        :type: str
        :return: dict -- a dictionary with result
        """

        return self.__search(query, 'datascan', **kwargs)

    def alert_list(self):
        """Call API Onyphe https://www.onyphe.io/api/v2/alert/list

               :return: dict -- a dictionary with result
        """
        return self._prepare_request('/'.join([self.version, 'alert/list']))
