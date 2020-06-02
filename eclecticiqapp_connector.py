# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import requests
import json
import urllib
import re

import logging
import datetime
import time

API_PATHS = {
    '2.1': {
        'auth': '/api/auth',
        'group_id_search': '/api/sources/',
        'feeds_list': '/private/outgoing-feed-download/',
        'feed_info': '/private/outgoing-feeds/',
        'feed_content_blocks': '/private/outgoing-feed-download/',
        'groups': '/private/groups/',
        'entities': '/private/entities/',
        'observable_search': '/api/observables/',
        'entity_search': '/private/search-all/',
        'entity_get': '/private/entities/',
        'taxonomy_get': '/private/taxonomies/',
        'observables': '/private/search-all/'
    }
}

USER_AGENT = 'Phantom Integration'


def format_ts(dt):
    return dt.replace(microsecond=0).isoformat() + 'Z'


def format_ts_human(dt):
    return dt.replace(microsecond=0).isoformat() + 'Z'


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class EclecticIQ_api(object):
    def __init__(self,
                 baseurl,
                 eiq_version,
                 username,
                 password,
                 verify_ssl=True,
                 proxy_ip=None,
                 proxy_username=None,
                 proxy_password=None,
                 logger=None
                 ):
        self.eiq_logging = self.set_logger(logger)
        self.eiq_username = username
        self.eiq_password = password
        self.baseurl = baseurl
        self.verify_ssl = self.set_verify_ssl(verify_ssl)
        self.proxy_ip = proxy_ip
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self.proxies = self.set_eiq_proxy()
        self.eiq_api_version = self.set_eiq_api_version(eiq_version)
        self.eiq_datamodel_version = self.set_eiq_datamodel_version(eiq_version)
        self.token_expires = 0
        self.headers = {
            'user-agent': USER_AGENT,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.get_outh_token()

    def set_logger(self, logger):
        if logger is None:
            logging.basicConfig(level=logging.INFO)
            logger_output = logging.getLogger()
            return logger_output
        else:
            return logger

    def set_verify_ssl(self, ssl_status):
        if ssl_status in ["1", "True", "true", True]:
            return True
        elif ssl_status in ["0", "False", "false", False]:
            return False
        else:
            return True

    def sanitize_eiq_url(self, eiq_url):
        # TD
        return

    def sanitize_eiq_version(self, eiq_version):
        if "." in eiq_version:
            eiq_version = re.search(r"^\d+\.\d", eiq_version).group()
            return float(eiq_version)
        elif re.findall(r"fc\-essentials", eiq_version, flags=re.IGNORECASE):
            return "FC-Essentials"
        elif re.findall(r"fc\-spotlight", eiq_version, flags=re.IGNORECASE):
            return "FC-Spotlight"
        else:
            # TD check code below
            try:
                eiq_version = re.search(r"^\d+\.\d", eiq_version).group()
                return int(eiq_version)
            except ValueError:
                pass

    def set_eiq_proxy(self):
        # TD sanitize proxy?

        if self.proxy_ip and self.proxy_username and self.proxy_password:
            return {
                'http': 'http://' + self.proxy_username + ':' + self.proxy_password + '@' + self.proxy_ip + '/',
                'https': 'http://' + self.proxy_username + ':' + self.proxy_password + '@' + self.proxy_ip + '/',
            }
        elif self.proxy_ip:
            return {
                'http': 'http://' + self.proxy_ip + '/',
                'https': 'http://' + self.proxy_ip + '/',
            }
        else:
            return None

    def set_eiq_api_version(self, eiq_version):
        eiq_version = self.sanitize_eiq_version(eiq_version)

        if (isinstance(eiq_version, float) or isinstance(eiq_version, int)) and eiq_version < 2.1:
            return '2.0'
        elif (isinstance(eiq_version, float) or isinstance(eiq_version, int)) and eiq_version >= 2.1:
            return '2.1'
        elif re.match(r"FC", eiq_version):
            return 'FC'
        else:
            # TD add warning
            return 'WARNING'

    def set_eiq_datamodel_version(self, eiq_version):
        eiq_version = self.sanitize_eiq_version(eiq_version)
        if (isinstance(eiq_version, float) or isinstance(eiq_version, int)) and eiq_version < 2.2:
            return "pre2.2"
        elif (isinstance(eiq_version, float) or isinstance(eiq_version, int)) and eiq_version >= 2.2:
            return "2.2"
        elif eiq_version == "FC-Essentials":
            return "FC-Essentials"
        elif eiq_version == "FC-Spotlight":
            return "FC-Spotlight"
        else:
            # TD add warning
            return 'WARNING'

    def get_outh_token(self):
        self.eiq_logging.info('Authenticating using username: ' + str(self.eiq_username))

        if (re.match("^[\\dabcdef]{64}$", self.eiq_password)) is None:
            try:
                r = requests.post(
                    self.baseurl + API_PATHS[self.eiq_api_version]['auth'],
                    headers=self.headers,
                    data=json.dumps({
                        'username': self.eiq_username,
                        'password': self.eiq_password
                    }),
                    verify=self.verify_ssl,
                    proxies=self.proxies,
                    timeout=30
                )

                if r and r.status_code in [100, 200, 201, 202]:
                    self.headers['Authorization'] = 'Bearer ' + r.json()['token']
                    self.token_expires = time.time() + 1500
                    self.eiq_logging.info('Authentication successful')
                else:
                    if not r:
                        msg = 'Could not perform auth request to EclecticIQ'
                        self.eiq_logging.exception(msg)
                        raise Exception(msg)
                    try:
                        err = r.json()
                        detail = err['errors'][0]['detail']
                        msg = ('EclecticIQ VA returned an error, code:[{0}], reason:[{1}], URL: [{2}], details:[{3}]'
                               .format(r.status_code, r.reason, r.url, detail))
                    except Exception:
                        msg = ('EclecticIQ VA returned an error, code:[{0}], reason:[{1}], URL: [{2}]'
                               .format(r.status_code, r.reason, r.url))
                    raise Exception(msg)

            except Exception:
                self.eiq_logging.error("Authentication failed")
                raise
        else:
            try:
                self.headers['Authorization'] = 'Bearer ' + self.eiq_password

                r = requests.get(
                    self.baseurl + '/api',
                    headers=self.headers,
                    verify=self.verify_ssl,
                    proxies=self.proxies,
                    timeout=30
                )

                if r and r.status_code in [100, 200, 201, 202]:
                    self.token_expires = time.time() + 1500
                    self.eiq_logging.info('Authentication successful')
                else:
                    if not r:
                        msg = 'Could not perform auth request to EclecticIQ'
                        self.eiq_logging.exception(msg)
                        raise Exception(msg)
                    try:
                        err = r.json()
                        detail = err['errors'][0]['detail']
                        msg = ('EclecticIQ VA returned an error, code:[{0}], reason:[{1}], URL: [{2}], details:[{3}]'
                               .format(r.status_code, r.reason, r.url, detail))
                    except Exception:
                        msg = ('EclecticIQ VA returned an error, code:[{0}], reason:[{1}], URL: [{2}]'
                               .format(r.status_code, r.reason, r.url))
                    raise Exception(msg)

            except Exception:
                self.eiq_logging.error("Authentication failed")
                raise

    def send_api_request(self, method, path, params=None, data=None):

        if self.token_expires < time.time():
            self.get_outh_token()

        url = self.baseurl + path

        r = None
        try:
            if method == 'post':
                r = requests.post(
                    url,
                    headers=self.headers,
                    params=params,
                    data=json.dumps(data),
                    verify=self.verify_ssl,
                    proxies=self.proxies,
                    timeout=30
                )
            elif method == 'get':
                r = requests.get(
                    url,
                    headers=self.headers,
                    params=params,
                    data=json.dumps(data),
                    verify=self.verify_ssl,
                    proxies=self.proxies,
                    timeout=30
                )
            else:
                self.eiq_logging.error("Unknown method: " + str(method))
                raise Exception
        except Exception:
            self.eiq_logging.exception(
                'Could not perform request to EclecticIQ VA: {0}: {1}'.format(method, url))

        if r and r.status_code in [100, 200, 201, 202]:
            return r
        else:
            if not r:
                msg = ('Could not perform request to EclecticIQ VA: {0}: {1}'.format(method, url))
                self.eiq_logging.exception(msg)
                raise Exception(msg)

            try:
                err = r.json()
                detail = err['errors'][0]['detail']
                msg = ('EclecticIQ VA returned an error, code:[{0}], reason:[{1}], URL: [{2}], details:[{3}]'
                    .format(
                        r.status_code,
                        r.reason,
                        r.url,
                        detail))
            except Exception:
                msg = ('EclecticIQ VA returned an error, code:[{0}], reason:[{1}], URL: [{2}]').format(
                    r.status_code,
                    r.reason,
                    r.url)
            raise Exception(msg)

    def get_source_group_uid(self, group_name):
        self.eiq_logging.debug("Requesting source id for specified group, name=[" + str(group_name) + "]")
        r = self.send_api_request(
            'get',
            path=API_PATHS[self.eiq_api_version]['groups'],
            params='filter[name]=' + str(group_name))

        if not r.json()['data']:
            self.eiq_logging.error(
                'Something went wrong fetching the group id. '
                'Please note the source group name is case sensitive! '
                'Received response:' + str(r.json()))
            return "error_in_fetching_group_id"
        else:
            self.eiq_logging.debug('Source group id received')
            self.eiq_logging.debug('Source group id is: ' + str(r.json()['data'][0]['source']))
            return r.json()['data'][0]['source']

    def get_feed_info(self, feed_ids):
        self.eiq_logging.info("Requesting feed info for feed id={0}".format(feed_ids))
        feed_ids = (feed_ids.replace(" ", "")).split(',')
        result = []

        if self.eiq_api_version == "FC":
            for k in feed_ids:
                feed_result = {'id': k, 'created_at': '', 'update_strategy': 'REPLACE', 'packaging_status': 'SUCCESS'}
                result.append(feed_result)
            self.feeds_info = result
            return result

        for k in feed_ids:
            feed_result = {}
            try:
                r = self.send_api_request(
                    'get',
                    path=API_PATHS[self.eiq_api_version]['feed_info'] + k)
            except Exception:
                self.eiq_logging.error('Feed id={0} information cannot be requested.'.format(k))
                continue

            if not r.json()['data']:
                self.eiq_logging.error(
                    'Feed id={0} information cannot be requested. Received response:' + str(r.json())).format(k)
                return "error_in_fetching_feed_info"
            else:
                self.eiq_logging.debug('Feed id={0} information requested'.format(k))
                feed_result['id'] = r.json()['data']['id']
                feed_result['created_at'] = r.json()['data']['created_at']
                feed_result['update_strategy'] = r.json()['data']['update_strategy']
                feed_result['packaging_status'] = r.json()['data']['packaging_status']
                feed_result['name'] = r.json()['data']['name']
                result.append(feed_result)
                self.eiq_logging.debug(
                    'Feed id={0} information retrieved successfully. Received response:'.format(k) + str(
                        json.dumps(feed_result)) + ''.format(k))

        return result

    def download_block_list(self, block):
        self.eiq_logging.debug("Downloading block url{0}".format(block))

        if self.eiq_api_version == "FC":
            block = (str(block)).replace(self.baseurl, '')

        r = self.send_api_request('get', path=str(block))
        data = r.text

        return data

    def get_feed_content_blocks(self, feed, feed_last_run=None):
        self.eiq_logging.debug("Requesting block list for feed id={0}".format(feed['id']))

        if feed_last_run is None:
            feed_last_run = {}
            feed_last_run['last_ingested'] = None
            feed_last_run['created_at'] = None

        if feed['packaging_status'] == 'SUCCESS' and feed['update_strategy'] == 'REPLACE':
            self.eiq_logging.debug("Requesting block list for REPLACE feed.")

            r = self.send_api_request(
                'get',
                path=API_PATHS[self.eiq_api_version]['feed_content_blocks'] + "{0}/runs/latest".format(feed['id']))

            data = r.json()['data']['content_blocks']
            if feed_last_run['last_ingested'] == data[-1]:
                self.eiq_logging.info(
                    "Received list contains {0} blocks for feed id={1}.".format(len(data), feed['id']))
                return []
            self.eiq_logging.info("Received list contains {0} blocks for feed id={1}.".format(len(data), feed['id']))
            return data

        elif feed['packaging_status'] == 'SUCCESS' and (feed['update_strategy'] in ['APPEND', 'DIFF']):
            self.eiq_logging.debug("Requesting block list for {0} feed.".format(feed['update_strategy']))

            r = self.send_api_request(
                'get',
                path=API_PATHS[self.eiq_api_version]['feed_content_blocks'] + "{0}".format(feed['id']))

            data = r.json()['data']['content_blocks']

            if (feed['created_at'] != feed_last_run['created_at']) or feed_last_run['last_ingested'] is None:
                self.eiq_logging.info(
                    "Received list contains {0} blocks for {1} feed:{2}. Feed created time changed or first run, "
                    "reingestion of all the feed content.".format(len(data), feed['update_strategy'], feed['id']))
                return data
            else:
                try:
                    last_ingested_index = data.index(feed_last_run['last_ingested'])
                    diff_data = data[last_ingested_index + 1:]
                    self.eiq_logging.info("Received list contains {0} blocks for {1} feed:{2}."
                                          .format(len(diff_data), feed['update_strategy'], feed['id']))
                    return diff_data
                except ValueError:
                    self.eiq_logging.error("Value of last ingested block not available in Feed {0}.".format(feed['id']))
                    return None

        elif feed['packaging_status'] == 'RUNNING':
            self.eiq_logging.info("Feed id={0} is running now. Collecting data is not possible.".format(feed['id']))
        else:
            self.eiq_logging.info(
                "Feed id={0} update strategy is not supported. Use Replace or Diff".format(feed['id']))

    def get_group_name(self, group_id):
        self.eiq_logging.info("Getting group name by id:{0}".format(group_id))
        r = self.send_api_request(
            'get',
            path=API_PATHS[self.eiq_api_version]['group_id_search'] + str(group_id))

        response = json.loads(r.text)
        result = {}

        result['name'] = response['data'].get('name', 'N/A')
        result['type'] = response['data'].get('type', 'N/A')

        return result

    def lookup_observable(self, value, type):
        """Method lookups specific observable by value and type.

        Args:
            value: value of Observable
            type: type of observable, e.g. ipv4, hash-md5 etc

        Returns:
            Return dictionary with Observable details:
             {created: date and time of creation,
             last_updated: last update time,
             maliciousness: value of maliciousness,
             type: type of Observable from args ,
             value: value of Observable from args,
             source_name: who produced Observable,
             platform_link: direct link o the platform
             }

            Otherwise returns None.

        """
        self.eiq_logging.info("Searching Observable:{0}, type:{1}".format(value, type))

        r = self.send_api_request(
            'get',
            path=API_PATHS[self.eiq_api_version]['observable_search'],
            params={'filter[type]': type, 'filter[value]': value})

        observable_response = json.loads(r.text)

        if observable_response['count'] == 1:
            result = {}
            result['created'] = str(observable_response['data'][0]['created_at'])[:16]
            result['last_updated'] = str(observable_response['data'][0]['last_updated_at'])[:16]
            result['maliciousness'] = observable_response['data'][0]['meta']['maliciousness']
            result['type'] = observable_response['data'][0]['type']
            result['value'] = observable_response['data'][0]['value']
            result['source_name'] = ""

            for k in observable_response['data'][0]['sources']:
                source_lookup_data = self.get_group_name(k)
                result['source_name'] += str(source_lookup_data['type']) + ': ' + str(source_lookup_data['name']) + '; '

            result['platform_link'] = self.baseurl + "/observables/" + type + "/" + urllib.quote_plus(value)

            return result

        elif observable_response['count'] > 1:
            self.eiq_logging.info("Finding duplicates for observable:{0}, type:{1}, return first one".format(value, type))
            result = {}
            result['created'] = str(observable_response['data'][0]['created_at'])[:16]
            result['last_updated'] = str(observable_response['data'][0]['last_updated_at'])[:16]
            result['maliciousness'] = observable_response['data'][0]['meta']['maliciousness']
            result['type'] = observable_response['data'][0]['type']
            result['value'] = observable_response['data'][0]['value']

            for k in observable_response['data'][0]['sources']:
                source_lookup_data = self.get_group_name(k)
                result['source_name'] += str(source_lookup_data['type']) + ': ' + str(source_lookup_data['name']) + '; '

            result['platform_link'] = self.baseurl + "/observables/" + type + "/" + urllib.quote_plus(value)

            return result

        else:

            return None

    def get_taxonomy_dict(self):
        """Method returns dictionary with all the available taxonomy in Platform.

        Returns:
            Return dictionary with {taxonomy ids:taxonomy title}. Otherwise returns False.

        """
        self.eiq_logging.info("Get all the taxonomy titles from Platform.")

        r = self.send_api_request(
            'get',
            path=API_PATHS[self.eiq_api_version]['taxonomy_get'])

        taxonomy = json.loads(r.text)
        taxonomy_dict = {}

        for i in taxonomy['data']:
            try:
                id = i['id']
                name = i['name']

                taxonomy_dict[id] = name
            except KeyError:
                continue

        if len(taxonomy_dict) > 0:
            return taxonomy_dict
        else:
            return False

    def get_entity_by_id(self, entity_id):
        """Method lookups specific entity by Id.

        Args:
            entity_id: Requested entity Id.

        Returns:
            Return dictionary with entity details:
             {entity_title: value,
             entity_type: value,
             created_at: value,
             source_name: value,
             tags_list: [
                tag and taxonomy list ...
                ],
             relationships_list: [
                    {relationship_type: incoming/outgoing,
                    connected_node: id,
                    connected_node_type: value,
                    connected_node_type: value
                    }
                relationship list ...
                ],
             observables_list: [
                    {value: obs_value,
                    type: obs_type
                    },
                    ...
                ]
             }

            Otherwise returns False.

        """
        self.eiq_logging.info("Looking up Entity {0}.".format(entity_id))

        r = self.send_api_request(
            'get',
            path=API_PATHS[self.eiq_api_version]['entity_get'] + str(entity_id))
        parsed_response = json.loads(r.text)
        taxonomy = self.get_taxonomy_dict()

        result = dict()

        result['entity_title'] = parsed_response['data']['meta'].get('title', 'N/A')
        result['entity_type'] = parsed_response['data']['data'].get('type', 'N/A')
        result['created_at'] = str(parsed_response['data'].get('created_at', 'N/A'))[:16]
        source = self.get_group_name(parsed_response['data']['sources'][0].get('source_id', 'N/A'))
        result['source_name'] = source['type'] + ': ' + source['name']
        result['tags_list'] = []

        try:
            for i in parsed_response['data']['meta']['tags']:
                result['tags_list'].append(i)
        except KeyError:
            pass

        try:
            for i in parsed_response['data']['meta']['taxonomy']:
                result['tags_list'].append(taxonomy.get(i))
        except KeyError:
            pass

        result['observables_list'] = []

        search_result = self.search_entity(entity_id=entity_id)

        try:
            for i in search_result[0]['_source']['extracts']:
                observable_to_add = {'value': i['value'],
                                     'type': i['kind']}
                result['observables_list'].append(observable_to_add)
        except (KeyError, TypeError):
            pass

        result['relationships_list'] = []

        if len(parsed_response['data']['incoming_stix_relations']) > 0:
            for i in parsed_response['data']['incoming_stix_relations']:
                relationship_to_add = {'relationship_type': 'incoming',
                                       'connected_node': i['data']['source'],
                                       'connection_type': i['data']['key'],
                                       'connected_node_type': i['data']['source_type']
                                       }
                result['relationships_list'].append(relationship_to_add)

        if len(parsed_response['data']['outgoing_stix_relations']) > 0:
            for i in parsed_response['data']['outgoing_stix_relations']:
                relationship_to_add = {'relationship_type': 'outgoing',
                                       'connected_node': i['data']['target'],
                                       'connection_type': i['data']['key'],
                                       'connected_node_type': i['data']['target_type']
                                       }
                result['relationships_list'].append(relationship_to_add)

        return result

    def search_entity(self, entity_value=None, entity_type=None, entity_id=None, observable_value=None):
        """Method search specific entity by specific search conditions.

        Note: search works with wildcards for entity value and with strict conditions for everything else.
            Also, it's recommended to use this method to lookup entity name based on the entity ID, because it doesnt
            return all the relationships.

            if you need to find specific entity - search by entity id
            if you need to find all the entities with specific observables extracted - search with observable values

        Args:
            entity_value: entity value to search. add " or * to make search wildcard or strict
            entity_type: value to search
            entity_id: entity id to search
            observable_value: observable value to search inside entity

        Returns:
            Return dictionary with all the entity details.
            Otherwise returns False.

        """
        self.eiq_logging.info("Searching Entity:{0} with extracted observable:{1}, type:{2}"
                              .format(entity_value, observable_value, entity_type))

        query_list = []

        if entity_value is not None:
            if entity_value[0] == '"' and entity_value[-1] == '"':
                entity_value = entity_value[1:-1]
                entity_value = entity_value.replace('"', '\\"')
                entity_value = '"' + entity_value + '"'
            else:
                entity_value = entity_value.replace('"', '\\"')

            query_list.append("data.title:" + entity_value)

        if observable_value is not None:
            query_list.append("extracts.value:\"" + observable_value + "\"")

        if entity_type is not None:
            query_list.append("data.type:" + entity_type)

        if entity_id is not None:
            query_list.append("id:\"" + entity_id + "\"")

        search_dict = {
            "query": {
                "query_string": {
                    "query": str(" AND ".join(query_list))
                }
            }
        }

        r = self.send_api_request(
            'post',
            path=API_PATHS[self.eiq_api_version]['entity_search'],
            data=search_dict)

        search_response = json.loads(r.text)

        if len(search_response['hits']['hits']) > 0:
            return search_response['hits']['hits']
        else:
            return False

    def create_entity(self, observable_dict, source_group_name, entity_title, entity_description,
                      entity_confidence='Medium', entity_tags=[], entity_type='eclecticiq-sighting',
                      entity_impact_value="None", indicator_type=None):

        """Method creates entity in Platform.

        Args:
            observable_dict: list of dictionaries with observables to create. Format:
                [{
                observable_type: "value",
                observable_value: value,
                observable_maliciousness: high/medium/low,
                observable_classification: good/bad
                }]
            source_group_name: group name in Platform for Source. Case sensitive.
            entity_title: value
            entity_description: value
            entity_confidence: Low/Medium/High
            entity_tags: list of strings
            entity_type: type of entity. e.g. indicator, ttp, eclecticiq-sighting etc
            entity_impact_value: "None", "Unknown", "Low", "Medium", "High"

        Returns:
            Return created entity id if successful otherwise returns False.

        """
        self.eiq_logging.info("Creating Entity in EclecticIQ Platform. Type:{0}, title:{1}"
                              .format(entity_type, entity_title))

        group_id = self.get_source_group_uid(source_group_name)

        today = datetime.datetime.utcnow().date()

        today_begin = format_ts(datetime.datetime(today.year, today.month, today.day, 0, 0, 0))
        threat_start = format_ts(datetime.datetime.utcnow())

        observable_dict_to_add = []
        record = {}

        for i in observable_dict:
            record = {}

            if entity_type == 'eclecticiq-sighting':
                record['link_type'] = "sighted"
            else:
                record['link_type'] = "observed"

            if i.get('observable_maliciousness', "") in ["low", "medium", "high"]:
                record['confidence'] = i['observable_maliciousness']

            if i.get('observable_classification', "") in ["bad", "good", "unknown"]:
                record['classification'] = i['observable_classification']

            if i.get('observable_value', ""):
                record['value'] = i['observable_value']
            else:
                continue

            if i.get('observable_type', "") in ["asn", "country", "cve", "domain", "email", "email-subject", "file",
                                                "handle",
                                                "hash-md5", "hash-sha1", "hash-sha256", "hash-sha512", "industry",
                                                "ipv4",
                                                "ipv6", "malware", "name", "organization", "port", "snort", "uri",
                                                "yara"]:
                record['kind'] = i['observable_type']
            else:
                continue

            observable_dict_to_add.append(record)

        if self.eiq_datamodel_version == '2.2':
            entity = {"data": {
                "data": {
                    "confidence": {
                        "type": "confidence",
                        "value": entity_confidence
                    },
                    "description": entity_description,
                    "description_structuring_format": "html",
                    "likely_impact": {
                        "type": "statement",
                        "value": entity_impact_value,
                        "value_vocab": "{http://stix.mitre.org/default_vocabularies-1}HighMediumLowVocab-1.0",
                    },
                    "type": entity_type,
                    "title": entity_title,
                    "security_control": {
                        "type": "information-source",
                        "identity": {
                            "name": "",
                            "type": "identity"
                        },
                        "time": {
                            "type": "time",
                            "start_time": today_begin,
                            "start_time_precision": "second"
                        }
                    },
                },
                "meta": {
                    "manual_extracts": observable_dict_to_add,
                    "taxonomy": [],
                    "estimated_threat_start_time": threat_start,
                    "tags": entity_tags,
                    "ingest_time": threat_start
                },
                "sources": [{
                    "source_id": group_id
                }]
            }}

            if indicator_type is not None:
                entity["data"]["data"]["types"] = []
                entity["data"]["data"]["types"].append({"value": indicator_type})

            if entity_type == 'eclecticiq-sighting':
                entity["data"]["data"]["security_control"]["identity"]["name"] = "3rd party Sightings script"

        else:
            # TD recheck
            entity = {"data": {
                "data": {
                    "confidence": {
                        "type": "confidence",
                        "value": "Low"
                    },
                    "description": entity_description,
                    "related_extracts": observable_dict_to_add,
                    "description_structuring_format": "html",
                    "type": entity_type,
                    "title": entity_title,
                    "security_control": {
                        "type": "information-source",
                        "identity": {
                            "name": "EclecticIQ Platform App for Splunk",
                            "type": "identity"
                        },
                        "time": {
                            "type": "time",
                            "start_time": today_begin,
                            "start_time_precision": "second"
                        }
                    },
                },
                "meta": {
                    "source": group_id,
                    "taxonomy": [],
                    "estimated_threat_start_time": threat_start,
                    "tags": ["Splunk Alert"],
                    "ingest_time": threat_start
                }
            }}

        r = self.send_api_request(
            'post',
            path=API_PATHS[self.eiq_api_version]['entities'],
            data=entity)

        entity_response = json.loads(r.text)

        try:
            return entity_response['data']['id']
        except KeyError:
            return False

    def get_observable(self, observable):
        self.eiq_logging.info('EclecticIQ_api: Searching for Observable: {0}'.format(observable))
        path = API_PATHS[self.eiq_api_version]['observables'] + '?q=extracts.value:' + observable
        r = self.send_api_request(
            'get',
            path=path)
        return r.json()


class EclecticiqAppConnector(BaseConnector):

    def __init__(self):

        super(EclecticiqAppConnector, self).__init__()
        self._state = None
        self._headers = None
        self._base_url = None

    def _handle_on_poll(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if self._tip_of_id == "None":
            return RetVal(action_result.set_status(phantom.APP_ERROR, "No Outgoing Feed ID in asset parameters"), None)

        artifact_count = param.get("artifact_count", 0)
        container_count = param.get("container_count", 0)

        feed_info = self.eiq_api.get_feed_info(self._tip_of_id)

        if feed_info[0]['update_strategy'] not in ['REPLACE', 'APPEND']:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Outgoing feed update strategy not supported."), None)
        elif feed_info[0]['packaging_status'] != 'SUCCESS':
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Outgoing feed is running now. Wait for run"
                                                                      " complete first."), None)

        if feed_info[0]['update_strategy'] == 'REPLACE':
            feed_content_block_list = self.eiq_api.get_feed_content_blocks(feed=feed_info[0])
            containers_processed = 0
            artifacts_processed = 0

            for idx, record in enumerate(feed_content_block_list):
                if containers_processed >= container_count != 0:
                    self.send_progress("Reached container polling limit: {0}".format(containers_processed))
                    return self.set_status(phantom.APP_SUCCESS)

                if artifacts_processed >= artifact_count != 0:
                    self.send_progress("Reached artifacts polling limit: {0}".format(artifacts_processed))
                    return self.set_status(phantom.APP_SUCCESS)

                self.send_progress("Processing block # {0}".format(idx))
                downloaded_block = json.loads(self.eiq_api.download_block_list(record))

                events = downloaded_block.get('entities', [])
                results = []

                for i in events:
                    idref = i['meta'].get('is_unresolved_idref', False)

                    if i['data']['type'] != "relation" and idref is not True:
                        container = {}
                        container['data'] = i
                        container['source_data_identifier'] = "EIQ Platform, OF: {0}, id#{1}. Entity id:{2}"\
                            .format(feed_info[0]["name"], feed_info[0]["id"], i['id'])

                        container['name'] = i['data'].get('title', 'No Title') + " - type: "\
                                            + i['data'].get('type', 'No Type')

                        container['id'] = i['id']

                        if i['meta'].get('tlp_color', "") in ["RED", "AMBER", "GREEN", "WHITE"]:
                            container['sensitivity'] = i['meta'].get('tlp_color', "").lower()

                        try:
                            severity = i['data']['impact']['value']
                            if severity in ["High", "Medium", "Low"]:
                                container['severity'] = severity.lower()
                        except KeyError:
                            pass

                        container['tags'] = i["meta"]["tags"]

                        if len(i["meta"].get("taxonomy_paths", "")) > 0:
                            for ii in i["meta"]["taxonomy_paths"]:
                                container['tags'].append(ii[-1])

                        artifacts = self._create_artifacts_for_event(i)
                        results.append({'container': container, 'artifacts': artifacts})

                containers_processed, artifacts_processed = \
                    self._save_results(results, containers_processed, artifacts_processed, artifact_count, container_count)

        elif feed_info[0]['update_strategy'] == 'APPEND':
            feed_last_run = {}
            feed_last_run['last_ingested'] = self._state.get('last_ingested', None)
            feed_last_run['created_at'] = self._state.get('created_at', None)

            feed_content_block_list = self.eiq_api.get_feed_content_blocks(feed=feed_info[0], feed_last_run=feed_last_run)
            containers_processed = 0
            artifacts_processed = 0

            for idx, record in enumerate(feed_content_block_list):
                if containers_processed >= container_count != 0:
                    self._state['last_ingested'] = str(record)
                    self._state['created_at'] = feed_info[0]['created_at']
                    self.save_state(self._state)

                    self.send_progress("Reached container polling limit: {0}".format(containers_processed))
                    return self.set_status(phantom.APP_SUCCESS)

                if artifacts_processed >= artifact_count != 0:
                    self._state['last_ingested'] = str(record)
                    self._state['created_at'] = feed_info[0]['created_at']
                    self.save_state(self._state)

                    self.send_progress("Reached artifacts polling limit: {0}".format(artifacts_processed))
                    return self.set_status(phantom.APP_SUCCESS)

                self.send_progress("Processing block # {0}".format(idx))
                downloaded_block = json.loads(self.eiq_api.download_block_list(record))

                events = downloaded_block.get('entities', [])
                results = []

                for i in events:
                    idref = i['meta'].get('is_unresolved_idref', False)

                    if i['data']['type'] != "relation" and idref is not True:
                        container = {}
                        container['data'] = i
                        container['source_data_identifier'] = "EIQ Platform, OF: {0}, id#{1}. Entity id:{2}"\
                            .format(feed_info[0]["name"], feed_info[0]["id"], i['id'])

                        container['name'] = i['data'].get('title', 'No Title') + " - type: "\
                                            + i['data'].get('type', 'No Type')

                        container['id'] = i['id']

                        if i['meta'].get('tlp_color', "") in ["RED", "AMBER", "GREEN", "WHITE"]:
                            container['sensitivity'] = i['meta'].get('tlp_color', "").lower()

                        try:
                            severity = i['data']['impact']['value']
                            if severity in ["High", "Medium", "Low"]:
                                container['severity'] = severity.lower()
                        except KeyError:
                            pass

                        container['tags'] = i["meta"]["tags"]

                        if len(i["meta"].get("taxonomy_paths", "")) > 0:
                            for ii in i["meta"]["taxonomy_paths"]:
                                container['tags'].append(ii[-1])

                        artifacts = self._create_artifacts_for_event(i)
                        results.append({'container': container, 'artifacts': artifacts})

                containers_processed, artifacts_processed = \
                    self._save_results(results, containers_processed, artifacts_processed, artifact_count, container_count)

                self._state['last_ingested'] = str(record)
                self._state['created_at'] = feed_info[0]['created_at']
                self.save_state(self._state)

        return self.set_status(phantom.APP_SUCCESS)

    def _save_results(self, results, containers_processed, artifacts_processed, artifacts_limit, containers_limit):
        for idx, item in enumerate(results):
            self.send_progress("Adding Container # {0}".format(idx))

            if containers_processed < containers_limit or containers_limit == 0:
                ret_val, response, container_id = self.save_container(item['container'])
                self.debug_print("save_container returns, value: {0}, reason: {1}, id: {2}".format(ret_val, response, container_id))
                containers_processed += 1
                if phantom.is_fail(ret_val):
                    continue
            else:
                return containers_processed, artifacts_processed

            artifacts = item['artifacts']
            len_artifacts = len(artifacts)

            for idx2, artifact in enumerate(artifacts):
                if artifacts_processed < artifacts_limit or artifacts_limit == 0:
                    if (idx2 + 1) == len_artifacts:
                        # mark it such that active playbooks get executed
                        artifact['run_automation'] = True

                    artifact['container_id'] = container_id
                    self.send_progress("Adding Container # {0}, Artifact # {1}".format(idx, idx2))
                    ret_val, status_string, artifact_id = self.save_artifact(artifact)
                    artifacts_processed += 1
                    self.debug_print("save_artifact returns, value: {0}, reason: {1}, id: {2}".format(ret_val, status_string, artifact_id))
                else:
                    return containers_processed, artifacts_processed

        return containers_processed, artifacts_processed

    def _create_artifacts_for_event(self, event):
        artifacts = []
        observables = event.get('extracts')

        if not observables:
            return artifacts

        for i in observables:
            artifact = dict()

            artifact['data'] = i
            artifact['source_data_identifier'] = i['value']
            artifact['name'] = (i['kind']).capitalize() + " Artifact"
            artifact['cef'] = cef = dict()
            cef['observationId'] = i['value']
            cef['msg'] = "EclecticIQ Threat Intelligence observable"

            if i['meta'].get('classification', ""):
                cef['cs2'] = i['meta']['classification']
                cef['cs2Label'] = "EclecticIQClassification"

            if i['meta'].get('confidence', ""):
                cef['cs3'] = i['meta']['confidence']
                cef['cs3Label'] = "EclecticIQConfidence"

            kind = i.get('kind', "")

            if kind in ["ipv4", "domain"]:
                cef['sourceAddress'] = i['value']
            elif kind == "uri":
                cef['requestURL'] = i['value']
            elif kind == "email":
                cef['suser'] = i['value']
            elif kind in ["hash-md5", "hash-sha1", "hash-sha256", "hash-sha512"]:
                cef['cs1'] = kind
                cef['cs1Label'] = "HashType"
                cef['fileHash'] = i['value']
                cef['hash'] = i['value']
            else:
                cef['cs1'] = kind
                cef['cs1Label'] = "EIQ_Kind"
                cef['cs2'] = i['value']
                cef['cs2Label'] = "EIQ_Value"

            artifacts.append(artifact)

        return artifacts

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Testing EclecticIQ Platform availability.")

        if self.eiq_api.headers.get('Authorization', False):
            self.save_progress("Test passed, authorization successful.")
        else:
            self.save_progress("Connectivity and auth test failed.")
            return action_result.get_status()

        if self._tip_of_id is not None:
            self.save_progress("-----------------------------------------")
            self.save_progress("Testing Outgoing Feed availability")
            outgoing_feed = self.eiq_api.get_feed_info(self._tip_of_id)

            if not outgoing_feed[0]:
                self.save_progress("Outgoing Feed check Failed.")
                return action_result.get_status()

            try:
                outgoing_feed_block_list = self.eiq_api.get_feed_content_blocks(outgoing_feed[0])
                self.save_progress("Outgoing Feed is available in the Platform. There are {0} blocks inside."
                                   .format(len(outgoing_feed_block_list)))
            except Exception as e:
                self.save_progress("Cannot collect data from Outgoing Feed. Check user permissions. Exception:" + e)

            try:
                test_block = self.eiq_api.download_block_list(outgoing_feed_block_list[0])
                json.loads(test_block)
                self.save_progress("Content test of Outgoing Feed passed.")
            except Exception as e:
                self.save_progress("Content type test of Outgoing Feed failed."
                                   " Check Content type in Platform. Exception:" + e)

        if self._tip_group is not None:
            self.save_progress("-----------------------------------------")
            self.save_progress("Testing Platform Group ID resolving")

            try:
                group_id = self.eiq_api.get_source_group_uid(self._tip_group)
                self.save_progress("Test passed, group ID: " + group_id)
            except Exception as e:
                self.save_progress("Group ID Check Failed. Exception:" + e)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        domain = param['domain']

        lookup_result = self.eiq_api.lookup_observable(domain, 'domain')

        if lookup_result is None:
            summary = action_result.update_summary({})
            summary['total_count'] = '0'
            return action_result.set_status(phantom.APP_SUCCESS, 'Domain not found in EclecticIQ Platform.')

        elif isinstance(lookup_result, dict):
            parsed_response = {
                    'last_updated': lookup_result['last_updated'],
                    'maliciousness': lookup_result['maliciousness'],
                    'value': lookup_result['value'],
                    'platform_link': lookup_result['platform_link'],
                    'source_name': lookup_result['source_name'],
                    'created': lookup_result['created']
                }
            action_result.add_data(parsed_response)

            summary = action_result.update_summary({})
            summary['total_count'] = '1'

            return action_result.set_status(phantom.APP_SUCCESS, 'Domain found in EclecticIQ Platform.')
        else:
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_email_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        email = param['email']

        lookup_result = self.eiq_api.lookup_observable(email, 'email')

        if lookup_result is None:
            summary = action_result.update_summary({})
            summary['total_count'] = '0'
            return action_result.set_status(phantom.APP_SUCCESS, 'Email not found in EclecticIQ Platform.')

        elif isinstance(lookup_result, dict):
            parsed_response = {
                    'last_updated': lookup_result['last_updated'],
                    'maliciousness': lookup_result['maliciousness'],
                    'value': lookup_result['value'],
                    'platform_link': lookup_result['platform_link'],
                    'source_name': lookup_result['source_name'],
                    'created': lookup_result['created']
                }
            action_result.add_data(parsed_response)

            summary = action_result.update_summary({})
            summary['total_count'] = '1'

            return action_result.set_status(phantom.APP_SUCCESS, 'Email found in EclecticIQ Platform.')
        else:
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_file_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        file_hash = param['hash']

        lookup_result = self.eiq_api.lookup_observable(file_hash, 'file,hash-md5,hash-sha1,hash-sha256,hash-sha512')

        if lookup_result is None:
            summary = action_result.update_summary({})
            summary['total_count'] = '0'
            return action_result.set_status(phantom.APP_SUCCESS, 'File hash not found in EclecticIQ Platform.')

        elif isinstance(lookup_result, dict):
            parsed_response = {
                    'last_updated': lookup_result['last_updated'],
                    'maliciousness': lookup_result['maliciousness'],
                    'value': lookup_result['value'],
                    'platform_link': lookup_result['platform_link'],
                    'source_name': lookup_result['source_name'],
                    'created': lookup_result['created']
                }
            action_result.add_data(parsed_response)

            summary = action_result.update_summary({})
            summary['total_count'] = '1'

            return action_result.set_status(phantom.APP_SUCCESS, 'File hash found in EclecticIQ Platform.')
        else:
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_ip_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ip = param['ip']

        lookup_result = self.eiq_api.lookup_observable(ip, 'ipv4')

        if lookup_result is None:
            summary = action_result.update_summary({})
            summary['total_count'] = '0'
            return action_result.set_status(phantom.APP_SUCCESS, 'IP not found in EclecticIQ Platform.')

        elif isinstance(lookup_result, dict):
            parsed_response = {
                    'last_updated': lookup_result['last_updated'],
                    'maliciousness': lookup_result['maliciousness'],
                    'value': lookup_result['value'],
                    'platform_link': lookup_result['platform_link'],
                    'source_name': lookup_result['source_name'],
                    'created': lookup_result['created']
                }
            action_result.add_data(parsed_response)

            summary = action_result.update_summary({})
            summary['total_count'] = '1'

            return action_result.set_status(phantom.APP_SUCCESS, 'IP found in EclecticIQ Platform.')
        else:
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_url_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        url = param['url']

        lookup_result = self.eiq_api.lookup_observable(url, 'uri')

        if lookup_result is None:
            summary = action_result.update_summary({})
            summary['total_count'] = '0'
            return action_result.set_status(phantom.APP_SUCCESS, 'URL not found in EclecticIQ Platform.')

        elif isinstance(lookup_result, dict):
            parsed_response = {
                    'last_updated': lookup_result['last_updated'],
                    'maliciousness': lookup_result['maliciousness'],
                    'value': lookup_result['value'],
                    'platform_link': lookup_result['platform_link'],
                    'source_name': lookup_result['source_name'],
                    'created': lookup_result['created']
                }
            action_result.add_data(parsed_response)

            summary = action_result.update_summary({})
            summary['total_count'] = '1'

            return action_result.set_status(phantom.APP_SUCCESS, 'URL found in EclecticIQ Platform.')
        else:
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_create_sighting(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if self._tip_group == "None":
            return RetVal(action_result.set_status(phantom.APP_ERROR, "No Group ID in asset parameters"), None)

        observables_dict = self._prepare_observables(param)

        sighting_conf_value = param['confidence_value']
        sighting_title = param['sighting_title']
        sighting_tags = param['tags'].split(",")
        sighting_impact_value = param.get('impact_value')
        sighting_description = param.get('sighting_description', "")

        sighting = self.eiq_api.create_entity(observable_dict=observables_dict, source_group_name=self._tip_group,
                                              entity_title=sighting_title, entity_description=sighting_description,
                                              entity_tags=sighting_tags, entity_confidence=sighting_conf_value,
                                              entity_impact_value=sighting_impact_value)

        action_result.add_data(sighting)
        summary = action_result.update_summary({})

        if sighting is not False:
            summary['important_data'] = 'Sighting was created in Threat Intelligence Platform.'
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            summary['important_data'] = 'Sighting wasnt created in Threat Intelligence Platform.'
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_create_indicator(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if self._tip_group == "None":
            return RetVal(action_result.set_status(phantom.APP_ERROR, "No Group ID in asset parameters"), None)

        observables_dict = self._prepare_entity_observables(param['observable_dictionary'])

        indicator_conf_value = param['confidence_value']
        indicator_title = param['indicator_title']
        indicator_tags = param['tags'].split(",")
        indicator_impact_value = param.get('impact_value')
        indicator_description = param.get('indicator_description', "")
        indicator_type = param['indicator_type']

        indicator = self.eiq_api.create_entity(observable_dict=observables_dict, source_group_name=self._tip_group,
                                              entity_title=indicator_title, entity_description=indicator_description,
                                              entity_tags=indicator_tags, entity_confidence=indicator_conf_value,
                                              entity_impact_value=indicator_impact_value, indicator_type=indicator_type,
                                              entity_type="indicator")

        action_result.add_data(indicator)
        summary = action_result.update_summary({})

        if indicator is not False:
            summary['important_data'] = 'Indicator was created in Threat Intelligence Platform.'
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            summary['important_data'] = 'Indicator wasnt created in Threat Intelligence Platform.'
            return action_result.set_status(phantom.APP_ERROR)

    def _prepare_observables(self, param):
        observable_params = [
            (
                param['sighting_maliciousness'],
                param['sighting_type'],
                param['sighting_value'],
            ),
            (
                param.get('observable_2_maliciousness'),
                param.get('observable_2_type'),
                param.get('observable_2_value'),
            ),
            (
                param.get('observable_3_maliciousness'),
                param.get('observable_3_type'),
                param.get('observable_3_value'),
            ),
        ]
        observables_list = []

        maliciousness_to_meta = {
            "Malicious (High confidence)": {
                "classification": "bad",
                "confidence": "high",
            },
            "Malicious (Medium confidence)": {
                "classification": "bad",
                "confidence": "medium",
            },
            "Malicious (Low confidence)": {
                "classification": "bad",
                "confidence": "low",
            },
            "Safe": {
                "classification": "good",
            },
            "Unknown": {
            },
        }

        for observable in observable_params:
            record = dict(
                observable_type=observable[1],
                observable_value=observable[2])

            record["observable_maliciousness"] = maliciousness_to_meta[observable[0]].get("confidence", "")
            record["observable_classification"] = maliciousness_to_meta[observable[0]].get("classification", "")

            observables_list.append(record)

        return observables_list

    def _prepare_entity_observables(self, param):
        """Method duplicate _prepare_observables method with difference in params names.
        Been added for backward compatibility.

        """
        split = (param.replace(" ", "")).split(",")

        observable_input = []

        element1 = split[::3]
        element2 = split[1::3]
        element3 = split[2::3]

        for i in range(len(element1)):
            observable_list = []
            observable_list.append(element1[i])
            observable_list.append(element2[i])
            observable_list.append(element3[i])
            observable_input.append(observable_list)

        observables_list = []

        maliciousness_to_meta = {
            "high": {
                "classification": "bad",
                "confidence": "high",
            },
            "medium": {
                "classification": "bad",
                "confidence": "medium",
            },
            "low": {
                "classification": "bad",
                "confidence": "low",
            },
            "safe": {
                "classification": "good",
            },
            "unknown": {
            },
        }

        for observable in observable_input:
            record = dict(
                observable_type=observable[1],
                observable_value=observable[0])

            record["observable_maliciousness"] = maliciousness_to_meta[observable[2]].get("confidence", "")
            record["observable_classification"] = maliciousness_to_meta[observable[2]].get("classification", "")

            observables_list.append(record)

        return observables_list

    def _handle_query_entities(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        query = param.get('query', None)

        if param['entity_type'] == "all":
            entity_type = '("campaign" OR "course-of-action" OR "exploit-target" OR "incident" OR' \
                          ' "indicator" OR "threat-actor" OR "ttp")'
        else:
            entity_type = param['entity_type']
        entity_value = param.get('entity_value', None)

        query_result = self.eiq_api.search_entity(entity_value=entity_value, entity_type=entity_type, observable_value=query)

        if query_result is not False:
            for k in query_result:
                parsed_response = {}
                if len(k['_source']['extracts']) > 0:
                    for kk in k['_source']['extracts']:
                        response_classification = kk['meta'].get('classification', 'N/A')
                        response_confidence = kk['meta'].get('confidence', 'N/A')
                        response_kind = kk.get('kind', 'N/A')
                        response_value = kk.get('value', 'N/A')
                        response_title = k['_source']['data'].get('title', 'N/A')
                        response_type = k['_source']['data'].get('type', 'N/A')
                        response_description = k['_source']['data'].get('description', 'N/A')
                        response_threat_start = k['_source']['meta'].get('estimated_threat_start_time', 'N/A')
                        response_tags = ''
                        response_source_name = k['_source']['sources'][0].get('name', 'N/A')
                        response_tags = ', '.join(k['_source']['tags'])
                        parsed_response = {
                                'extract_kind': response_kind,
                                'extract_value': response_value,
                                'extract_classification': response_classification,
                                'extract_confidence': response_confidence,
                                'title': response_title,
                                'type': response_type,
                                'description': response_description,
                                'threat_start': response_threat_start,
                                'tags': response_tags,
                                'source_name': response_source_name
                            }
                        action_result.add_data(parsed_response)
                else:
                    response_classification = 'N/A'
                    response_confidence = 'N/A'
                    response_kind = 'N/A'
                    response_value = 'N/A'
                    response_title = k['_source']['data'].get('title', 'N/A')
                    response_description = k['_source']['data'].get('description', 'N/A')
                    response_threat_start = k['_source']['meta'].get('estimated_threat_start_time', 'N/A')
                    response_tags = ''
                    response_source_name = k['_source']['sources'][0].get('name', 'N/A')
                    response_tags = ', '.join(k['_source']['tags'])
                    parsed_response = {
                        'extract_kind': response_kind,
                        'extract_value': response_value,
                        'extract_classification': response_classification,
                        'extract_confidence': response_confidence,
                        'title': response_title,
                        'description': response_description,
                        'threat_start': response_threat_start,
                        'tags': response_tags,
                        'source_name': response_source_name
                    }
                    action_result.add_data(parsed_response)

            action_result.add_extra_data(query_result)
            summary = action_result.update_summary({})
            summary['total_count'] = len(query_result)

            return action_result.set_status(phantom.APP_SUCCESS, 'Entity found in EclecticIQ Platform.')

        elif query_result is False:
            summary = action_result.update_summary({})
            summary['total_count'] = '0'
            return action_result.set_status(phantom.APP_SUCCESS, 'No entities found in EclecticIQ Platform.')
        else:
            return action_result.set_status(phantom.APP_ERROR)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'domain_reputation':
            ret_val = self._handle_domain_reputation(param)

        elif action_id == 'file_reputation':
            ret_val = self._handle_file_reputation(param)

        elif action_id == 'ip_reputation':
            ret_val = self._handle_ip_reputation(param)

        elif action_id == 'url_reputation':
            ret_val = self._handle_url_reputation(param)

        elif action_id == 'email_reputation':
            ret_val = self._handle_email_reputation(param)

        elif action_id == 'create_sighting':
            ret_val = self._handle_create_sighting(param)

        elif action_id == 'create_indicator':
            ret_val = self._handle_create_indicator(param)

        elif action_id == 'query_entities':
            ret_val = self._handle_query_entities(param)

        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

        return ret_val

    def initialize(self):

        self._state = self.load_state()
        # get the asset config
        config = self.get_config()

        self.eiq_api = EclecticIQ_api(baseurl=config['tip_uri'],
                                      eiq_version='2.4',
                                      username=config['tip_user'],
                                      password=config['tip_password'],
                                      verify_ssl=config.get('tip_ssl_check', False),
                                      proxy_ip=config.get('tip_proxy_uri', None),
                                      proxy_password=config.get('tip_proxy_password', None),
                                      proxy_username=config.get('tip_proxy_user', None))

        self._tip_group = config.get('tip_group', None)
        self._tip_of_id = config.get('tip_of_id', None)

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = EclecticiqAppConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
