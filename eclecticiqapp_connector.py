# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from eclecticiqapp_consts import *
import requests
import json
from bs4 import BeautifulSoup
import urllib
import re


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class EclecticiqAppConnector(BaseConnector):

    def __init__(self):

        super(EclecticiqAppConnector, self).__init__()
        self._state = None
        self._headers = None
        self._base_url = None

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})
        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately
        # Process a json response
        if 'json' or 'octet-stream' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers={}, params=None, data=None, method="get"):

        config = self.get_config()
        headers.update(self._headers)
        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            data=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_on_poll(self, param):

        # TD check limitations in feed, how many containers and artifacts to ingest
        # TD self._tip_of_id availabilty before run anything

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if self._tip_of_id == "None":
            return RetVal(action_result.set_status(phantom.APP_ERROR, "No Outgoing Feed ID in asset parameters"), None)

        endpoint_uri = '/private/outgoing-feed-download/' + str(self._tip_of_id) + '/runs/latest'
        ret_val, response = self._make_rest_call(endpoint_uri, action_result, headers=self._headers)

        uri_list = response['data']['content_blocks']

        for k in range(len(uri_list)):

            self.send_progress("Processing block # {0}".format(k))

            ret_val, response = self._make_rest_call(str(uri_list[k]), action_result, headers=self._headers)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            events = response.get('entities', [])

            results = []

            for i, event in enumerate(events):
                self.send_progress("Processing Container # {0}".format(i))

                try:
                    idref = event['meta']['is_unresolved_idref']
                except KeyError:
                    idref = False

                if event['data']['type'] != "relation" and idref is not True:
                    container = dict()
                    container['data'] = event
                    container['source_data_identifier'] = event['id']
                    container['name'] = event['data']['title'] + " - type:" + event['data']['type']
                    container['id'] = event['id']

                    try:
                        sensitivity = event['meta']['tlp_color']
                        if sensitivity == "RED":
                            container['sensitivity'] = "red"
                        elif sensitivity == "AMBER":
                            container['sensitivity'] = "amber"
                        elif sensitivity == "GREEN":
                            container['sensitivity'] = "green"
                        elif sensitivity == "WHITE":
                            container['sensitivity'] = "white"
                        else:
                            container['sensitivity'] = ''
                    except KeyError:
                        pass

                    try:
                        severity = event['data']['impact']['value']
                        if severity == "High":
                            container['severity'] = "high"
                        elif severity == "Medium":
                            container['severity'] = "medium"
                        elif severity == "Low":
                            container['severity'] = "low"
                        else:
                            container['severity'] = ''
                    except KeyError:
                        pass

                    container['tags'] = []

                    try:
                        if len(event["meta"]["tags"]) > 0:
                            for i in range(len(event["meta"]["tags"])):
                                container['tags'].append(event["meta"]["tags"][i])
                    except KeyError:
                        pass

                    try:
                        if len(event["meta"]["taxonomy_paths"]) > 0:
                            for i in range(len(event["meta"]["taxonomy_paths"])):
                                container['tags'].append(event["meta"]["taxonomy_paths"][i][-1])
                    except KeyError:
                        pass

                    artifacts = self._create_artifacts_for_event(event, i)
                    results.append({'container': container, 'artifacts': artifacts})

            self._save_results(results)

        return self.set_status(phantom.APP_SUCCESS)

    def _save_results(self, results):

        containers_processed = 0
        for i, result in enumerate(results):

            # result is a dictionary of a single container and artifacts
            if ('container' not in result):
                continue

            if ('artifacts' not in result):
                # igonore containers without artifacts
                continue

            if (len(result['artifacts']) == 0):
                # igonore containers without artifacts
                continue

            containers_processed += 1

            self.send_progress("Adding Container # {0}".format(i))
            ret_val, response, container_id = self.save_container(result['container'])
            self.debug_print("save_container returns, value: {0}, reason: {1}, id: {2}".format(ret_val, response, container_id))

            if (phantom.is_fail(ret_val)):
                continue

            if (not container_id):
                continue

            if ('artifacts' not in result):
                continue

            artifacts = result['artifacts']

            # get the length of the artifact, we might have trimmed it or not
            len_artifacts = len(artifacts)

            for j, artifact in enumerate(artifacts):

                # if it is the last artifact of the last container
                if ((j + 1) == len_artifacts):
                    # mark it such that active playbooks get executed
                    artifact['run_automation'] = True

                artifact['container_id'] = container_id
                self.send_progress("Adding Container # {0}, Artifact # {1}".format(i, j))
                ret_val, status_string, artifact_id = self.save_artifact(artifact)
                self.debug_print("save_artifact returns, value: {0}, reason: {1}, id: {2}".format(ret_val, status_string, artifact_id))

        return containers_processed

    def _create_artifacts_for_event(self, event, container_index):

        artifacts = []

        observables = event.get('extracts')

        if (not observables):
            return artifacts

        # event_id = event['id']

        for i, observation in enumerate(observables):

            self.send_progress("Processing Container # {0} Artifact # {1}".format(container_index, i))

            artifact = dict()

            artifact['data'] = observation
            artifact['source_data_identifier'] = observation['value']
            artifact['name'] = (observation['kind']).capitalize() + " Artifact"
            artifact['cef'] = cef = dict()
            cef['observationId'] = observation['value']
            cef['msg'] = "EclectiIQ Threat Intelligence observable"

            try:
                if observation['meta']['classification']:
                    cef['cs2'] = observation['meta']['classification']
                    cef['cs2Label'] = "EclecticIQClassification"
            except KeyError:
                pass

            try:
                if observation['meta']['confidence']:
                    cef['cs3'] = observation['meta']['confidence']
                    cef['cs3Label'] = "EclecticIQConfidence"
            except KeyError:
                pass

            try:
                kind = observation['kind']
                if kind == "ipv4":
                    cef['sourceAddress'] = observation['value']
                elif kind == "domain":
                    cef['sourceAddress'] = observation['value']
                elif kind == "uri":
                    cef['requestURL'] = observation['value']
                elif kind == "email":
                    cef['suser'] = observation['value']
                elif kind == "hash-md5":
                    cef['cs1'] = kind
                    cef['cs1Label'] = "HashType"
                    cef['fileHash'] = observation['value']
                elif kind == "hash-sha1":
                    cef['cs1'] = kind
                    cef['cs1Label'] = "HashType"
                    cef['fileHash'] = observation['value']
                elif kind == "hash-sha256":
                    cef['cs1'] = kind
                    cef['cs1Label'] = "HashType"
                    cef['fileHash'] = observation['value']
                elif kind == "hash-sha512":
                    cef['cs1'] = kind
                    cef['cs1Label'] = "HashType"
                    cef['fileHash'] = observation['value']
            except KeyError:
                pass

            artifacts.append(artifact)

        return artifacts

    def _handle_test_connectivity(self, param):

        # TD add visual delimitation of checks and add conditions for checkings group ID and feed ID for polling
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Testing TIP availability by sending request to /status/ endpoint")
        ret_val, response = self._make_rest_call('/private/status', action_result, headers=self._headers)
        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()
        message_status = response['data']['celery_nodes_state']['health']
        self.save_progress("Test passed, TIP status: " + message_status)
        self.save_progress("-----------------------------------------")

        if self._tip_of_id != "None":
            self.save_progress("Testing Outgoing Feed availability")
            endpoint_uri = '/private/outgoing-feed-download/' + str(self._tip_of_id) + '/runs/latest'
            ret_val, response = self._make_rest_call(endpoint_uri, action_result, headers=self._headers)
            if (phantom.is_fail(ret_val)):
                self.save_progress("Outgoing Feed check Failed.")
                return action_result.get_status()
            message_status = str(len(response['data']['content_blocks']))
            self.save_progress("Test passed, in Outgoing Feed: " + message_status + " blocks.")
            self.save_progress("-----------------------------------------")

        if self._tip_group != "None":
            self.save_progress("Testing Group ID resolving")
            group_uri = '/private/groups?filter[name]=' + str(self._tip_group)
            ret_val, response = self._make_rest_call(group_uri, action_result, headers=self._headers)
            if (phantom.is_fail(ret_val)):
                self.save_progress("Group ID Check Failed.")
                return action_result.get_status()
            message_status = response['data'][0]['source']
            self.save_progress("Test passed, group ID: " + message_status)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_reputation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        domain = param['domain']
        endpoint_uri = "/api/observables?filter[type]=domain&filter[value]=" + urllib.quote_plus(domain)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint_uri, action_result, headers=self._headers)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})

        if response['total_count'] >= 1:
            summary['TIP_uri'] = self._base_url + '/observables/' + str(response['data'][0]['type']) + '/' + urllib.quote_plus(domain)
            summary['important_data'] = 'Domain found in Threat Intelligence Platform.'
        else:
            summary['important_data'] = 'Domain not found in Threat Intelligence Platform.'

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_email_reputation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        email = param['email']
        endpoint_uri = "/api/observables?filter[type]=email&filter[value]=" + urllib.quote_plus(email)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint_uri, action_result, headers=self._headers)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})

        if response['total_count'] >= 1:
            summary['TIP_uri'] = self._base_url + '/observables/' + str(response['data'][0]['type']) + '/' + urllib.quote_plus(email)
            summary['important_data'] = 'Email found in Threat Intelligence Platform.'
        else:
            summary['important_data'] = 'Email not found in Threat Intelligence Platform.'

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_file_reputation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        file_hash = param['hash']
        endpoint_uri = "/api/observables?filter[type]=file,hash-md5,hash-sha1,hash-sha256,hash-sha512&filter[value]=" + urllib.quote_plus(file_hash)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint_uri, action_result, headers=self._headers)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})

        if response['total_count'] >= 1:
            summary['TIP_uri'] = self._base_url + '/observables/' + str(response['data'][0]['type']) + '/' + urllib.quote_plus(file_hash)
            summary['important_data'] = 'File hash found in Threat Intelligence Platform.'
        else:
            summary['important_data'] = 'File hash not found in Threat Intelligence Platform.'

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ip_reputation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        ip = param['ip']
        endpoint_uri = "/api/observables?filter[type]=ipv4&filter[value]=" + urllib.quote_plus(ip)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint_uri, action_result, headers=self._headers)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})

        if response['total_count'] >= 1:
            summary['TIP_uri'] = self._base_url + '/observables/' + str(response['data'][0]['type']) + '/' + urllib.quote_plus(ip)
            summary['important_data'] = 'IP found in Threat Intelligence Platform.'
        else:
            summary['important_data'] = 'IP not found in Threat Intelligence Platform.'

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_url_reputation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        url = param['url']
        endpoint_uri = "/api/observables?filter[type]=uri&filter[value]=" + urllib.quote_plus(url)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint_uri, action_result, headers=self._headers)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})

        if response['total_count'] >= 1:
            summary['TIP_uri'] = self._base_url + '/observables/' + str(response['data'][0]['type']) + '/' + urllib.quote_plus(url)
            summary['important_data'] = 'URL found in Threat Intelligence Platform.'
        else:
            summary['important_data'] = 'URL not found in Threat Intelligence Platform.'

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_sighting(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if self._tip_group == "None":
            return RetVal(action_result.set_status(phantom.APP_ERROR, "No Group ID in asset parameters"), None)

        group_uri = '/private/groups?filter[name]=' + str(self._tip_group)

        ret_val, response = self._make_rest_call(group_uri, action_result, headers=self._headers)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        group_id = response['data'][0]['source']

        sighting_type = param['sighting_type']
        sighting_value = param['sighting_value']
        sighting_conf_value = param['confidence_value']
        sighting_title = param['sighting_title']
        sighting_tags = param['tags'].split(",")

        try:
            sighting_description = param['description']
        except KeyError:
            sighting_description = ""
            pass

        sighting = {
            "data": {
                "data": {
                    "confidence": {
                        "type": "confidence",
                        "value": sighting_conf_value
                    },
                    "description": sighting_description,
                    "related_extracts": [{
                        "type": "eclecticiq-extract",
                        "kind": sighting_type,
                        "value": sighting_value
                    }],
                    "description_structuring_format": "html",
                    "type": "eclecticiq-sighting",
                    "title": sighting_title,
                    "security_control": {
                        "type": "information-source",
                        "identity": {
                            "name": "EclecticIQ App for Phantom",
                            "type": "identity"
                        }
                    }
                },
                "meta": {
                    "taxonomy": [],
                    "tags": sighting_tags
                    # ["Phantom Sighting"]
                },
                "sources": [{
                    "source_id": str(group_id)
                }]
            }
        }

        sightings_uri = '/private/entities/'

        ret_val, response = self._make_rest_call(sightings_uri, action_result, headers=self._headers, data=json.dumps(sighting), method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})

        try:
            len(response['data'])
            summary['important_data'] = 'Sighting was created in Threat Intelligence Platform.'
            return action_result.set_status(phantom.APP_SUCCESS)
        except:
            summary['important_data'] = 'Sighting wasnt created in Threat Intelligence Platform.'
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_query_entities(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        query = param['query']
        endpoint_uri = "/private/search-all?q={0}&type=indicator".format(query)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint_uri, action_result, headers=self._headers)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['important_data'] = "value"

        return action_result.set_status(phantom.APP_SUCCESS)

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

        elif action_id == 'query_entities':
            ret_val = self._handle_query_entities(param)

        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

        return ret_val

    def initialize(self):

        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = re.sub(r"(https?\:\/\/[^\/]+)(.*)", r"\1", config['tip_uri'])
        try:
            self._tip_of_id = config['tip_of_id']
        except:
            self._tip_of_id = "None"

        try:
            self._tip_group = config['tip_group']
        except:
            self._tip_group = "None"

        auth_uri = self._base_url + '/api/auth'
        self._headers = {'user-agent': 'Phantom Cyber', 'Content-Type': 'application/json', 'Accept': 'application/json'}
        data = dict()
        data['username'] = config.get('tip_user')
        data['password'] = config.get('tip_password')

        r = requests.post(auth_uri, headers=self._headers, data=json.dumps(data), verify=False)

        self._headers['Authorization'] = 'Bearer ' + r.json()['token']

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
