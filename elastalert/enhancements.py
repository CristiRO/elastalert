# -*- coding: utf-8 -*-
from .util import pretty_ts
from .util import elastalert_logger
import datetime
import requests
import json
import re
import alienpy.alien as alien

class BaseEnhancement(object):
    """ Enhancements take a match dictionary object and modify it in some way to
    enhance an alert. These are specified in each rule under the match_enhancements option.
    Generally, the key value pairs in the match module will be contained in the alert body. """

    def __init__(self, rule):
        self.rule = rule

    def process(self, match):
        """ Modify the contents of match, a dictionary, in some way """
        raise NotImplementedError()


class TimeEnhancement(BaseEnhancement):
    def process(self, match):
        match['@timestamp'] = pretty_ts(match['@timestamp'])


class DropMatchException(Exception):
    """ ElastAlert will drop a match if this exception type is raised by an enhancement """
    pass

class FileFilterEnhancement(BaseEnhancement):
    jalienClient = None

    def process(self, match):
        fileName = match['arguments.keyword']
        if not self.isFile(fileName):
            elastalert_logger.info('Dropped down the match with name={}. Reason: it does not appear to be a file.'.format(fileName))
            raise DropMatchException()

        if self.isRegularUserFile(fileName):
            elastalert_logger.info('Dropped down the match with name={}. Reason: it appears to be a regular user file.'.format(fileName))
            raise DropMatchException()

        if not self.jalienClient:
            self.jalienClient = alien.AliEn()
        out = self.jalienClient.run('stat ' + fileName)
        if not out.ansdict['results']:
            elastalert_logger.info('Dropped down the match with name={}. Reason: file does not exist anymore.'.format(fileName))
            raise DropMatchException()

        size = out.ansdict['results'][0]['size']

        #TODO: instead of using requests, elasticsearch client should be used, as in the main class of ElastAlert
        requestData = {"query":{"bool":{"must":[{"match_phrase":{"arguments":{"query":fileName}}},{"match_phrase":{"arguments":{"query":"read"}}},{"range":{"@timestamp":{"gte":"now-1d","lte":"now","format":"epoch_millis"}}},{"match_phrase":{"arguments":{"query":fileName}}},{"match_phrase":{"arguments":{"query":"read"}}}],"should":[],"must_not":[]}}}
        headers = {'Content-type': 'application/json'}

        #TODO: this url should be configurable (es_endpoint, es_port, es_index)
        url = "http://localhost:9200/logstash-new-*/_search"

        response = requests.request(method='get', url=url, data=json.dumps(requestData), headers=headers)
        numHits = response.json()['hits']['total']

        limit = 1024 * 1024 * 1024 * 240 #240GB
        bandwidth = int(size) * int(numHits)
        bandwidthInGB = str(round(bandwidth / (1024 * 1024 * 1024), 2))
        if bandwidth < limit:
            elastalert_logger.info('Dropped down the match with name={}. Reason: total bandwidth not exceeded. Bandwidth used={}GB'.format(fileName, bandwidthInGB))
            raise DropMatchException()

        match['file_name'] = match['arguments.keyword']
        match['occurences'] = numHits
        match['bandwidth_used_GB'] = bandwidthInGB

        match.pop('arguments.keyword', None)
        match.pop('num_hits', None)
        match.pop('num_matches', None)

    def isFile(self, fileName):
        return '/alice' in fileName

    def isRegularUserFile(self, fileName):
        return '/user/' in fileName and '/user/a/alitrain' not in fileName and '/user/a/aliprod' not in fileName

class UserFileEnhancement(BaseEnhancement):
    jalienClient = None

    def process(self, match):
        fileName = match['arguments.keyword']

        if not self.isFile(fileName):
            elastalert_logger.info('Dropped down the match with name={}. Reason: it does not appear to be a file.'.format(fileName))
            raise DropMatchException()

        if not self.isRegularUserFile(fileName):
            elastalert_logger.info('Dropped down the match with name={}. Reason: it does not appear to be a regular user file.'.format(fileName))
            raise DropMatchException()

        if not self.jalienClient:
            self.jalienClient = alien.AliEn()
        out = self.jalienClient.run('stat ' + fileName)
        if not out.ansdict['results']:
            elastalert_logger.info('Dropped down the match with name={}. Reason: file does not exist anymore.'.format(fileName))
            raise DropMatchException()
        size = out.ansdict['results'][0]['size']

        requestData = {"query":{"bool":{"must":[{"match_phrase":{"arguments":{"query":fileName}}},{"match_phrase":{"arguments":{"query":"read"}}},{"range":{"@timestamp":{"gte":"now-1d","lte":"now","format":"epoch_millis"}}},{"match_phrase":{"arguments":{"query":fileName}}},{"match_phrase":{"arguments":{"query":"read"}}}],"should":[],"must_not":[]}}}
        headers = {'Content-type': 'application/json'}

        #TODO: this url should be configurable (es_endpoint, es_port, es_index)
        url = "http://localhost:9200/logstash-new-*/_search"

        response = requests.request(method='get', url=url, data=json.dumps(requestData), headers=headers)
        numHits = response.json()['hits']['total']

        limit = 24 * 1024 * 1024 * 1024 #24 GB
        bandwidth = int(size) * int(numHits)
        bandwidthInGB = str(round(bandwidth / (1024 * 1024 * 1024), 2))
        if bandwidth < limit:
            elastalert_logger.info('Dropped down the match with name={}. Reason: total bandwidth not exceeded. Bandwidth used={}GB'.format(fileName, bandwidthInGB))
            raise DropMatchException()

        # Extracting some jobIds
        clientId = response.json()['hits']['hits'][0]['_source']['clientID']
        # TODO: check jAliEn script why it does not backfill
        requestData = {"sort":[{"@timestamp":{"order":"desc","unmapped_type":"boolean"}}],"query":{"bool":{"must":[{"range":{"@timestamp":{"gte":"now-1d","lte":"now","format":"epoch_millis"}}}],"filter":[{"bool":{"filter":[{"bool":{"should":[{"match":{"command":"login"}}],"minimum_should_match":1}},{"bool":{"filter":[{"bool":{"should":[{"query_string":{"fields":["arguments"],"query":"*queueid*"}}],"minimum_should_match":1}},{"bool":{"should":[{"match":{"clientID":clientId}}],"minimum_should_match":1}}]}}]}}],"should":[],"must_not":[]}}}

        response = requests.request(method='get', url=url, data=json.dumps(requestData), headers=headers)

        jobIds = []
        for hit in response.json()['hits']['hits']:
            argument = hit['_source']['arguments'][0]
            for s in argument.split(","):
                if 'queueid' in s:
                    try:
                        found = re.search('OU=queueid\\\\=(.+?)/resubmission\\\\=(.+?)', s).group(1)
                        jobIds.append(found)
                    except AttributeError:
                        found = ''

        match['file_name'] = match['arguments.keyword']
        match['occurences'] = numHits
        match['bandwidth_used_GB'] = bandwidthInGB
        match['last_10_queueIds_of_this_clientID'] = ', '.join(jobIds)

        match.pop('arguments.keyword', None)
        match.pop('num_hits', None)
        match.pop('num_matches', None)

    def isFile(self, fileName):
        return '/alice' in fileName

    def isRegularUserFile(self, fileName):
        return '/user/' in fileName and '/user/a/alitrain' not in fileName and '/user/a/aliprod' not in fileName

class WeekendFilterEnhancement(BaseEnhancement):
    def process(self, match):
        dayOfTheWeek = datetime.datetime.today().isoweekday()
        fileName = match['file_name']
        if dayOfTheWeek == 6 or dayOfTheWeek == 7:
            elastalert_logger.info('Dropped down the match with name={}. Reason: nobody should work in the weekend!'.format(fileName))
            raise DropMatchException()
