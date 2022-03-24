# -*- coding: utf-8 -*-
from .util import pretty_ts
from .util import elastalert_logger
from .util import elasticsearch_client
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
    es_client = None

    def __init__(self, rule):
        self.rule = rule

        conf = {}
        conf['es_host'] = 'alice-logstash.cern.ch'
        conf['es_port'] = '9200'
        conf['es_conn_timeout'] = '600'
        self.es_client = elasticsearch_client(conf)

    def process(self, match):
        fileName = match['file_path.keyword']
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

        response = self.es_client.count(index="alicecs1-jalien-*", body=json.dumps(requestData))

        numHits = response['count']

        limit = 1024 * 1024 * 1024 * 240 #240GB
        bandwidth = int(size) * int(numHits)
        bandwidthInGB = str(round(bandwidth / (1024 * 1024 * 1024), 2))
        if bandwidth < limit:
            elastalert_logger.info('Dropped down the match with name={}. Reason: total bandwidth not exceeded. Bandwidth used={}GB'.format(fileName, bandwidthInGB))
            raise DropMatchException()

        match['file_name'] = match['file_path.keyword']
        match['occurences'] = numHits
        match['bandwidth_used_GB'] = bandwidthInGB

        match.pop('file_path.keyword', None)
        match.pop('num_hits', None)
        match.pop('num_matches', None)

    def isFile(self, fileName):
        return '/alice' in fileName

    def isRegularUserFile(self, fileName):
        return '/user/' in fileName and '/user/a/alitrain' not in fileName and '/user/a/aliprod' not in fileName

class UserFileEnhancement(BaseEnhancement):
    jalienClient = None
    es_client = None

    def __init__(self, rule):
        self.rule = rule

        conf = {}
        conf['es_host'] = 'alice-logstash.cern.ch'
        conf['es_port'] = '9200'
        conf['es_conn_timeout'] = '600'
        self.es_client = elasticsearch_client(conf)

    def process(self, match):
        fileName = match['file_path.keyword']

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

        response = self.es_client.search(index="alicecs1-jalien-*", body=json.dumps(requestData), track_total_hits=True)

        numHits = response['hits']['total']['value']

        limit = 24 * 1024 * 1024 * 1024 #24 GB
        bandwidth = int(size) * int(numHits)
        bandwidthInGB = str(round(bandwidth / (1024 * 1024 * 1024), 2))
        if bandwidth < limit:
            elastalert_logger.info('Dropped down the match with name={}. Reason: total bandwidth not exceeded. Bandwidth used={}GB'.format(fileName, bandwidthInGB))
            raise DropMatchException()

        # Extracting some jobIds
        clientId = response['hits']['hits'][0]['_source']['clientID']
        elastalert_logger.info("Searching some jobIds for clientId={} and fileName={}".format(clientId, fileName))
        requestData = {"sort":[{"@timestamp":{"order":"desc","unmapped_type":"boolean"}}],"query":{"bool":{"must":[{"match_phrase":{"command":{"query":"login"}}},{"match_phrase":{"clientID":{"query":clientId}}},{"range":{"@timestamp":{"gte":"now-1d","lte":"now","format":"epoch_millis"}}}]}}}

        response = self.es_client.search(index="alicecs1-jalien-*", body=json.dumps(requestData))

        jobIds = []
        for hit in response['hits']['hits']:
            argument = hit['_source']['arguments'][0]
            for s in argument.split(","):
                if 'queueid' in s:
                    try:
                        found = re.search('OU=queueid\\\\=(.+?)/resubmission\\\\=(.+?)', s).group(1)
                        formatted = '[' + found + '](https://alimonitor.cern.ch/jobs/jdl.jsp?pid=' + found + ")"
                        jobIds.append(formatted)
                    except AttributeError:
                        found = ''

        match['file_name'] = match['file_path.keyword']
        match['occurences'] = numHits
        match['bandwidth_used_GB'] = bandwidthInGB
        if jobIds:
            match['last_10_queueIds_of_this_clientID'] = ', '.join(jobIds)
        else:
            match['last_10_queueIds_of_this_clientID'] = 'No queueId found for clientID={}'.format(clientId)

        match.pop('file_path.keyword', None)
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
