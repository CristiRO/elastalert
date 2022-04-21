# -*- coding: utf-8 -*-
from fileinput import filename
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
        self.es_client = elasticsearch_client(self.rule)

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

        requestData = {"query":{"bool":{"must":[{"match_phrase":{"file_path":{"query":fileName}}},{"range":{"@timestamp":{"gte":"now-1d","lte":"now","format":"epoch_millis"}}},{"match_phrase":{"file_path":{"query":fileName}}}],"should":[],"must_not":[]}}}

        response = self.es_client.count(index="popularity*", body=json.dumps(requestData))

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
        self.es_client = elasticsearch_client(self.rule)

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

        requestData = {"query":{"bool":{"must":[{"match_phrase":{"file_path":{"query":fileName}}},{"range":{"@timestamp":{"gte":"now-1d","lte":"now","format":"epoch_millis"}}},{"match_phrase":{"file_path":{"query":fileName}}}],"should":[],"must_not":[]}}}

        response = self.es_client.search(index="popularity*", body=json.dumps(requestData), track_total_hits=True)

        numHits = response['hits']['total']['value']

        limit = 24 * 1024 * 1024 * 1024 #24 GB
        bandwidth = int(size) * int(numHits)
        bandwidthInGB = str(round(bandwidth / (1024 * 1024 * 1024), 2))
        if bandwidth < limit:
            elastalert_logger.info('Dropped down the match with name={}. Reason: total bandwidth not exceeded. Bandwidth used={}GB'.format(fileName, bandwidthInGB))
            raise DropMatchException()

        # Extracting some jobIds
        requestDataFirstPhase = {"query":{"bool":{"filter":[{"bool":{"filter":[{"bool":{"minimum_should_match":1,"should":[{"match_phrase":{"arguments.keyword":fileName}}]}},{"bool":{"minimum_should_match":1,"should":[{"bool":{"minimum_should_match":1,"should":[{"match_phrase":{"command.keyword":"PFNforReadOrDel"}}]}},{"bool":{"minimum_should_match":1,"should":[{"match_phrase":{"command.keyword":"access"}}]}}]}}]}},{"range":{"@timestamp":{"gte":"now-1d","lte":"now"}}}],"must":[],"must_not":[],"should":[]}},"collapse":{"field":"address.keyword","inner_hits":{"name":"latest","size":1,"sort":[{"@timestamp":"desc"}],"_source":"false","docvalue_fields":["address.keyword"]}}}
        elastalert_logger.info("Searching collapsed results for different adresses of fileName={}".format(filename))

        response = self.es_client.search(index="logstash-new-*", body=json.dumps(requestDataFirstPhase))

        jobIds = []
        for hit in response['hits']['hits']:
            address = hit['fields']['address.keyword'][0]
            elastalert_logger.info("Got address={} for fileName={}. Searching for jobId...".format(address, fileName))
            requestDataSecondPhase = {"query":{"bool":{"filter":[{"bool":{"filter":[{"bool":{"minimum_should_match":1,"should":[{"match_phrase":{"address.keyword":address}}]}},{"bool":{"minimum_should_match":1,"should":[{"match_phrase":{"command.keyword":"login"}}]}}]}},{"range":{"@timestamp":{"gte":"now-2d","lte":"now"}}}],"must":[],"must_not":[],"should":[]}}}
            innerResponse = self.es_client.search(index="logstash-new-*", body=json.dumps(requestDataSecondPhase))
            rawArgument = innerResponse['hits']['hits'][0]['_source']['arguments'][0]
            for s in rawArgument.split(","):
                if 'queueid' in s:
                    try:
                        found = re.search('OU=queueid\\\\=(.+?)/resubmission\\\\=(.+?)', s).group(1)
                        formatted = '[' + found + '](https://alimonitor.cern.ch/jobs/jdl.jsp?pid=' + found + ")"
                        jobIds.append(formatted)
                    except AttributeError:
                        found = ''

        # clientId = response['hits']['hits'][0]['_source']['clientID']
        # elastalert_logger.info("Searching some jobIds for clientId={} and fileName={}".format(clientId, fileName))
        # requestData = {"sort":[{"@timestamp":{"order":"desc","unmapped_type":"boolean"}}],"query":{"bool":{"must":[{"match_phrase":{"command":{"query":"login"}}},{"match_phrase":{"clientID":{"query":clientId}}},{"range":{"@timestamp":{"gte":"now-1d","lte":"now","format":"epoch_millis"}}}]}}}

        # response = self.es_client.search(index="alicecs1-jalien-*", body=json.dumps(requestData))

        # jobIds = []
        # for hit in response['hits']['hits']:
        #     argument = hit['_source']['arguments'][0]
        #     for s in argument.split(","):
        #         if 'queueid' in s:
        #             try:
        #                 found = re.search('OU=queueid\\\\=(.+?)/resubmission\\\\=(.+?)', s).group(1)
        #                 formatted = '[' + found + '](https://alimonitor.cern.ch/jobs/jdl.jsp?pid=' + found + ")"
        #                 jobIds.append(formatted)
        #             except AttributeError:
        #                 found = ''

        match['file_name'] = match['file_path.keyword']
        match['occurences'] = numHits
        match['bandwidth_used_GB'] = bandwidthInGB
        if jobIds:
            match['last_10_queueIds_of_this_clientID'] = ', '.join(jobIds)
        else:
            match['last_10_queueIds_of_this_clientID'] = 'No queueId found.'
        # match['last_10_queueIds_of_this_clientID'] = 'QueueID temporary disabled'

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
