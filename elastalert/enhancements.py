# -*- coding: utf-8 -*-
from .util import pretty_ts
from .util import elastalert_logger
import datetime
import requests
import json
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
    def process(self, match):
        fileName = match['arguments.keyword']
        if '/alice/' not in fileName:
            elastalert_logger.info('Dropped down the match with name={}. Reason: it does not appear to be a file.'.format(fileName))
            raise DropMatchException()

        alien.setup_logging()
        j = alien.AliEn()
        out = j.run('stat ' + fileName)
        size = out.ansdict['results'][0]['size']
        # size = 1024 * 100 # temporary for testing

        requestData = {"query":{"bool":{"must":[{"match_phrase":{"arguments":{"query":fileName}}},{"match_phrase":{"arguments":{"query":"read"}}},{"range":{"@timestamp":{"gte":"now-1d","lte":"now","format":"epoch_millis"}}},{"match_phrase":{"arguments":{"query":fileName}}},{"match_phrase":{"arguments":{"query":"read"}}}],"should":[],"must_not":[]}}}
        headers = {'Content-type': 'application/json'}

        #TODO: this url should be configurable (es_endpoint, es_port, es_index)
        url = "http://localhost:9200/logstash-new-*/_search"

        response = requests.request(method='get', url=url, data=json.dumps(requestData), headers=headers)
        numHits = response.json()['hits']['total']

        limit = 1024 * 1024 * 1024 #1GB
        bandwidth = int(size) * int(numHits)
        bandwidthInGB = str(round(bandwidth / limit, 2))
        if bandwidth < limit:
            elastalert_logger.info('Dropped down the match with name={}. Reason: total bandwidth not exceeded. Bandwidth used={}GB'.format(fileName, bandwidthInGB))
            raise DropMatchException()

        match['file_name'] = match['arguments.keyword']
        match['occurences'] = numHits
        match['bandwidth_used_GB'] = bandwidthInGB

        match.pop('arguments.keyword', None)
        match.pop('num_hits', None)
        match.pop('num_matches', None)

class WeekendFilterEnhancement(BaseEnhancement):
    def process(self, match):
        dayOfTheWeek = datetime.datetime.today().isoweekday()
        fileName = match['file_name']
        if dayOfTheWeek == 6 or dayOfTheWeek == 7:
            elastalert_logger.info('Dropped down the match with name={}. Reason: nobody should work in the weekend!'.format(fileName))
            raise DropMatchException()
