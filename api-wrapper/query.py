import logging
import uuid
from dotenv import load_dotenv
from urllib.parse import urljoin
from datetime import datetime, timezone
import dateparser
import json
import yaml
import traceback
import requests

logger = logging.getLogger(__name__)

# token - access_token
# Request header - Authorization: Bearer <token>
authToken = {}
dataSets = []
queryConfig = {}

def localLog(msg, printit=False, level=None):
    if printit:
        print(msg)
    
    if level:
        logger.log(level, msg)


def getAuthToken():
    global authToken
    localLog('Loading auth token', False, logging.INFO)
    with open('token.json') as f:
        token = json.load(f)
    
    # check the token
    expiry = dateparser.parse(token['expiry'])
    now = dateparser.parse('now UTC')
    if now > expiry:
        raise Exception('Token expired. Get a new token')
    
    localLog('Loaded authentication token', True)
    authToken = token

def loadQuery():
    global queryConfig
    localLog('Loading query', True, logging.INFO)
    with open('query.yaml') as f:
        config = yaml.load(f, yaml.Loader)
    
    # config validation
    if getConfigKey(config, 'query', 'query') == None:
        raise Exception('Query not defined')
    if getConfigKey(config, 'query', 'type') == None:
        raise Exception('Query type not defined')
    if getConfigKey(config, 'dataset') == None:
        raise Exception('Dataset not defined')

    limit = getConfigKey(config, 'query', 'limit')
    if limit == None:
        limit = 100
        config['query']['limit'] = limit
        localLog('Limit set to {}'.format(limit), True, logging.INFO)
    
    # parse the dates
    fmt = '%Y-%m-%dT%H:%M:%SZ'
    st = getConfigKey(config, 'timing', 'start')
    if st == None:
        raise Exception('start time not defined')
    et = getConfigKey(config, 'timing', 'end')
    if et == None:
        raise Exception('end time not defined')
    
    # Local times
    startTime = dateparser.parse(st)
    endTime = dateparser.parse(et)
    if startTime == None or endTime == None:
        raise Exception('Failed to parse times')
    
    startTime = startTime.astimezone()
    endTime = endTime.astimezone()
    now = datetime.now().astimezone()
    if endTime < startTime or endTime > now:
        raise Exception('Time travel is not possible')
    
    # Convert to UTC
    config['timing']['start'] = startTime.astimezone(timezone.utc).strftime(fmt)
    config['timing']['end'] = endTime.astimezone(timezone.utc).strftime(fmt)
    #print(config)

    queryConfig = config
    localLog('Query loaded OK', False, logging.INFO)

def getAPIURL(path):
    base = getConfigKey(queryConfig, 'endpoint')
    if base == None:
        logger.fatal('Grepr endpoint not set in config file')
        raise Exception('Endpoint no set')
    
    if path[0] != '/':
        path = '/' + path
    url = urljoin(base, '/api{}'.format(path))
    localLog('API URL {}'.format(url), False, logging.INFO)
    return url

# get all datasets and save the results
def loadDatasets():
    global dataSets

    localLog('Loading datasets', False, logging.INFO)
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(authToken['access_token'])
    }

    url = getAPIURL('/v1/datasets')
    r = requests.get(url, headers=headers)
    print('Datasets Status {}'.format(r.status_code))
    r.raise_for_status()

    dataSets = r.json()
    localLog('datasets saved {}'.format(len(dataSets)), False, logging.INFO)

# look up dataset id by name
def getDatasetID(name):
    id = None
    for d in dataSets:
        if d['name'] == name:
            id = d['id']
            break
    
    localLog('Data set {} : {}'.format(name, id), False, logging.INFO)
    return id

def getConfigKey(data, *keys):
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
        if data is None:
            return None
    return data
    

def getQueryData():
    query = getConfigKey(queryConfig, 'query', 'query')
    queryType = getConfigKey(queryConfig, 'query', 'type')
    localLog('Running query {} {}'.format(queryType, query), True, logging.INFO)
    dataset = getConfigKey(queryConfig, 'dataset')
    datasetId = getDatasetID(dataset)
    if datasetId == None:
        raise Exception('Dataset ID not found')

    limit = getConfigKey(queryConfig, 'query', 'limit')
    start = getConfigKey(queryConfig, 'timing', 'start')
    end = getConfigKey(queryConfig, 'timing', 'end')

    localLog('Start time {}'.format(start), True, logging.INFO)
    localLog('End time {}'.format(end), True, logging.INFO)

    data = {
        'name': uuid.uuid4().hex,
        'execution': 'SYNCHRONOUS',
        'processing': 'BATCH',
        'tags': {},
        'jobGraph': {
            'vertices': [{
                'name': 'source',
                'type': 'grepr-raw-log-source',
                'reductionInterval': 'PT2M',
                'datasetId': datasetId,
                'start': start,
                'end': end,
                'query': {
                    'type': queryType,
                    'query': query
                },
                'limit': limit,
                'sortOrder': 'UNSORTED'
            },
            {
                'name': 'sink',
                'type': 'logs-sync-sink'
            }],
            'edges': [
                'source -> sink'
            ]
        }
    }

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(authToken['access_token'])
    }
    url = getAPIURL('/v1/jobs/sync')

    count = 0
    with open('results.txt', 'wb') as f:
        with requests.post(url, headers=headers, json=data, stream=True) as r:
            localLog('Query status {}'.format(r.status_code), True, logging.INFO)
            r.raise_for_status()
            for line in r.iter_lines():
                if line:
                    f.write(line)
                    # preserve the new line
                    f.write(b'\n')
                    count += 1

    localLog('Query finished - {} rows. Results saved in results.txt'.format(count), True, logging.INFO)
    return True

def main():
    # set up logging
    fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(filename='query.log', level=logging.INFO, format=fmt)
    localLog('Starting', False, logging.INFO)
    loadQuery()
    getAuthToken()
    loadDatasets()
    getQueryData()
    


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        localLog(e, True, logging.ERROR)
        traceback.print_tb(e.__traceback__)
