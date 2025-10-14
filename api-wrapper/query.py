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


def getAuthToken():
    global authToken
    logger.info('Loading auth token')
    with open('token.json') as f:
        token = json.load(f)
    
    # check the token
    expiry = dateparser.parse(token['expiry'])
    now = dateparser.parse('now UTC')
    if now > expiry:
        raise Exception('Token expired. Get a new token')
    
    print('Loaded authentication token')
    authToken = token

def loadQuery():
    global queryConfig
    print('Loading Query')
    logger.info('Loading query')
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
        logger.info('Limit set to {}'.format(limit))
        print('Limit set to {}'.format(limit))
    
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
    logger.info('Query loaded OK')

def getAPIURL(path):
    base = getConfigKey(queryConfig, 'endpoint')
    if base == None:
        logger.fatal('Grepr endpoint not set in config file')
        raise Exception('Endpoint no set')
    
    if path[0] != '/':
        path = '/' + path
    url = urljoin(base, '/api{}'.format(path))
    logger.info('API URL {}'.format(url))
    return url

# get all datasets and save the results
def loadDatasets():
    global dataSets

    logger.info('Loading datasets')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(authToken['access_token'])
    }

    url = getAPIURL('/v1/datasets')
    r = requests.get(url, headers=headers)
    print('Datasets Status {}'.format(r.status_code))
    r.raise_for_status()

    dataSets = r.json()
    logger.info('datasets saved {}'.format(len(dataSets)))

# look up dataset id by name
def getDatasetID(name):
    id = None
    for d in dataSets:
        if d['name'] == name:
            id = d['id']
            break
    
    logger.info('Data set {} : {}'.format(name, id))
    return id

def getConfigKey(data, *keys):
    if data and keys:
        element = keys[0]
        if element:
            value = data.get(element)
            return value if len(keys) == 1 else getConfigKey(value, *keys[1:])
    

def getQueryData():
    query = getConfigKey(queryConfig, 'query', 'query')
    queryType = getConfigKey(queryConfig, 'query', 'type')
    logger.info('Running query {} {}'.format(queryType, query))
    print('Running query {} {}'.format(queryType, query))
    dataset = getConfigKey(queryConfig, 'dataset')
    datasetId = getDatasetID(dataset)
    if datasetId == None:
        raise Exception('Dataset ID not found')

    limit = getConfigKey(queryConfig, 'query', 'limit')
    start = getConfigKey(queryConfig, 'timing', 'start')
    end = getConfigKey(queryConfig, 'timing', 'end')

    print('Start time {}'.format(start))
    logger.info('Start time {}'.format(start))
    print('End time {}'.format(end))
    logger.info('End time {}'.format(end))

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
    #print(data)

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(authToken['access_token'])
    }
    url = getAPIURL('/v1/jobs/sync')

    with open('results.txt', 'wb') as f:
        with requests.post(url, headers=headers, json=data, stream=True) as r:
            logger.info('Query status {}'.format(r.status_code))
            print('Query status {}'.format(r.status_code))
            r.raise_for_status()
            for line in r.iter_lines():
                if line:
                    f.write(line)
                    # preserve the new line
                    f.write(b'\n')

    print('Query finished. Results saved in results.txt')
    logger.info('query finished')
    return True

def main():
    # set up logging
    fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(filename='query.log', level=logging.INFO, format=fmt)
    logger.info('Starting')
    loadQuery()
    getAuthToken()
    loadDatasets()
    getQueryData()
    


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logger.error(e)
        print(e)
        traceback.print_tb(e.__traceback__)
