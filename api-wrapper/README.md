# Grepr Query API wrapper

[Grepr](http://grepr.ai/) **Intelligent Observability Data Engine** is a proxy for obserability agents. It collects the data from agents such as:
Datadog, Splunk, New Relic and continuously semantically analyses the data stream. It automatically detetcts similarities in the
data and using machine learns builds and maintains an active set of filters. Frequently occuring data is summarised and forwarded
to the observability backend while unique data is passed straigh through. This results in a data reduction of 90% with the
associated platform cost savings.

No data is lost. All data intercepted by Grepr is retained in low cost storage and can be queried and optionally backfilled to
the observability platform. This can be performed via the Grepr dashboard or via the API. This is where this set of utilities
come in handy.

## Installation

Written for Python3

Create a virtual environment for Python. In the directory where you downloaded these files.

```bash
$ python3 -m venv venv
```

Activate the virtual environment

```bash
$ . venv/bin/activate
```

Install the dependencies

```bash
$ pip install -r requirements.txt
```

## Set Up

Create text file called `credentials` and set your client identifier and secret.
Contact Grepr support if you do not already have these.

```
CLIENT_ID="123456"
CLIENT_SECRET="not telling"
```

Now get an API key by running the `get-token.py` script.

```bash
$ python get-token.py
```

This will save the authentication token in a file called `token.json`. By default this token is valid for 24 hours.
After that the `get-token.py` script will have to be run again. This token file can be shared without giving away
the client identifier and secret.

## Running a query

The `query.yaml` is used to define the query to be run, see the comments inside the file. Once this file has been
configured, run the query.

```bash
$ ./run.sh
```

As the query runs, its progress is reported. More information will be available in the `query.log` and the results
will be written to the `results.txt` file. Each line of the file is JSON making it easy to parse and used the data
however you wish.

# TODO

* Add option to backfill the results
