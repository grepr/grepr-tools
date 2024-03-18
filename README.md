# Grepr Tools
A collection of tools for working with Grepr

## Datadog tools

### `setup_grepr_poc_keys.py`
A python script that will create a limited access Service Account in Datadog that can only view logs with
a specified filter. It will generate an API and an App key that can then be provided to Grepr to access 
logs for a Trial-mode deployment. It requires a full-access App key to run and create the service account, but
that's only used for the initial setup. See details at https://docs.datadoghq.com/account_management/api-app-keys/.

The script outputs what it did into a `.json` file. The tool can undo what it previously did by using the `revert`
subcommand. For full usage, run `python3 setup_grepr_poc_keys.py --help`.

Basic usage:
```bash
export DD_API_KEY=<your API key>
export DD_APP_KEY=<your App key>
python3 setup_grepr_poc_keys.py setup --site <site> <query> <service_account_email>
```
