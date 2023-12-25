# FRITZ!Box Logs

This script logs into a FRITZ!Box router, retrieves logs from the router, and formats the logs into a JSON string.

## Usage

To use this script, run the following command:
`python3 fritzbox_logs.py http://fritz.box user pass interval`

Where:

* `http://fritz.box` is the URL of your FRITZ!Box router.
* `user` is the username for your FRITZ!Box router.
* `pass` is the password for your FRITZ!Box router.
* `interval` is the number of seconds between each log retrieval.

## Output

The script will output a JSON string containing the logs from your FRITZ!Box router. The logs will be formatted in the following way:

```{
  "logs": [
    {
      "timestamp": "2023-03-08T12:00:00",
      "msg": "This is a log message."
    },
    {
      "timestamp": "2023-03-08T12:01:00",
      "msg": "This is another log message."
    },
    {
      "timestamp": "2023-03-08T12:02:00",
      "msg": "This is a third log message."
    }
  ]
}```

## License

This script is licensed under the Apache License 2.0.
