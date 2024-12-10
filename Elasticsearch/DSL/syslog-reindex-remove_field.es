{
  "source": {
    "index": "syslog"
  },
  "dest": {
    "index": ".ds-logs-DATASET-syslog-DATE"
  },
  "script": {
    "source": """
      if (ctx._source.log?.syslog?.hostname != null) {
        ctx._source.log.syslog.remove('hostname');
      }
    """
  }
}
