{
  "source": {
    "index": "syslog"
  },
  "dest": {
    "index": ".ds-logs-DATASET-syslog-DATE"
  },
  "script": {
    "source": """
      ctx._source.agent = ctx._source.agent ?: [:]; 
      ctx._source.agent.name = 'AGENT';
      ctx._source.event = ctx._source.event ?: [:]; 
      ctx._source.event.dataset = 'DATASET';
    """
  }
}