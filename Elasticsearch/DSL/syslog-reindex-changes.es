
{
  "source": {
    "index": "from"
  },
  "dest": {
    "index": "to_index"
  },
  "script": {
    "source": """
      ctx._source.customer = 'ABC';
      ctx._source.event = ctx._source.event ?: [:]; 
      ctx._source.event.kind = 'metrics';
      if (ctx._source.cve_sev != null) {
        ctx._source.event.severity = ctx._source.cve_sev;
        ctx._source.remove("cve_sev");
      }
      if (ctx._source.event.severity != null) {
        ctx._source.event.severity = ctx._source.event.severity.toUpperCase();
      }
    """
  }
}