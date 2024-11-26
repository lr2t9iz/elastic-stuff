{
  "order": 100,
  "index_patterns": [ ".ds-logs-DATASET-syslog-*" ],
  "settings": {
    "index": {
      "number_of_shards": "1",
      "number_of_replicas": "0"
    }
  },
  "mappings": {
    "dynamic_templates": [
      { "ecs_non_indexed_keyword": {
        "path_match": "event.original", 
          "mapping": {
            "doc_values": false,
            "index": false,
            "type": "keyword"
          }
        }
      }
    ],
    "properties": {
      "agent" : {
        "properties" : {
          "name" : { "type" : "keyword",
            "fields": { "text": { "type": "match_only_text" } }
          }
        }
      },
      "event": {
        "properties": {
          "dataset": { "type": "keyword" },
          "created": { "type": "date" }
        }
      }
    }
  },
  "aliases": {
    "logs-syslog-custom": {
      "is_write_index": true
    }
  }
}