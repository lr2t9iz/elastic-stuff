{
  "trigger": { "schedule": { "interval": "10s" } },
  "input": {
    "search": {
      "request": {
        "search_type": "query_then_fetch",
        "indices": [ "logstash-tcpdump-*" ],
        "types": [ "tcpdump" ],
        "body": {
          "size": 0,
          "query": {
            "bool": {
              "must": [
                { "range": { "@timestamp": { "gte": "now-30s" } } },
                { "match": { "tags": "tcp_connection_started" } }                
              ]
            }
          },
          "aggs": {
            "by_src_ip": { "terms": { "field": "src_ip" },
              "aggs": {
                "by_target_ip": { "terms": { "field": "dst_ip", "order": { "unique_port_count": "desc" } },
                  "aggs": { 
                    "unique_port_count": { "cardinality": { "field": "dst_port" } } 
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  "condition": {
    "script": {
      "inline": """
        for (int i = 0; i < ctx.payload.aggregations.by_src_ip.buckets.size(); i++) {
          for (int j = 0; j < ctx.payload.aggregations.by_src_ip.buckets[i].by_target_ip.buckets.size(); j++) {
              if (ctx.payload.aggregations.by_src_ip.buckets[i].by_target_ip.buckets[j].unique_port_count.value > threshold) 
                return true;
            };
        };
        return false;
        """,
      "params": { "threshold": 50 }
    }
  },
  "throttle_period": "30s",
  "actions": {
    "email_administrator": {
      "transform": {
        "script": {
          "inline": """
            def target='';
            def attacker='';
            def body='';
            for (int i = 0; i < ctx.payload.aggregations.by_src_ip.buckets.size(); i++) {
                for (int j = 0; j < ctx.payload.aggregations.by_src_ip.buckets[i].by_target_ip.buckets.size(); j++) {
                    if (ctx.payload.aggregations.by_src_ip.buckets[i].by_target_ip.buckets[j].unique_port_count.value > threshold) {
                        target=ctx.payload.aggregations.by_src_ip.buckets[i].by_target_ip.buckets[j].key;
                        attacker=ctx.payload.aggregations.by_src_ip.buckets[i].key;
                        body='Detected portscan from ['+attacker+'] to ['+target+']. '+ctx.payload.aggregations.by_src_ip.buckets[i].by_target_ip.buckets[j].unique_port_count.value+ ' unique ports scanned.'; 
                        return [ body : body ];
                    };
                };
            };
          """,
          "params": { "threshold": 50 }
        }
      },
      "email": {
        "profile": "standard",
        "attach_data": true,
        "priority": "high",
        "to": [ "antonio@elastic.co" ],
        "subject": "[Security Alert] - Port scan detected",
        "body": """
          {{ctx.payload.body}}
          Ref: https://www.elastic.co/blog/elasticsearch-and-siem-implementing-host-portscan-detection
          """
      }
    }
  }
}
