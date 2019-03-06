const { createRequestEncryptor } = require('./lib/index');
const input = {
  "cluster_name": "docker-cluster",
  "license": {
    "uid": "8a12a798-16d2-43e1-949f-dcdbdc5d1de5",
    "expiry_date_in_millis": 1480182662331,
    "issue_date": "2016-10-27T17:51:02.331Z",
    "start_date_in_millis": -1,
    "issued_to": "docker-cluster",
    "expiry_date": "2016-11-26T17:51:02.331Z",
    "hkey": "b28eff1e29819abd4047f2c6840da2fd4f1bee70f0d596c4d6bb6a1db4136e4b",
    "max_nodes": 1000,
    "issue_date_in_millis": 1477590662331,
    "type": "trial",
    "issuer": "elasticsearch",
    "status": "active"
  },
  "cluster_uuid": "9WoyNsZ1QNSvX55FWGXg3Q",
  "telemetry": {
    "usage": {
      "logstash": false,
      "kibana": false,
      "xpack": {
        "watcher": false,
        "security": false,
        "reporting": false,
        "monitoring": true,
        "graph": false,
        "ml": false
      }
    },
    "api_version": 1
  },
  "version": "5.0.0-rc1",
  "cluster_stats": {
    "indices": {
      "shards": {
        "replication": 0,
        "primaries": 67,
        "total": 67,
        "index": {
          "replication": {
            "min": 0,
            "avg": 0,
            "max": 0
          },
          "shards": {
            "min": 1,
            "avg": 2.4814814814814814,
            "max": 5
          },
          "primaries": {
            "min": 1,
            "avg": 2.4814814814814814,
            "max": 5
          }
        }
      },
      "completion": {
        "size_in_bytes": 298
      },
      "query_cache": {
        "miss_count": 0,
        "memory_size_in_bytes": 0,
        "cache_size": 0,
        "total_count": 0,
        "evictions": 0,
        "hit_count": 0,
        "cache_count": 0
      },
      "docs": {
        "deleted": 4380,
        "count": 1091439
      },
      "fielddata": {
        "memory_size_in_bytes": 0,
        "evictions": 0
      },
      "count": 27,
      "store": {
        "throttle_time_in_millis": 0,
        "size_in_bytes": 1118218809
      },
      "segments": {
        "version_map_memory_in_bytes": 0,
        "norms_memory_in_bytes": 35136,
        "file_sizes": {},
        "max_unsafe_auto_id_timestamp": -1,
        "count": 209,
        "fixed_bit_set_memory_in_bytes": 144,
        "term_vectors_memory_in_bytes": 0,
        "points_memory_in_bytes": 991701,
        "index_writer_memory_in_bytes": 0,
        "memory_in_bytes": 4541263,
        "terms_memory_in_bytes": 1822366,
        "doc_values_memory_in_bytes": 1524660,
        "stored_fields_memory_in_bytes": 167400
      }
    },
    "nodes": {
      "jvm": {
        "max_uptime_in_millis": 187488,
        "mem": {
          "heap_max_in_bytes": 2077753344,
          "heap_used_in_bytes": 490278336
        },
        "versions": [
          {
            "vm_version": "25.92-b14",
            "count": 1,
            "vm_vendor": "Oracle Corporation",
            "version": "1.8.0_92-internal",
            "vm_name": "OpenJDK 64-Bit Server VM"
          }
        ],
        "threads": 104
      },
      "process": {
        "open_file_descriptors": {
          "min": 474,
          "avg": 474,
          "max": 474
        },
        "cpu": {
          "percent": 0
        }
      },
      "os": {
        "available_processors": 8,
        "names": [
          {
            "name": "Linux",
            "count": 1
          }
        ],
        "mem": {
          "used_in_bytes": 19406778368,
          "free_percent": 62,
          "total_in_bytes": 50551386112,
          "free_in_bytes": 31144607744,
          "used_percent": 38
        },
        "allocated_processors": 8
      },
      "network_types": {
        "http_types": {
          "netty4": 1
        },
        "transport_types": {
          "netty4": 1
        }
      },
      "versions": [
        "5.0.0-rc1"
      ],
      "plugins": [
        {
          "classname": "org.elasticsearch.xpack.XPackPlugin",
          "name": "x-pack",
          "description": "Elasticsearch Expanded Pack Plugin",
          "version": "5.0.0-rc1"
        }
      ],
      "count": {
        "total": 1,
        "data": 1,
        "coordinating_only": 0,
        "master": 1,
        "ingest": 1
      },
      "fs": {
        "total_in_bytes": 492122619904,
        "free_in_bytes": 393570127872,
        "spins": "true",
        "available_in_bytes": 368548065280
      }
    },
    "timestamp": 1478006643213,
    "status": "yellow"
  },
  "timestamp": "2016-11-01T13:24:03.213Z",
  "stack_stats": {
    "xpack": {
      "watcher": {
        "execution": {
          "actions": {
            "_all": {
              "total": 0,
              "total_time_in_ms": 0
            }
          }
        },
        "available": true,
        "count": {
          "total": 0,
          "active": 0
        },
        "enabled": true
      },
      "security": {
        "available": true,
        "enabled": false
      },
      "monitoring": {
        "available": true,
        "enabled_exporters": {
          "local": 1
        },
        "enabled": true
      },
      "graph": {
        "available": true,
        "enabled": true
      }
    }
  }
}

const jwks = {
  "keys": [
    {
      "kty": "RSA",
      "kid": "kibana_7.1.0",
      "use": "enc",
      "alg": "RSA-OAEP",
      "e": "AQAB",
      "n": "ltCSk002_KDrhwq0sWb5F91laZRl3W9ZeSRVIHGQ_tfD4gg6uP-RLJ-Q00-cDpkMEdR8ueY95Bzo2GgHawgFaTHvUXgeTnY5_WY0rvq0DUF4FqgTzarF3AIa-u9Dp_1Yd4Hb56w5sxIz0d0tf_4S7-k446i03vPTMjH353ws7IGW4iEkaF05gpwr5tWSeJfJp7BNRe4N2fMtaivBRwiNvxAfggSK7lZVmVAYaJd3DwA8OLzLNB6_3vZ4V2zJaB8D-lGJv5zmQ929euYk2V3dGqChmDg6U2wH4Qucue7g16pNchdYNmaOB4DRCdct77cR1zgi66wNWcFYgkwS5RAxoliGnye4sjiYrFZk18nXQFqbpe2jqhi5q9kiXeg2JQ9ZEIpmVV1zAlij87wgypKfvaQZI_6V7izTYiZpMt0ZAU5FxoRaN2DzkIzXvUjxdfI916hmDHNoi0pfiB6eOApHYLNQuT1fLs15yIlQXRyHmEiSLmJXZZGodAF8KK5yXGiSsnL3qGfO7Xd3EUY5TVBvrWqIzXAkpnCNT71gueLzGOOguodmG2eWkBW2ZtTE9PtccD8YvHmB9fYJ10JEGBrMiHmATB7a1lgO5f90FcDXj9sRNgl0mBZemuPEiltyD_73qdJb96J_wbb_qICUL8KegJgx8YtcuzXyjOc2UHoNaic",
      "d": "CrUiQv0Pc15FeqAC9jl2ZABfC-DyXodiVdyDgrstbTqKeMjWyn2yo_VsReR4Ev1Awx9P_67eJAz9ZyfzpuC56Z8W-7TIig-QzHHuOaIpGGvWh91FEqwWQimQGtLT_eBZ4JpCr68lpZYcQcEvUtAKLihj1p4KwW2USBMOI8xIMD5_JOzvdc1woNpPr6LoNFGqipJU2istppTCW7Bhl5Z-4drWMdf6uTM9_pWWNg7S8Ci3HdwhnUC1pLHhF2vs3Mye7q3NVuJf4t-ibVBbu2cTpKlU78bGNVgNMygs53KTWhyIRRptM-eSG-xEaytw4n0f8iTVLeBYTlAQ5adbDBJbQ6xYBNh2VIsczvBs3oyXt-6KiJQ47D6VsKa1Q2fv9Rze8JZTqRPDQLyg0W7jn6BJzaZdxdripUHnyK1PIsl-KpueWPKDHaILqogz5Whx7t7HwwIOz4S-k6yeAPmFG8h3xBgm3TC01BeDHXkC3TpYjlUEmYPUfkslQb145luzmOciQZa0fFIsqv_cKnzWpLFtdFCzXCnrXDvitK048t4lCRonYkXZ0_LNHlZlhk7CsimewqgCc-_bNXuvWD--3VHklTpETy10aKvGjxsgQDizwVgmxjrXsvHqzN646h732Co2pl8gFTzbRSGrZ041eIWpNQQZWzd9vZnJlE0zgpD_gqE",
      "p": "4MCV7RXibidXTlTS1kQKF7FYzArbf7yYf-oCf1m-fqSdaSaj4fJ5odXAcO7por1rY19Ba0y5OTRxG3TexOZk4AgPXWvrrl2U9wYEzpv2Pe4FqrY_SKzSY5_9aJt-0RMoPR2jGztOokz2ZQIswZ72ymr57kUTjt0LiDH6Dt-QA-8x_RWXxFSM9AWnJBP5qJiFLcHXrh24jGJ2KADEWQVXWWlk6swLpixVpjKRb6-FXM-FTqG385crGVN9veE14WcPADTlqVV1RkXfZKg1GmkXp3eGbt7eK47mi0WkELOz1d6LTeDOkp-5qCOtU2x25u6saX67Av91RssrKo98n_epsQ",
      "q": "q8hkM-oBSGpJdv1ssMSk_7ZbgSLSedoSK9Wz-l1ALATATkuOFRhNTQei1PUcMlKP3SzAQ0MJdPdvFaNkLicNOttBsh-jm6B1n3qX1VC_-0Am1sx9P_cQXqaWBBO1HtHtT7BmNWU_m0p5_t_dNgDbSRBz-dINXjRjpaeAn1sWL_o50bRX5-vewFbSVnYCY8ZV8vXl5bSA4vXWHw0Yvs5995DTXt2ikI4XsNRJW5C8dmQwYpEZab1iOScH3XRgOrjgJWrKjN8bZ_x5cfQFkek2dbnLrypltJPNIVMA7WEm2DtA3Hw9pGWBpthoBhrAqdrtCKl1GMomNvFZVMmco_9vVw",
      "dp": "mZ-J2zBmQVzqtEQOiR6gt2klhPK27iz_IA_X_SxepTnnzoP26O5QbWopzAfB8tb-nEHz-V_MC2npFhdgXb4NnYRk3Dp0Mg8NT3vxtTetrM8RWIqR3x8h_67QC7ydhlNN4dhsMKTtLsrkcE54QTBjCCDvDQpyP-ifhUyD2768NbQ9uvwTbMNORU3H3UU6FR-LiKdCwWTXTD3Q_a7ohuC7wAXmUQd_vun28U8HUgvrYHEIcaLglcPyVbFX9X4G0jcbbcy6XnBnZM1F0QuYoKDM5k8wuH_l5Ggc9X14k2IBvmILXgQXruk2gdNBGhC9hUQG3WUedwIeK3Gb48-II9-pQQ",
      "dq": "Qzg2Ja5i9CBLQRmn53_7hOip491peS8hPy_vrn_A9biiO8ELBywsS4E6cZS8hOCT1RuG3Isl7zRHrrLyJ7E2VxqnGXmR_vsKK-6_7UQc68dNq233cQlPyYnsWAoSLM4-y5keVbSZ8D1zgY2-NTyekneyukY83uknORJTnYf6JaoH6Axm_aTp1F_lDNo-0yYwSdN5M6qvaKCEOkBYt4l7910fqRaXX3OKx7I6Rm9boARSfq-Cv0LRZcXlKP46DaB8bYfdXMSNJ-K-7x1q9I7KtcSPdKrlg4T2lxyw1zLWDXUaS2z-fg8ObehuxDzBuXWmnWYaISoxS_yjVS9TcUUqHw",
      "qi": "qeSwfCHNVu3NIuSk5iUaBUitpKB_CwxUyule2dldUe3gwnWz39g1cp60OpQ8AobdOlLTXV02f5V6tCswPtotlEbnIVpOKacqlaEBvbDEOInyczXIkLGWId5fbLvgwVqGVpcRY9hP7STg0ks-lNC0xYOubmLRE33-kGKzn-6KjDXKKcTQ2I6Y0E5UxKqdp_OkoUonBM4obKhoXWx8vN0D97vyvNsNn5d2fmwe6QcX2qlpdvO4RtdF0L8ZaYaGYlASCe3KxCiMfqv5x0ZoADk5WYzmEMYeXCXthGzEOAfQY_5_1SlFBhECB2Tq7DaeK7ABOExFzjGUbn5ros2q5AhyVA"
    }
  ]
}

;(async () => {
  const manager = await createRequestEncryptor(jwks);
  const encryptedPayload = await manager.encrypt('kibana_7.1.0', input);
  console.log('encryptedPayload::', JSON.stringify(encryptedPayload, null, 2));
})();