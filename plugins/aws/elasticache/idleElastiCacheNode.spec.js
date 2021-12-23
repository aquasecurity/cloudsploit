const expect = require('chai').expect;
const idleElastiCacheNode = require('./idleElastiCacheNode');

const describeCacheClusters = [
    {
        "CacheClusterId": "sad1",
        "ConfigurationEndpoint": {
            "Address": "sad1.zvodgj.cfg.use1.cache.amazonaws.com",
            "Port": 11211
        },
        "ClientDownloadLandingPage": "https://console.aws.amazon.com/elasticache/home#client-download:",
        "CacheNodeType": "cache.t2.micro",
        "Engine": "memcached",
        "EngineVersion": "1.6.6",
        "CacheClusterStatus": "available",
        "NumCacheNodes": 1,
        "PreferredAvailabilityZone": "us-east-1a",
        "CacheClusterCreateTime": "2021-12-10T10:17:24.387000+00:00",
        "PreferredMaintenanceWindow": "fri:04:00-fri:05:00",
        "PendingModifiedValues": {},
        "CacheSecurityGroups": [],
        "CacheParameterGroup": {
            "CacheParameterGroupName": "default.memcached1.6",
            "ParameterApplyStatus": "in-sync",
            "CacheNodeIdsToReboot": []
        },
        "CacheSubnetGroupName": "mine",
        "AutoMinorVersionUpgrade": true,
        "SecurityGroups": [
            {
                "SecurityGroupId": "sg-05682812766c2fca2",
                "Status": "active"
            }
        ],
        "AuthTokenEnabled": false,
        "TransitEncryptionEnabled": false,
        "AtRestEncryptionEnabled": false,
        "ARN": "arn:aws:elasticache:us-east-1:000011112222:cluster:sad1",
        "ReplicationGroupLogDeliveryEnabled": false,
        "LogDeliveryConfigurations": []
    }
];

const ecMetricStatistics = [
    {
        "Datapoints": [
            {
                "Timestamp": "2018-12-16T17:03:10Z",
                "Average": 4.333,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T18:03:10Z",
                "Average": 3.333,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 6.333,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 2.333,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 1.333,
                "Unit": "Percent"
            },
        ]
    },
    {
        "Datapoints": [
            {
                "Timestamp": "2018-12-16T17:03:10Z",
                "Average": 0,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T18:03:10Z",
                "Average": 0,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 0,
                "Unit": "Percent"
            },
        ]
    },
    {
        "Datapoints": [
            {
                "Timestamp": "2018-12-16T17:03:10Z",
                "Unit": "Percent"
            }
        ]
    }
]

const createCache = (cluster, metrics) => {
    if (cluster && cluster.length) var id = cluster[0].CacheClusterId;
    return {
        elasticache: {
            describeCacheClusters: {
                'us-east-1': {
                    data: cluster,
                },
            },
        },
        cloudwatch: {
            getEcMetricStatistics: {
                'us-east-1': {
                    [id]: {
                        data: metrics
                    }
                }
            }
        },
    };
};

const createErrorCache = () => {
    return {
        elasticache: {
            describeCacheClusters: {
                'us-east-1': {
                    err: {
                        message: 'error desribing cache clusters'
                    },
                },
            },
        },
        cloudwatch: {
            getEcMetricStatistics: {
                'us-east-1': {
                    err: {
                        message: 'error getting metric stats'
                    },
                }
            }
        },
    };
};

const createNullCache = () => {
    return {
        elasticache: {
            describeCacheClusters: {
                'us-east-1': null,
            },
        },
        cloudwatch: {
            getEcMetricStatistics: {
                'us-east-1': null
            },
        },
    };
};

describe('idleElastiCacheNode', function () {
    describe('run', function () {
        it('should PASS if metric count is greater than 5', function (done) {
            const cache = createCache([describeCacheClusters[0]], ecMetricStatistics[0]);
            idleElastiCacheNode.run(cache, { elasticache_idle_node_percentage:'5.00' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('ElastiCache cluster is not idle');
                done();
            });
        });

        it('should FAIL if metric count is lesser than 5', function (done) {
            const cache = createCache([describeCacheClusters[0]], ecMetricStatistics[1]);
            idleElastiCacheNode.run(cache, { elasticache_idle_node_percentage:'5.00' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('ElastiCache cluster is idle');
                done();
            });
        });
    
        it('should PASS if metric count is not part of the response', function (done) {
            const cache = createCache([describeCacheClusters[0]], ecMetricStatistics[2]);
            idleElastiCacheNode.run(cache, { elasticache_idle_node_percentage:'5.00' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('ElastiCache cluster is not idle');
                done();
            });
        });
    
        it('should PASS if no ElastiCache cluster found', function (done) {
            const cache = createCache([]);
            idleElastiCacheNode.run(cache, { elasticache_idle_node_percentage:'5.00' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ElastiCache cluster found');
                done();
            });
        });

        it('should UNKNOWN if unable to describe cache clusters', function (done) {
            const cache = createErrorCache();
            idleElastiCacheNode.run(cache, { elasticache_idle_node_percentage:'5.00' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for ElastiCache cluster');
                done();
            });
        });

        it('should not return any results if describe cache clusters response not found', function (done) {
            const cache = createNullCache();
            idleElastiCacheNode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
