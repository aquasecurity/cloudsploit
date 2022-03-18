const expect = require('chai').expect;
var elasticaheDesiredNodeType = require('./elasticaheDesiredNodeType');

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
        "CacheClusterCreateTime": "2021-12-01T10:46:20.450000+00:00",
        "PreferredMaintenanceWindow": "fri:10:00-fri:11:00",
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
        "ARN": "arn:aws:elasticache:us-east-1:101363889637:cluster:sad1",
        "ReplicationGroupLogDeliveryEnabled": false,
        "LogDeliveryConfigurations": []
    },
    {
        "CacheClusterId": "sad23-001",
        "ClientDownloadLandingPage": "https://console.aws.amazon.com/elasticache/home#client-download:",
        "CacheNodeType": "cache.r6g.large",
        "Engine": "redis",
        "EngineVersion": "6.2.5",
        "CacheClusterStatus": "available",
        "NumCacheNodes": 1,
        "PreferredAvailabilityZone": "us-east-1a",
        "CacheClusterCreateTime": "2021-12-01T10:56:34.474000+00:00",
        "PreferredMaintenanceWindow": "wed:09:00-wed:10:00",
        "PendingModifiedValues": {},
        "CacheSecurityGroups": [],
        "CacheParameterGroup": {
            "CacheParameterGroupName": "default.redis6.x",
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
        "ReplicationGroupId": "sad23",
        "SnapshotRetentionLimit": 0,
        "SnapshotWindow": "05:00-06:00",
        "AuthTokenEnabled": false,
        "TransitEncryptionEnabled": false,
        "AtRestEncryptionEnabled": false,
        "ARN": "arn:aws:elasticache:us-east-1:101363889637:cluster:sad23-001",
        "ReplicationGroupLogDeliveryEnabled": false,
        "LogDeliveryConfigurations": []
    }
];


const createCache = (describeCacheClusters) => {
    return {
        elasticache: {
            describeCacheClusters: {
                'us-east-1': {
                    data: describeCacheClusters
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        elasticache: {
            describeCacheClusters: {
                'us-east-1': {
                    err: {
                        message: 'error listing elasticache functions'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        mq: {
            describeCacheClusters: {
                'us-east-1': null
            }
        }
    };
};

describe('elasticaheDesiredNodeType', function () {
    describe('run', function () {

        it('should PASS if ElastiCache clusters have the desired node type', function (done) {
            const cache = createCache([describeCacheClusters[0]]);
            elasticaheDesiredNodeType.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('cluster has desired node type');
                done();
            });
        });

        it('should FAIL if ElastiCache cluster does not have desired node type', function (done) {
            const cache = createCache([describeCacheClusters[1]]);
            elasticaheDesiredNodeType.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('cluster does not have desired node type')
                done();
            });
        });

        it('should PASS if No ElastiCache cluster found', function (done) {
            const cache = createCache([]);
            elasticaheDesiredNodeType.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ElastiCache cluster found');
                done();
            });
        });

        it('should UNKNOWN if unable to list ElastiCache clusters', function (done) {
            const cache = createErrorCache();
            elasticaheDesiredNodeType.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query ElastiCache cluster: error listing elasticache functions');
                done();
            });
        });

        it('should not return anything if list clusters response not found', function (done) {
            const cache = createNullCache();
            elasticaheDesiredNodeType.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});