var expect = require('chai').expect;
const elasticacheClusterInVpc = require('./elasticacheClusterInVpc');

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
    },
    {
        "CacheClusterId": "test-002",
        "ClientDownloadLandingPage": "https://console.aws.amazon.com/elasticache/home#client-download:",
        "CacheNodeType": "cache.t2.micro",
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
        "CacheSubnetGroupName": "",
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

const createCache = (clusters) => {
    return {
        elasticache: {
            describeCacheClusters: {
                'us-east-1': {
                    data: clusters,
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        elasticache: {
            describeCacheClusters: {
                'us-east-1': {
                    err: {
                        message: 'error describing clusters'
                    },
                },
            },
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
    };
};

describe('elasticacheClusterInVpc', function () {
    describe('run', function () {
        it('should FAIL if ElastiCache cluster is not in VPC', function (done) {
            const cache = createCache([describeCacheClusters[1]]);
            elasticacheClusterInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if ElastiCache cluster is in VPC', function (done) {
            const cache = createCache([describeCacheClusters[0]]);
            elasticacheClusterInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS no ElastiCache clusters found', function (done) {
            const cache = createCache([]);
            elasticacheClusterInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error querying for ElastiCache clusters', function (done) {
            const cache = createErrorCache();
            elasticacheClusterInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for ElastiCache clusters', function (done) {
            const cache = createNullCache();
            elasticacheClusterInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
