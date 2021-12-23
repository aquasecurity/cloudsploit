var expect = require('chai').expect;
const elasticacheNodesCount = require('./elasticacheNodesCount');

const describeCacheClusters = [
    {
        "CacheClusterId": "test1",
        "ClientDownloadLandingPage": "https://console.aws.amazon.com/elasticache/home#client-download:",
        "CacheNodeType": "cache.r6g.large",
        "Engine": "memcached",
        "EngineVersion": "1.6.6",
        "CacheClusterStatus": "creating",
        "NumCacheNodes": 5,
        "PreferredAvailabilityZone": "us-east-1a",
        "PreferredMaintenanceWindow": "wed:09:30-wed:10:30",
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
        "ARN": "arn:aws:elasticache:us-east-1:000111222333:cluster:sadeed1",
        "ReplicationGroupLogDeliveryEnabled": false,
        "LogDeliveryConfigurations": []
    },
    {
        "CacheClusterId": "test2",
        "ClientDownloadLandingPage": "https://console.aws.amazon.com/elasticache/home#client-download:",
        "CacheNodeType": "cache.r6g.large",
        "Engine": "memcached",
        "EngineVersion": "1.6.6",
        "CacheClusterStatus": "creating",
        "NumCacheNodes": 2,
        "PreferredAvailabilityZone": "us-east-1a",
        "PreferredMaintenanceWindow": "wed:09:30-wed:10:30",
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
        "ARN": "arn:aws:elasticache:us-east-1:000111222333:cluster:sadeed1",
        "ReplicationGroupLogDeliveryEnabled": false,
        "LogDeliveryConfigurations": []
    }
];


const createCache = (clusters) => {
    return {
        elasticache:{
            describeCacheClusters: {
                'us-east-1': {
                    data: clusters
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        elasticache:{
            describeCacheClusters: {
                'us-east-1': {
                    err: {
                        message: 'error describing elasticache clusters'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        elasticache:{
            describeCacheClusters: {
                'us-east-1': null,
            },
        },
    };
};

describe('elasticacheNodesCount', function () {
    describe('run', function () {
        it('should PASS if region contains provisioned Elasticache nodes less than or equal to the limit', function (done) {
            const cache = createCache([describeCacheClusters[1]]);
            const settings = { elasticache_nodes_count_per_region: '5' };

            elasticacheNodesCount.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[1].status).to.equal(0);
                expect(results[1].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if region contains provisioned Elasticache nodes more than the limit', function (done) {
            const cache = createCache([describeCacheClusters[0]]);
            const settings = { elasticache_nodes_count_per_region: '4', elasticache_nodes_count_global: '4' };

            elasticacheNodesCount.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Elasticache clusters found', function (done) {
            const cache = createCache([]);
            elasticacheNodesCount.run(cache, { elasticache_nodes_count_per_region: '5' }, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to describe clusters', function (done) {
            const cache = createErrorCache();
            elasticacheNodesCount.run(cache, { elasticache_nodes_count_per_region: '5' }, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});