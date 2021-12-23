var expect = require('chai').expect;
const unusedElastiCacheReservedNode = require('./unusedElastiCacheReservedNode');

const describeCacheClusters = [
    {
        "CacheClusterId": "sad2",
        "ClientDownloadLandingPage": "https://console.aws.amazon.com/elasticache/home#client-download:",
        "CacheNodeType": "cache.t2.micro",
        "Engine": "memcached",
        "EngineVersion": "1.6.6",
        "CacheClusterStatus": "creating",
        "NumCacheNodes": 1,
        "PreferredMaintenanceWindow": "sat:08:30-sat:09:30",
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
        "ARN": "arn:aws:elasticache:us-east-1:000011112222:cluster:sad2",
        "ReplicationGroupLogDeliveryEnabled": false,
        "LogDeliveryConfigurations": []
    },
];

const describeReservedCacheNodes = [
    {
        "ReservedCacheNodeId": "mynode",
        "ReservedCacheNodesOfferingId": "xxxxxxxxx-xxxxx-xxxxx-xxxx-xxxxxxxx71",
        "CacheNodeType": "cache.t2.micro",
        "StartTime": "2019-12-06T02:50:44.003Z",
        "Duration": 31536000,
        "FixedPrice": 0.0,
        "UsagePrice": 0.0,
        "CacheNodeCount": 1,
        "ProductDescription": "redis",
        "OfferingType": "No Upfront",
        "State": "payment-pending",
        "RecurringCharges": [
            {
                "RecurringChargeAmount": 0.023,
                "RecurringChargeFrequency": "Hourly"
            }
        ],
        "ReservationARN": "arn:aws:elasticache:us-west-2:xxxxxxxxxxxx52:reserved-instance:mynode"
    },
    {
        "ReservedCacheNodeId": "mynode",
        "ReservedCacheNodesOfferingId": "xxxxxxxxx-xxxxx-xxxxx-xxxx-xxxxxxxx71",
        "CacheNodeType": "cache.t3.small",
        "StartTime": "2019-12-06T02:50:44.003Z",
        "Duration": 31536000,
        "FixedPrice": 0.0,
        "UsagePrice": 0.0,
        "CacheNodeCount": 1,
        "ProductDescription": "redis",
        "OfferingType": "No Upfront",
        "State": "payment-pending",
        "RecurringCharges": [
            {
                "RecurringChargeAmount": 0.023,
                "RecurringChargeFrequency": "Hourly"
            }
        ],
        "ReservationARN": "arn:aws:elasticache:us-west-2:xxxxxxxxxxxx52:reserved-instance:mynode"
    }
];

const createCache = (clusters, nodes) => {
    return {
        elasticache:{
            describeCacheClusters: {
                'us-east-1': {
                    data: clusters
                },
            },
            describeReservedCacheNodes: {
                'us-east-1': {
                    data: nodes
                }
            }
        },
    };
};

const createErrorCache = () => {
    return {
        elasticache:{
            describeCacheClusters: {
                'us-east-1': {
                    err: {
                        message: 'error while describing ElastiCache clusters'
                    },
                },
            },
            describeReservedCacheNodes: {
                'us-east-1': {
                    err: {
                        message: 'error while describing ElastiCache reserved cache nodes'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ElastiCache:{
            describeCacheClusters: {
                'us-east-1': null,
            },
            describeReservedCacheNodes: {
                'us-east-1': null,
            },
        },
    };
};

describe('unusedElastiCacheReservedNode', function () {
    describe('run', function () {
        it('should PASS if ElastiCache reserved cache node is being used', function (done) {
            const cache = createCache([describeCacheClusters[0]], [describeReservedCacheNodes[0]]);
            unusedElastiCacheReservedNode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if ElastiCache reserved cache node is not being used', function (done) {
            const cache = createCache([describeCacheClusters[0]], [describeReservedCacheNodes[1]]);
        unusedElastiCacheReservedNode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no ElastiCache reserved cache nodes found', function (done) {
            const cache = createCache([], []);
            unusedElastiCacheReservedNode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe clusters', function (done) {
            const cache = createErrorCache();
            unusedElastiCacheReservedNode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe reserved cache nodes', function (done) {
            const cache = createCache([]);
            unusedElastiCacheReservedNode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should PASS if describe clusters response not found', function (done) {
            const cache = createNullCache();
            unusedElastiCacheReservedNode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});