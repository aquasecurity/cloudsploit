var expect = require('chai').expect;
const elasticacheRedisMultiAZ = require('./elasticacheRedisMultiAZ');

const clusters = [
    {
        "ReplicationGroupId": "sadeed",
        "Description": " ",
        "GlobalReplicationGroupInfo": {},
        "Status": "creating",
        "PendingModifiedValues": {},
        "MemberClusters": [
            "sadeed-001",
            "sadeed-002",
            "sadeed-003"
        ],
        "SnapshottingClusterId": "sadeed-002",
        "AutomaticFailover": "enabling",
        "MultiAZ": "enabled",
        "SnapshotRetentionLimit": 1,
        "SnapshotWindow": "10:00-11:00",
        "ClusterEnabled": false,
        "CacheNodeType": "cache.t2.micro",
        "AuthTokenEnabled": false,
        "TransitEncryptionEnabled": false,
        "AtRestEncryptionEnabled": false,
        "ARN": "arn:aws:elasticache:us-east-1:101363889637:replicationgroup:sadeed",
        "LogDeliveryConfigurations": [],
        "ReplicationGroupCreateTime": "2021-12-07T14:52:04.997000+00:00"
    },
    {
        "ReplicationGroupId": "sadeed",
        "Description": " ",
        "GlobalReplicationGroupInfo": {},
        "Status": "creating",
        "PendingModifiedValues": {},
        "MemberClusters": [
            "sadeed-001",
            "sadeed-002",
            "sadeed-003"
        ],
        "SnapshottingClusterId": "sadeed-002",
        "AutomaticFailover": "enabling",
        "MultiAZ": "disabled",
        "SnapshotRetentionLimit": 1,
        "SnapshotWindow": "10:00-11:00",
        "ClusterEnabled": false,
        "CacheNodeType": "cache.t2.micro",
        "AuthTokenEnabled": false,
        "TransitEncryptionEnabled": false,
        "AtRestEncryptionEnabled": false,
        "ARN": "arn:aws:elasticache:us-east-1:101363889637:replicationgroup:sadeed",
        "LogDeliveryConfigurations": [],
        "ReplicationGroupCreateTime": "2021-12-07T14:52:04.997000+00:00"
    }
];

const createCache = (clusters) => {
    return {
        elasticache: {
            describeReplicationGroups: {
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
            describeReplicationGroups: {
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
            describeReplicationGroups: {
                'us-east-1': null,
            },
        },
    };
};

describe('elasticacheRedisMultiAZ', function () {
    describe('run', function () {
        it('should FAIL if Multi-AZ is not enabled for ElastiCache cluster', function (done) {
            const cache = createCache([clusters[1]]);
            elasticacheRedisMultiAZ.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if Multi-AZ is enabled for ElastiCache cluster', function (done) {
            const cache = createCache([clusters[0]]);
            elasticacheRedisMultiAZ.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS no ElastiCache clusters found', function (done) {
            const cache = createCache([]);
            elasticacheRedisMultiAZ.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error querying for ElastiCache clusters', function (done) {
            const cache = createErrorCache();
            elasticacheRedisMultiAZ.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for ElastiCache clusters', function (done) {
            const cache = createNullCache();
            elasticacheRedisMultiAZ.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
