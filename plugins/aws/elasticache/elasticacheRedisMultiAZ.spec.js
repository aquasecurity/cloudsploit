var expect = require('chai').expect;
const elasticacheRedisMultiAZ = require('./elasticacheRedisMultiAZ');

const describeCacheClusters = [
    {
        "CacheClusterId": "sadeed-001",
        "ClientDownloadLandingPage": "https://console.aws.amazon.com/elasticache/home#client-download:",
        "CacheNodeType": "cache.t2.micro",
        "Engine": "redis",
        "EngineVersion": "6.2.5",
        "CacheClusterStatus": "available",
        "NumCacheNodes": 1,
        "PreferredAvailabilityZone": "us-east-1a",
        "CacheClusterCreateTime": "2021-12-07T15:02:36.703000+00:00",
        "PreferredMaintenanceWindow": "mon:09:00-mon:10:00",
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
        "ReplicationGroupId": "sadeed",
        "SnapshotRetentionLimit": 0,
        "SnapshotWindow": "10:00-11:00",
        "AuthTokenEnabled": false,
        "TransitEncryptionEnabled": false,
        "AtRestEncryptionEnabled": false,
        "ARN": "arn:aws:elasticache:us-east-1:101363889637:cluster:sadeed-001",
    },
    {
        "CacheClusterId": "sadeed-001",
        "ClientDownloadLandingPage": "https://console.aws.amazon.com/elasticache/home#client-download:",
        "CacheNodeType": "cache.t3.micro",
        "Engine": "redis",
        "EngineVersion": "6.0.5",
        "CacheClusterStatus": "available",
        "NumCacheNodes": 1,
        "PreferredAvailabilityZone": "us-east-1f",
        "CacheClusterCreateTime": "2021-11-11T11:49:33.551000+00:00",
        "PreferredMaintenanceWindow": "fri:03:00-fri:04:00",
        "PendingModifiedValues": {},
        "CacheSecurityGroups": [],
        "CacheParameterGroup": {
            "CacheParameterGroupName": "default.redis6.x",
            "ParameterApplyStatus": "in-sync",
            "CacheNodeIdsToReboot": []
        },
        "CacheSubnetGroupName": "elasticache-subnet",
        "AutoMinorVersionUpgrade": true,
        "SecurityGroups": [
            {
                "SecurityGroupId": "sg-aa941691",
                "Status": "active"
            }
        ],
        "ReplicationGroupId": "sad",
        "SnapshotRetentionLimit": 1,
        "SnapshotWindow": "04:00-05:00",
        "AuthTokenEnabled": false,
        "TransitEncryptionEnabled": false,
        "AtRestEncryptionEnabled": true,
        "ARN": "arn:aws:elasticache:us-east-1:560213429563:cluster:sad-001",
        "ReplicationGroupLogDeliveryEnabled": false,
        "LogDeliveryConfigurations": []
    }
];

const describeReplicationGroups = [
    {
        "ReplicationGroups": [
            {

                "ReplicationGroupId": "sadeed",
                "Description": " ",
                "GlobalReplicationGroupInfo": {},
                "Status": "creating",
                "PendingModifiedValues": {},
                "MemberClusters": [
                    "sadeed-001"
                ],
                "SnapshottingClusterId": "sadeed-001",
                "AutomaticFailover": "disabled",
                "MultiAZ": "enabled",
                "SnapshotRetentionLimit": 1,
                "SnapshotWindow": "04:00-05:00",
                "ClusterEnabled": false,
                "CacheNodeType": "cache.t3.micro",
                "AuthTokenEnabled": false,
                "TransitEncryptionEnabled": false,
                "AtRestEncryptionEnabled": true,
                "KmsKeyId": "arn:aws:kms:us-east-1:560213429563:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
                "ARN": "arn:aws:elasticache:us-east-1:560213429563:replicationgroup:sadeed",
                "LogDeliveryConfigurations": [],
                "ReplicationGroupCreateTime": "2021-11-11T09:30:37.072000+00:00"
            }
        ]
    },
    {
        "ReplicationGroups": [
            {

                "ReplicationGroupId": "sad",
                "Description": " ",
                "GlobalReplicationGroupInfo": {},
                "Status": "creating",
                "PendingModifiedValues": {},
                "MemberClusters": [
                    "sadeed-001"
                ],
                "SnapshottingClusterId": "sad-001",
                "AutomaticFailover": "disabled",
                "MultiAZ": "disabled",
                "SnapshotRetentionLimit": 1,
                "SnapshotWindow": "04:00-05:00",
                "ClusterEnabled": false,
                "CacheNodeType": "cache.t3.micro",
                "AuthTokenEnabled": false,
                "TransitEncryptionEnabled": false,
                "AtRestEncryptionEnabled": true,
                "ARN": "arn:aws:elasticache:us-east-1:560213429563:replicationgroup:sadeed",
                "LogDeliveryConfigurations": [],
                "ReplicationGroupCreateTime": "2021-11-11T09:30:37.072000+00:00"
            }
        ]
    }
];


const createCache = (clusters, describeReplicationGroups, clustersErr, describeReplicationGroupsErr) => {
    var ReplicationGroupId = (clusters && clusters.length) ? clusters[0].ReplicationGroupId : null;
    return {
        elasticache: {
            describeCacheClusters: {
                'us-east-1': {
                    err: clustersErr,
                    data: clusters
                },
            },
            describeReplicationGroups: {
                'us-east-1': {
                    [ReplicationGroupId]: {
                        data: describeReplicationGroups,
                        err: describeReplicationGroupsErr
                    }
                }
            }
        },
    }
}

describe('elasticacheRedisMultiAZ', function () {
    describe('run', function () {
        it('should PASS if ElastiCache Redis Cluster has MultiAZ feature enabled.', function (done) {
            const cache = createCache(describeCacheClusters[0], describeReplicationGroups[0]);
            elasticacheRedisMultiAZ.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if ElastiCache Redis Cluster does not have MultiAZ feature enabled.', function (done) {
            const cache = createCache([describeCacheClusters[1]], describeReplicationGroups[1]);
            elasticacheRedisMultiAZ.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no ElastiCache Redis Cluster found', function (done) {
            const cache = createCache([]);
            elasticacheRedisMultiAZ.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list ElastiCache Redis Cluster', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list ElastiCache Redis Cluster" });
            elasticacheRedisMultiAZ.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})