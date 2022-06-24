var expect = require('chai').expect;
var redisClusterEncryptionAtRest = require('./redisClusterEncryptionAtRest');

const describeCacheClusters = [
    {   
        "CacheClusterId": "sadeed-001",
        "ClientDownloadLandingPage": "https://console.aws.amazon.com/elasticache/home#client-download:",
        "CacheNodeType": "cache.t3.micro",
        "Engine": "redis",
        "EngineVersion": "6.0.5",
        "CacheClusterStatus": "creating",
        "NumCacheNodes": 1,
        "PreferredAvailabilityZone": "us-east-1f",
        "PreferredMaintenanceWindow": "tue:05:00-tue:06:00",
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
        "ReplicationGroupId": "sadeed",
        "SnapshotRetentionLimit": 1,
        "SnapshotWindow": "04:00-05:00",
        "AuthTokenEnabled": false,
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
        "ReplicationGroupId": "sadeed",
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
                "MultiAZ": "disabled",
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

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my Glue data when no other key is defined",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    },
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my Glue data when no other key is defined",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "AWS",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    }
];

const listKeys = [
    {
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250"
    }
]

const createCache = (clusters, keys, describeReplicationGroups, describeKey, clustersErr, keysErr, describeKeyErr, describeReplicationGroupsErr) => {
    var keyId = (clusters && clusters.length && clusters[0].KmsKeyId) ? clusters[0].KmsKeyId.split('/')[1] : null;
    var ReplicationGroupId = (clusters && clusters.length) ? clusters[0].ReplicationGroupId: null;
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
        kms: {
            listKeys: {
                'us-east-1': {
                    data: keys,
                    err: keysErr
                }
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        err: describeKeyErr,
                        data: describeKey
                    },
                },
            },
        },
    };
};

describe('redisClusterEncryptionAtRest', function () {
    describe('run', function () {
        it('should PASS if Redis Cluster at-rest is encrypted with desired encryption level', function (done) {
            const cache = createCache(describeCacheClusters[0], listKeys, describeReplicationGroups[0], describeKey[0]);
            redisClusterEncryptionAtRest.run(cache, { ec_atrest_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Redis Cluster at-rest is not encrypted with desired encryption level', function (done) {
            const cache = createCache([describeCacheClusters[1]],listKeys, describeReplicationGroups[1], describeKey[1]);
            redisClusterEncryptionAtRest.run(cache, { ec_atrest_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no  Redis Cluster at-rest found', function (done) {
            const cache = createCache([]);
            redisClusterEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list  Redis Cluster at-rest', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list AppFlow flows" });
            redisClusterEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(describeCacheClusters, null, null, null, { message: "Unable to list KMS keys" });
            redisClusterEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})