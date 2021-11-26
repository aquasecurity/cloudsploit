var expect = require('chai').expect;
var docdbClusterEncrypted = require('./docdbClusterEncrypted');


const describeDBClusters = [
    {
      AvailabilityZones: [Array],
      BackupRetentionPeriod: 1,
      DBClusterIdentifier: 'docdb-2021-11-10-10-16-10',
      DBClusterParameterGroup: 'default.docdb4.0',
      DBSubnetGroup: 'default-vpc-99de2fe4',
      Status: 'available',
      EarliestRestorableTime: '2021-11-10T10:18:02.730Z',
      Endpoint: 'docdb-2021-11-10-10-16-10.cluster-csumzsa0neyf.us-east-1.docdb.amazonaws.com',
      ReaderEndpoint: 'docdb-2021-11-10-10-16-10.cluster-ro-csumzsa0neyf.us-east-1.docdb.amazonaws.com',
      MultiAZ: false,
      Engine: 'docdb',
      EngineVersion: '4.0.0',
      LatestRestorableTime: '2021-11-10T10:18:02.730Z',
      Port: 27017,
      MasterUsername: 'cloudsploit',
      PreferredBackupWindow: '00:00-00:30',
      PreferredMaintenanceWindow: 'thu:05:24-thu:05:54',
      ReadReplicaIdentifiers: [],
      DBClusterMembers: [Array],
      VpcSecurityGroups: [Array],
      HostedZoneId: 'ZNKXH85TT8WVW',
      StorageEncrypted: true,
      KmsKeyId: 'arn:aws:kms:us-east-1:000011112222:key/2cff2321-73c6-4bac-95eb-bc9633d3e8a9',
      DbClusterResourceId: 'cluster-TWDPR3PSXGUPMCESNBK6W55SH4',
      DBClusterArn: 'arn:aws:rds:us-east-1:000011112222:cluster:docdb-2021-11-10-10-16-10',
      AssociatedRoles: [],
      ClusterCreateTime: '2021-11-10T10:16:49.359Z',
      EnabledCloudwatchLogsExports: [],
      DeletionProtection: true
    }
];

const listKeys = [
    {
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/2cff2321-73c6-4bac-95eb-bc9633d3e8a9"
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "2cff2321-73c6-4bac-95eb-bc9633d3e8a9",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/2cff2321-73c6-4bac-95eb-bc9633d3e8a9",
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
            "KeyId": "2cff2321-73c6-4bac-95eb-bc9633d3e8a9",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/2cff2321-73c6-4bac-95eb-bc9633d3e8a9",
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

const createCache = (clusters, keys, describeKey, clustersErr, keysErr, describeKeyErr) => {
    var keyId = (clusters && clusters.length && clusters[0].KmsKeyId) ? clusters[0].KmsKeyId.split('/')[1] : null;
    return {
        docdb: {
            describeDBClusters: {
                'us-east-1': {
                    err: clustersErr,
                    data: clusters
                },
            },
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



describe('docdbClusterEncrypted', function () {
    describe('run', function () {
        it('should PASS if DocumentDb Cluster is encrypted with desired encryption level', function (done) {
            const cache = createCache(describeDBClusters, listKeys, describeKey[0]);
            docdbClusterEncrypted.run(cache, { documentdb_cluster_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('DocumentDB cluster is encrypted with awscmk');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should FAIL if DocumentDB Clusters is not encrypted with desired encyption level', function (done) {
            const cache = createCache(describeDBClusters, listKeys, describeKey[1]);
            docdbClusterEncrypted.run(cache, { documentdb_cluster_desired_encryption_level:'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('DocumentDB cluster is encrypted with awskms ');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should PASS if no DocumentDB Clusters found', function (done) {
            const cache = createCache([]);
            docdbClusterEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No DocumentDB clusters found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list DocumentDB Clusters', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list DocumentDB Clusters encryption" });
            docdbClusterEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list KMS keys" });
            docdbClusterEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
