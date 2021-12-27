var expect = require('chai').expect;
var docdbClusterBackupRetention = require('./docdbClusterBackupRetention');

const describeDBClusters = [
    {
      AvailabilityZones: [],
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
      DBClusterMembers: [],
      VpcSecurityGroups: [],
      HostedZoneId: 'ZNKXH85TT8WVW',
      StorageEncrypted: true,
      KmsKeyId: 'arn:aws:kms:us-east-1:000011112222:key/2cff2321-73c6-4bac-95eb-bc9633d3e8a9',
      DbClusterResourceId: 'cluster-TWDPR3PSXGUPMCESNBK6W55SH4',
      DBClusterArn: 'arn:aws:rds:us-east-1:000011112222:cluster:docdb-2021-11-10-10-16-10',
      AssociatedRoles: [],
      ClusterCreateTime: '2021-11-10T10:16:49.359Z',
      EnabledCloudwatchLogsExports: [],
      DeletionProtection: true
    },
    {
      AvailabilityZones: [],
      BackupRetentionPeriod: 10,
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
      DBClusterMembers: [],
      VpcSecurityGroups: [],
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

const createCache = (clusters, clustersErr) => {
    return {
        docdb: {
            describeDBClusters: {
                'us-east-1': {
                    err: clustersErr,
                    data: clusters
                },
            },
        }
    };
};

describe('docdbClusterBackupRetention', function () {
    describe('run', function () {
        it('should PASS if DocumentDb Cluster has the recommended backup retention period', function (done) {
            const cache = createCache([describeDBClusters[1]]);
            docdbClusterBackupRetention.run(cache, { doc_db_backup_retention_threshold: 7 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('DocumentDB cluster has a backup retention period of 10');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if DocumentDB Clusters do not have the recommended backup retention period', function (done) {
            const cache = createCache([describeDBClusters[0]]);
            docdbClusterBackupRetention.run(cache, { doc_db_backup_retention_threshold: 7 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('DocumentDB cluster has a backup retention period of 1');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no DocumentDB Clusters found', function (done) {
            const cache = createCache([]);
            docdbClusterBackupRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No DocumentDB clusters found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list DocumentDB Clusters', function (done) {
            const cache = createCache(null,  { message: "Unable to list DocumentDB Clusters encryption" });
            docdbClusterBackupRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
