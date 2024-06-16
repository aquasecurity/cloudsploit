var expect = require('chai').expect;
var docdbProfilerEnabled = require('./docdbClusterProfilerEnabled');

const describeDBClusters = [
    {
      AvailabilityZones: [],
      BackupRetentionPeriod: 1,
      DBClusterArn: 'arn:aws:rds:us-east-1:000011112222:cluster:docdb-2021-11-10-10-16-10',
      DBClusterIdentifier: 'docdb-2021-11-10-10-16-10',
      DBClusterParameterGroup: 'default.docdb4.0',
      DBSubnetGroup: 'default-vpc-99de2fe4',
      Status: 'available',
      DeletionProtection: true,
      EnabledCloudwatchLogsExports: [ "audit", "profiler"]
    },
    {
      AvailabilityZones: [],
      BackupRetentionPeriod: 10,
      DBClusterArn: 'arn:aws:rds:us-east-1:000011112223:cluster:docdb-2021-11-10-10-16-10',
      DBClusterIdentifier: 'docdb-2021-11-10-10-16-10',
      DBClusterParameterGroup: 'default.docdb4.0',
      DBSubnetGroup: 'default-vpc-99de2fe4',
      Status: 'available',
      DeletionProtection: false,
      EnabledCloudwatchLogsExports: [ "audit"]
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

describe('docdbProfilerEnabled', function () {
    describe('run', function () {
        it('should PASS if DocumentDb Cluster has profiler feature  enabled', function (done) {
            const cache = createCache([describeDBClusters[0]]);
            docdbProfilerEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('DocumentDB cluster has profiler feature enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if DocumentDB Clusters does not have profiler feature  enabled', function (done) {
            const cache = createCache([describeDBClusters[1]]);
            docdbProfilerEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('DocumentDB cluster does not have profiler feature enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no DocumentDB Clusters found', function (done) {
            const cache = createCache([]);
            docdbProfilerEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No DocumentDB clusters found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list DocumentDB Clusters', function (done) {
            const cache = createCache(null,  { message: "Unable to list DocumentDB Clusters encryption" });
            docdbProfilerEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list DocumentDB clusters:');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
