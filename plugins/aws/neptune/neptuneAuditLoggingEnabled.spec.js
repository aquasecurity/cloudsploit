var expect = require('chai').expect;
var neptuneAuditLoggingEnabled = require('./neptuneAuditLoggingEnabled');

const describeDBClusters = [
    {
        AvailabilityZones: [],
        BackupRetentionPeriod: 1,
        DBClusterArn: 'arn:aws:rds:us-east-1:000011112222:cluster:neptune-cluster-1',
        DBClusterIdentifier: 'neptune-cluster-1',
        DBClusterParameterGroup: 'default.neptune1',
        DBSubnetGroup: 'default-vpc-99de2fe4',
        Status: 'available',
        Engine: 'neptune',
        EnabledCloudwatchLogsExports: [ "audit", "error"]
    },
    {
        AvailabilityZones: [],
        BackupRetentionPeriod: 10,
        DBClusterArn: 'arn:aws:rds:us-east-1:000011112223:cluster:neptune-cluster-2',
        DBClusterIdentifier: 'neptune-cluster-2',
        DBClusterParameterGroup: 'default.neptune1',
        DBSubnetGroup: 'default-vpc-99de2fe4',
        Status: 'available',
        Engine: 'neptune',
        EnabledCloudwatchLogsExports: [ "error"]
    },
    {
        AvailabilityZones: [],
        BackupRetentionPeriod: 10,
        DBClusterArn: 'arn:aws:rds:us-east-1:000011112224:cluster:neptune-cluster-3',
        DBClusterIdentifier: 'neptune-cluster-3',
        DBClusterParameterGroup: 'default.neptune1',
        DBSubnetGroup: 'default-vpc-99de2fe4',
        Status: 'available',
        Engine: 'neptune',
        EnabledCloudwatchLogsExports: []
    },
    {
        AvailabilityZones: [],
        BackupRetentionPeriod: 10,
        DBClusterArn: 'arn:aws:rds:us-east-1:000011112225:cluster:neptune-cluster-4',
        DBClusterIdentifier: 'neptune-cluster-4',
        DBClusterParameterGroup: 'default.neptune1',
        DBSubnetGroup: 'default-vpc-99de2fe4',
        Status: 'available',
        Engine: 'neptune'
    }
];

const createCache = (clusters, clustersErr) => {
    return {
        neptune: {
            describeDBClusters: {
                'us-east-1': {
                    err: clustersErr,
                    data: clusters
                },
            },
        }
    };
};

describe('neptuneAuditLoggingEnabled', function () {
    describe('run', function () {
        it('should PASS if Neptune cluster has audit logging enabled', function (done) {
            const cache = createCache([describeDBClusters[0]]);
            neptuneAuditLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Neptune database cluster has audit logging enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Neptune cluster does not have audit logging enabled', function (done) {
            const cache = createCache([describeDBClusters[1]]);
            neptuneAuditLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Neptune database cluster does not have audit logging enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Neptune cluster has empty EnabledCloudwatchLogsExports', function (done) {
            const cache = createCache([describeDBClusters[2]]);
            neptuneAuditLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Neptune database cluster does not have audit logging enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Neptune cluster does not have EnabledCloudwatchLogsExports property', function (done) {
            const cache = createCache([describeDBClusters[3]]);
            neptuneAuditLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Neptune database cluster does not have audit logging enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Neptune clusters found', function (done) {
            const cache = createCache([]);
            neptuneAuditLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Neptune database clusters found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Neptune clusters', function (done) {
            const cache = createCache(null,  { message: "Unable to list Neptune clusters" });
            neptuneAuditLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list Neptune database clusters:');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});

