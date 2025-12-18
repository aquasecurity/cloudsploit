var expect = require('chai').expect;
var neptuneAuditLogging = require('./neptuneAuditLoggingEnabled'); 


const describeDBClusters = [
    {
        "AllocatedStorage": 1,
        "BackupRetentionPeriod": 1,
        "DbClusterResourceId": "cluster-AUDIT1",
        "DBClusterArn": "arn:aws:rds:us-east-1:000111222333:cluster:database-2",
        "AssociatedRoles": [],
        "Engine": "neptune",
        "EnableAuditLog": true
    },
    {
        "AllocatedStorage": 1,
        "BackupRetentionPeriod": 1,
        "DbClusterResourceId": "cluster-AUDIT2",
        "DBClusterArn": "arn:aws:rds:us-east-1:000111222334:cluster:database-3",
        "AssociatedRoles": [],
        "Engine": "neptune",
        "EnableAuditLog": false
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
        },
    };
};

describe('neptuneAuditLogging', function () {
    describe('run', function () {

        it('should PASS if Neptune DB cluster has audit logging enabled', function (done) {
            const cache = createCache([describeDBClusters[0]]);
            neptuneAuditLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Neptune audit logging is enabled');
                expect(results[0].region).to.include('us-east-1');
                done();
            });
        });

        it('should FAIL if Neptune DB cluster does not have audit logging enabled', function (done) {
            const cache = createCache([describeDBClusters[1]]);
            neptuneAuditLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Neptune audit logging is disabled');
                expect(results[0].region).to.include('us-east-1');
                done();
            });
        });

        it('should PASS if no Neptune DB clusters found', function (done) {
            const cache = createCache([]);
            neptuneAuditLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Neptune database clusters found');
                expect(results[0].region).to.include('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Neptune DB clusters', function (done) {
            const cache = createCache(null, { message: "Unable to list Neptune database clusters" });
            neptuneAuditLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.include('us-east-1');
                done();
            });
        });

    });
});
