var expect = require('chai').expect;
var neptuneDBIamAuth = require('./neptuneDBIamAuth');

const describeDBClusters = [
    {
        "AllocatedStorage": 1,
        "BackupRetentionPeriod": 1,
        "DbClusterResourceId": "cluster-WNY2ZTZWH4RQ2CTKEEP4GVCPU4",
        "DBClusterArn": "arn:aws:rds:us-east-1:000111222333:cluster:database-2",
        "AssociatedRoles": [],
        "IAMDatabaseAuthenticationEnabled": true
    },
    {
        "AllocatedStorage": 1,
        "BackupRetentionPeriod": 1,
        "DbClusterResourceId": "cluster-WNY2ZTZWH4RQ2CTKEEP4GVCPU9",
        "DBClusterArn": "arn:aws:rds:us-east-1:000111222334:cluster:database-3",
        "AssociatedRoles": [],
        "IAMDatabaseAuthenticationEnabled": false
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



describe('neptuneDBIamAuth', function () {
    describe('run', function () {
        it('should PASS if Neptune database instance has IAM authentication enabled', function (done) {
            const cache = createCache([describeDBClusters[0]]);
            neptuneDBIamAuth.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Neptune database instance has IAM authentication enabled');
                expect(results[0].region).to.include('us-east-1');
                done();
            });
        });


        it('should FAIL if Neptune database instance does not have IAM authentication enabled', function (done) {
            const cache = createCache([describeDBClusters[1]]);
            neptuneDBIamAuth.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Neptune database instance does not have IAM authentication enabled');
                expect(results[0].region).to.include('us-east-1');
                done();
            });
        });


        it('should PASS if no Neptune database instances found', function (done) {
            const cache = createCache([]);
            neptuneDBIamAuth.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Neptune database instances found');
                expect(results[0].region).to.include('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Neptune Database instances', function (done) {
            const cache = createCache(null, { message: "Unable to list Neptune database instances" });
            neptuneDBIamAuth.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list Neptune database instances:');
                expect(results[0].region).to.include('us-east-1');
                done();
            });
        });
    });
});
