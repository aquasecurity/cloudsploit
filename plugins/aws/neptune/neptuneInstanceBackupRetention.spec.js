var expect = require('chai').expect;
var neptuneInstanceBackupRetention = require('./neptuneInstanceBackupRetention');

const describeDBClusters = [
    {
        "BackupRetentionPeriod": 1,
        "DBClusterIdentifier": "database-2",
        "DBClusterParameterGroup": "default.neptune1",
        "DBSubnetGroup": "default-vpc-0f4f4575a74fac014",
        "Status": "available",
        "EarliestRestorableTime": "2021-11-16T09:01:51.536000+00:00",
        "Endpoint": "database-2.cluster-cscif9l5pu36.us-east-1.neptune.amazonaws.com",
        "ReaderEndpoint": "database-2.cluster-ro-cscif9l5pu36.us-east-1.neptune.amazonaws.com",
        "Engine": "neptune",
        "DbClusterResourceId": "cluster-WNY2ZTZWH4RQ2CTKEEP4GVCPU4",
        "DBClusterArn": "arn:aws:rds:us-east-1:000111222333:cluster:database-2",
        "AssociatedRoles": [],
    },
    {
        "BackupRetentionPeriod": 10,
        "DBClusterIdentifier": "database-3",
        "DBClusterParameterGroup": "default.neptune1",
        "DBSubnetGroup": "default-vpc-0f4f4575a74fac014",
        "Status": "available",
        "EarliestRestorableTime": "2021-11-16T09:01:51.536000+00:00",
        "Endpoint": "database-3.cluster-cscif9l5pu36.us-east-1.neptune.amazonaws.com",
        "ReaderEndpoint": "database-3.cluster-ro-cscif9l5pu36.us-east-1.neptune.amazonaws.com",
        "Engine": "neptune",
        "DbClusterResourceId": "cluster-WNY2ZTZWH4RQ2CTKEEP4GVCPU4",
        "DBClusterArn": "arn:aws:rds:us-east-1:000111222333:cluster:database-3",
        "AssociatedRoles": [],
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

describe('neptuneInstanceBackupRetention', function () {
    describe('run', function () {
        it('should PASS if Neptune database instance Cluster has the recommended backup retention period', function (done) {
            const cache = createCache([describeDBClusters[1]]);
            neptuneInstanceBackupRetention.run(cache, { doc_db_backup_retention_threshold: 7 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Neptune database instance has a backup retention period of 10 which is greater than or equal to 7 days limit');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Neptune database instance do not have the recommended backup retention period', function (done) {
            const cache = createCache([describeDBClusters[0]]);
            neptuneInstanceBackupRetention.run(cache, { doc_db_backup_retention_threshold: 7 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Neptune database instance has a backup retention period of 1 which is less than 7 days limit');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Neptune database instances found', function (done) {
            const cache = createCache([]);
            neptuneInstanceBackupRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Neptune database instances found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Neptune database instance', function (done) {
            const cache = createCache(null,  { message: "Unable to list Neptune database instance encryption" });
            neptuneInstanceBackupRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
