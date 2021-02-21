const expect = require('chai').expect;
var dbDeletionProtectionEnabled = require('./dbDeletionProtectionEnabled');

const describeDBClusters = [
    {
        "MasterUsername": "admin",
        "PreferredBackupWindow": "08:37-09:07",
        "HostedZoneId": "ZUFXD4SLT2LS7",
        "StorageEncrypted": false,
        "DbClusterResourceId": "cluster-H4KOO22AIJUW5I7YRZ4MBSIHKQ",
        "DBClusterArn": "arn:aws:rds:us-east-1:112233445566:cluster:cluster-1",
        "DeletionProtection": true
    },
    {
        "MasterUsername": "admin",
        "PreferredBackupWindow": "08:37-09:07",
        "HostedZoneId": "ZUFXD4SLT2LS7",
        "StorageEncrypted": false,
        "DbClusterResourceId": "cluster-H4KOO22AIJUW5I7YRZ4MBSIHKQ",
        "DBClusterArn": "arn:aws:rds:us-east-1:112233445566:cluster:cluster-1",
        "DeletionProtection": false
    }
];

const createCache = (clusterData, clusterErr) => {
    return {
        neptune: {
            describeDBClusters: {
                'us-east-1': {
                    data: clusterData,
                    err: clusterErr
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        neptune: {
            describeDBClusters: {
                'us-east-1': null
            }
        }
    };
};

describe('dbDeletionProtectionEnabled', function () {
    describe('run', function () {

        it('should PASS if DB cluster has deletion protection enabled', function (done) {
            const cache = createCache([describeDBClusters[0]]);
            dbDeletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if DB cluster does not have deletion protection enabled', function (done) {
            const cache = createCache([describeDBClusters[1]]);
            dbDeletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Neptune clusters found', function (done) {
            const cache = createCache([]);
            dbDeletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to describe DB clusters', function (done) {
            const cache = createCache([], { message: 'Unable to describe clusters' });
            dbDeletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should not return anything if describe DB clusters response not found', function (done) {
            const cache = createNullCache();
            dbDeletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});