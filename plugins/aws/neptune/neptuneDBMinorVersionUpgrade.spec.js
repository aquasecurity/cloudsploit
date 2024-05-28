var expect = require('chai').expect;
var neptuneDBMinorVersionUpgrade = require('./neptuneDBMinorVersionUpgrade');

const describeDBInstances = [
    {
        DBInstanceIdentifier: "db-neptune-1-instance-1",
        Engine: "neptune",
        AutoMinorVersionUpgrade: true,
        DBClusterIdentifier: "db-neptune-1",
        DBInstanceArn: "arn:aws:rds:us-east-1:12341234123:db:db-neptune-1-instance-1"
    },
    {
        DBInstanceIdentifier: "db-neptune-1-instance-1",
        Engine: "neptune",
        AutoMinorVersionUpgrade: false,
        DBClusterIdentifier: "db-neptune-1",
        DBInstanceArn: "arn:aws:rds:us-east-1:12341234123:db:db-neptune-1-instance-1"
    }
];

const createCache = (clusters, clustersErr) => {
    return {
        neptune: {
            describeDBInstances: {
                'us-east-1': {
                    err: clustersErr,
                    data: clusters
                },
            },
        },
    };
};

describe('neptuneDBMinorVersionUpgrade', function () {
    describe('run', function () {
        it('should PASS if Neptune database instance has auto minor version upgrade enabled', function (done) {
            const cache = createCache([describeDBInstances[0]]);
            neptuneDBMinorVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Neptune database instance has auto minor version upgrade enabled');
                expect(results[0].region).to.include('us-east-1');
                done();
            });
        });


        it('should FAIL if Neptune database instance does not have auto minor version upgrade enabled', function (done) {
            const cache = createCache([describeDBInstances[1]]);
            neptuneDBMinorVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Neptune database instance does not have auto minor version upgrade enabled');
                expect(results[0].region).to.include('us-east-1');
                done();
            });
        });

        it('should PASS if no Neptune database instances found', function (done) {
            const cache = createCache([]);
            neptuneDBMinorVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Neptune database instances found');
                expect(results[0].region).to.include('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Neptune Database instances', function (done) {
            const cache = createCache(null, { message: "Unable to list Neptune database cluster instances" });
            neptuneDBMinorVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.include('us-east-1');
                done();
            });
        });
    });
});