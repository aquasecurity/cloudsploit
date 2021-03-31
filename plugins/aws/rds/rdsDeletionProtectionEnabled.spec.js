const expect = require('chai').expect;
var rdsDeletionProtectionEnabled = require('./rdsDeletionProtectionEnabled');

const describeDBInstances = [
    {
        "DBInstanceIdentifier": "database-1",
        "Engine": "mysql",
        "DBInstanceStatus": "available",
        "DBInstanceArn": "arn:aws:rds:us-east-1:560213429563:db:database-1",
        "IAMDatabaseAuthenticationEnabled": false,
        "PerformanceInsightsEnabled": false,
        "DeletionProtection": true,
        "AssociatedRoles": [],
        "TagList": [],
        "CustomerOwnedIpEnabled": false
    },
    {
        "DBInstanceIdentifier": "database-1",
        "Engine": "mysql",
        "DBInstanceStatus": "available",
        "DBInstanceArn": "arn:aws:rds:us-east-1:560213429563:db:database-1",
        "IAMDatabaseAuthenticationEnabled": false,
        "PerformanceInsightsEnabled": false,
        "DeletionProtection": false,
        "AssociatedRoles": [],
        "TagList": [],
        "CustomerOwnedIpEnabled": false
    }
];

const createCache = (instanceData, instanceErr) => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    data: instanceData,
                    err: instanceErr
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': null
            }
        }
    };
};

describe('rdsDeletionProtectionEnabled', function () {
    describe('run', function () {

        it('should PASS if RDS instance has deletion protection enabled', function (done) {
            const cache = createCache([describeDBInstances[0]]);
            rdsDeletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if RDS instance does not have deletion protection enabled', function (done) {
            const cache = createCache([describeDBInstances[1]]);
            rdsDeletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no RDS instances found', function (done) {
            const cache = createCache([]);
            rdsDeletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to describe RDS instances', function (done) {
            const cache = createCache([], { message: 'Unable to describe instances' });
            rdsDeletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should not return anything if describe RDS instances response not found', function (done) {
            const cache = createNullCache();
            rdsDeletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});