const expect = require('chai').expect;
var iamDbAuthenticationEnabled = require('./iamDbAuthenticationEnabled');

const describeDBInstances = [
    {
        "DBInstanceArn": "arn:aws:rds:ap-south-1:111222333444:db:database-1",
        "IAMDatabaseAuthenticationEnabled": true,
        "Engine": "postgres",
    },
    {
        "DBInstanceArn": "arn:aws:rds:ap-south-1:111222333444:db:database-1",
        "IAMDatabaseAuthenticationEnabled": false,
        "Engine": "postgres",
    }
];

const createCache = (clusterData, clusterErr) => {
    return {
        rds: {
            describeDBInstances: {
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
        rds: {
            describeDBInstances: {
                'us-east-1': null
            }
        }
    };
};

describe('iamDbAuthenticationEnabled', function () {
    describe('run', function () {

        it('should PASS if RDS instance has IAM Database Authentication enabled', function (done) {
            const cache = createCache([describeDBInstances[0]]);
            iamDbAuthenticationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if RDS instance does not have IAM Database Authentication enabled', function (done) {
            const cache = createCache([describeDBInstances[1]]);
            iamDbAuthenticationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no RDS instances found', function (done) {
            const cache = createCache([]);
            iamDbAuthenticationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to describe RDS instances', function (done) {
            const cache = createCache([], { message: 'Unable to describe instances' });
            iamDbAuthenticationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should not return anything if describe DB instances response not found', function (done) {
            const cache = createNullCache();
            iamDbAuthenticationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});