var expect = require('chai').expect;
var rdsSqlAuditRetentionPeriod = require('./rdsSqlAuditRetentionPeriod.js');

const describeDBInstances = [
    {
        "EngineVersion": "13.0",
        "DBInstanceId": "pgm-2ev213kfnogf7mfi",
        "Engine": "PostgreSQL"
    },
    {
        "EngineVersion": "13.0",
        "DBInstanceId": "pgm-2ev213kfnogf7mfi",
        "Engine": "MySQL"
    }
];

const describeSqlCollectorRetention = [
    {
        "ConfigValue": "30",
        "RequestId": "1C8130FE-6388-4EA8-90B0-9C0541D3D37F"
    },
    {
        "ConfigValue": "1095",
        "RequestId": "1C8130FE-6388-4EA8-90B0-9C0541D3D37F"
    }
];

const createCache = (describeDBInstances, describeSqlCollectorRetention, describeDBInstancesErr, describeSqlCollectorRetentionErr) => {
    let instanceId = (describeDBInstances && describeDBInstances.length) ? describeDBInstances[0].DBInstanceId : null;
    return {
        rds: {
            DescribeDBInstances: {
                'cn-hangzhou': {
                    data: describeDBInstances,
                    err: describeDBInstancesErr
                },
            },
            DescribeSQLCollectorRetention: {
                'cn-hangzhou': {
                    [instanceId]: {
                        data: describeSqlCollectorRetention,
                        err: describeSqlCollectorRetentionErr
                    }
                }
            }
        },
    };
};

describe('rdsSqlAuditRetentionPeriod', function () {
    describe('run', function () {
        it('should FAIL if RDS DB instance does not have sql audit log retention greater than 180 days', function (done) {
            const cache = createCache(describeDBInstances, describeSqlCollectorRetention[0]);
            rdsSqlAuditRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[0].message).to.include('is lesser than 180 days');
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it(`should FAIL if RDS DB instance does not have sql audit log retention greater than set days limit`, function (done) {
            const cache = createCache(describeDBInstances, describeSqlCollectorRetention[0]);
            rdsSqlAuditRetentionPeriod.run(cache, { sqlAuditRetentionPeriod: '300' }, (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[0].message).to.include(`is lesser than`);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if RDS DB instance have sql audit log retention greater than 180 days', function (done) {
            const cache = createCache(describeDBInstances, describeSqlCollectorRetention[1]);
            rdsSqlAuditRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[0].message).to.include('is greater than');
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it(`should PASS if RDS DB instance have sql audit log retention greater than set days limit`, function (done) {
            const cache = createCache(describeDBInstances, describeSqlCollectorRetention[1]);
            rdsSqlAuditRetentionPeriod.run(cache, { sqlAuditRetentionPeriod: '365' }, (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[0].message).to.include(`is greater than or equal to`);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no RDS DB instances found', function (done) {
            const cache = createCache([]);
            rdsSqlAuditRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('No RDS DB instances found');
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query RDS DB instances', function (done) {
            const cache = createCache([], null, { err: 'Unable to query RDS DB instances' });
            rdsSqlAuditRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('Unable to query RDS DB instances');
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query DB sql audit log retention', function (done) {
            const cache = createCache([describeDBInstances[0]], {}, null, { err: 'Unable to query DB sql audit log retention' });
            rdsSqlAuditRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('Unable to query DB sql audit log retention');
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})