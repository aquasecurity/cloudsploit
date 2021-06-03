var expect = require('chai').expect;
var rdsAuditingEnabled = require('./rdsAuditingEnabled.js');

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

const describeSqlAudit = [
    {
        SQLCollectorStatus: 'Enable'
    },
    {
        SQLCollectorStatus: 'Disabled'
    }
];

const createCache = (dbInstances, describeSqlAudit, dbInstancesErr, describeSqlAuditErr) => {
    let instanceId = (dbInstances && dbInstances.length) ? dbInstances[0].DBInstanceId : null;
    return {
        rds: {
            DescribeDBInstances: {
                'cn-hangzhou': {
                    data: dbInstances,
                    err: dbInstancesErr
                },
            },
            DescribeSQLCollectorPolicy: {
                'cn-hangzhou': {
                    [instanceId]: {
                        data: describeSqlAudit,
                        err: describeSqlAuditErr
                    }
                }
            }
        },
    };
};

describe('rdsAuditingEnabled', function () {
    describe('run', function () {
        it('should FAIL if RDS DB instance does not have sql auditing enabled', function (done) {
            const cache = createCache(describeDBInstances, describeSqlAudit[1]);
            rdsAuditingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('RDS DB instance does not have sql auditing enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if RDS DB instance have sql auditing enabled', function (done) {
            const cache = createCache(describeDBInstances, describeSqlAudit[0]);
            rdsAuditingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('RDS DB instance have sql auditing enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no RDS DB instances found', function (done) {
            const cache = createCache([]);
            rdsAuditingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No RDS DB instances found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query RDS DB instances', function (done) {
            const cache = createCache([], null, { err: 'Unable to query RDS DB instances' });
            rdsAuditingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query RDS DB instances');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query DB sql auditing policy', function (done) {
            const cache = createCache([describeDBInstances[0]], {}, null, { err: 'Unable to query DB sql auditing policy' });
            rdsAuditingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query DB sql auditing policy');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})