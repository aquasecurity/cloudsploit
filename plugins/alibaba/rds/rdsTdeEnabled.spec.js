var expect = require('chai').expect;
var rdsTdeEnabled = require('./rdsTdeEnabled.js');

const describeDBInstances = [
    {
        "EngineVersion": "5.6",
        "DBInstanceId": "rm-7go88dw3m8uw51ayj",
        "Engine": "MySQL"
    },
    {
        "EngineVersion": "13.0",
        "DBInstanceId": "pgm-2ev213kfnogf7mfi",
        "Engine": "PostgreSQL"
    }
];

const describeDBTde = [
    {
        TDEStatus: 'Enabled'
    },
    {
        TDEStatus: 'Disabled'
    }
];

const createCache = (dbInstances, describeDBTde, dbInstancesErr, describeDBTdeErr) => {
    let instanceId = (dbInstances && dbInstances.length) ? dbInstances[0].DBInstanceId : null;
    return {
        rds: {
            DescribeDBInstances: {
                'cn-hangzhou': {
                    data: dbInstances,
                    err: dbInstancesErr
                },
            },
            DescribeDBInstanceTDE: {
                'cn-hangzhou': {
                    [instanceId]: {
                        data: describeDBTde,
                        err: describeDBTdeErr
                    }
                }
            }
        },
    };
};

describe('rdsTdeEnabled', function () {
    describe('run', function () {
        it('should FAIL if RDS DB instance does not have TDE enabled', function (done) {
            const cache = createCache(describeDBInstances, describeDBTde[1]);
            rdsTdeEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('RDS DB instance does not have TDE enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if RDS DB instance have TDE enabled', function (done) {
            const cache = createCache(describeDBInstances, describeDBTde[0]);
            rdsTdeEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('RDS DB instance has TDE enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if RDS DB instance have engine type other MySQL 5.6 and SQL Server Enterprise Edition', function (done) {
            const cache = createCache(describeDBInstances, describeDBTde[0]);
            rdsTdeEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include(`TDE is not supported for postgresql 13.0 engine type`);
                expect(results[1].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no RDS DB instances found', function (done) {
            const cache = createCache([]);
            rdsTdeEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No RDS DB instances found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query RDS DB instances', function (done) {
            const cache = createCache([], null, { err: 'Unable to query RDS DB instances' });
            rdsTdeEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query RDS DB instances');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query RDS DB instance TDE', function (done) {
            const cache = createCache([describeDBInstances[0]], {}, null, { err: 'Unable to query RDS DB instance TDE' });
            rdsTdeEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query RDS DB instance TDE');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})