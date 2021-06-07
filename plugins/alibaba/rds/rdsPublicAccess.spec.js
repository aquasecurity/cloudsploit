var expect = require('chai').expect;
var rdsPublicAccess = require('./rdsPublicAccess.js');

const describeDBInstances = [
    {
        "DBInstanceId": "pgm-2ev213kfnogf7mfi",
        "Engine": "PostgreSQL"
    }
];

const describeInstanceWhitelist = [
    {
        Items: {
            DBInstanceIPArray: [
            {
                DBInstanceIPArrayAttribute: "",
                SecurityIPType: "IPv4",
                SecurityIPList: "127.0.0.1",
                WhitelistNetworkType: "MIX",
                DBInstanceIPArrayName: "default",
            },
            {
                DBInstanceIPArrayAttribute: "hidden",
                SecurityIPType: "IPv4",
                SecurityIPList: "10.81.176.172,10.81.89.178,100.104.172.0/24,100.104.220.0/24,11.193.102.115,11.193.102.131,11.195.184.229,11.195.184.232,11.195.184.233,11.195.184.234,11.195.184.83,11.195.184.84,11.195.184.89,11.195.184.93",
                WhitelistNetworkType: "MIX",
                DBInstanceIPArrayName: "hdm_security_ips",
            }],
        },
    },
    {
        Items: {
            DBInstanceIPArray: [
            {
                DBInstanceIPArrayAttribute: "",
                SecurityIPType: "IPv4",
                SecurityIPList: "127.0.0.1,0.0.0.0/0",
                WhitelistNetworkType: "MIX",
                DBInstanceIPArrayName: "default",
            },
            {
                DBInstanceIPArrayAttribute: "hidden",
                SecurityIPType: "IPv4",
                SecurityIPList: "10.81.176.172,10.81.89.178,100.104.172.0/24,100.104.220.0/24,11.193.102.115,11.193.102.131,11.195.184.229,11.195.184.232,11.195.184.233,11.195.184.234,11.195.184.83,11.195.184.84,11.195.184.89,11.195.184.93",
                WhitelistNetworkType: "MIX",
                DBInstanceIPArrayName: "hdm_security_ips",
            }],
        },
    }
];

const createCache = (dbInstances, describeInstanceWhitelist, dbInstancesErr, describeInstanceWhitelistErr) => {
    let instanceId = (dbInstances && dbInstances.length) ? dbInstances[0].DBInstanceId : null;
    return {
        rds: {
            DescribeDBInstances: {
                'cn-hangzhou': {
                    data: dbInstances,
                    err: dbInstancesErr
                },
            },
            DescribeDBInstanceIPArrayList: {
                'cn-hangzhou': {
                    [instanceId]: {
                        data: describeInstanceWhitelist,
                        err: describeInstanceWhitelistErr
                    }
                }
            }
        },
    };
};

describe('rdsPublicAccess', function () {
    describe('run', function () {
        it('should FAIL if RDS DB instance is publicly accessible', function (done) {
            const cache = createCache(describeDBInstances, describeInstanceWhitelist[1], null, null);
            rdsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('RDS DB instance is publicly accessible');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if RDS DB instance is not publicly accessible', function (done) {
            const cache = createCache(describeDBInstances, describeInstanceWhitelist[0]);
            rdsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('RDS DB instance is not publicly accessible');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no RDS DB instances found', function (done) {
            const cache = createCache([]);
            rdsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No RDS DB instances found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query RDS DB instances', function (done) {
            const cache = createCache([], null, { err: 'Unable to query RDS DB instances' });
            rdsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query RDS DB instances');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if Unable to query DB IP Array List', function (done) {
            const cache = createCache([describeDBInstances[0]], {}, null, { err: 'Unable to query DB IP Array List' });
            rdsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query DB IP Array List');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})