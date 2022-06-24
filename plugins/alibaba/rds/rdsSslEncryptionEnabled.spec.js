var expect = require('chai').expect;
var rdsSslEncryptionEnabled = require('./rdsSslEncryptionEnabled.js');

const describeDBInstances = [
    {
        "EngineVersion": "13.0",
        "DBInstanceStatus": "Running",
        "ResourceGroupId": "rg-aekzsj44b4lt5fa",
        "DBInstanceNetType": "Intranet",
        "DBInstanceClass": "pg.n2.small.2c",
        "CreateTime": "2021-05-04T17:13:45Z",
        "VSwitchId": "vsw-rj94uhhrj5qz5008lwi1x",
        "DBInstanceType": "Primary",
        "PayType": "Postpaid",
        "LockMode": "Unlock",
        "MutriORsignle": false,
        "InstanceNetworkType": "VPC",
        "InsId": 1,
        "VpcId": "vpc-rj9vu86hdve3qr173ew17",
        "DBInstanceId": "pgm-2ev213kfnogf7mfi",
        "ConnectionMode": "Standard",
        "ReadOnlyDBInstanceIds": {
          "ReadOnlyDBInstanceId": []
        },
        "VpcCloudInstanceId": "pgm-2ev213kfnogf7mfi",
        "ExpireTime": "",
        "LockReason": "",
        "Engine": "PostgreSQL"
    }
];

const describeDBInstanceSSL = [
    {
        "SSLExpireTime": "",
        "RequestId": "B61DFDF9-627C-41BD-81C6-5DF77D2A63ED",
        "RequireUpdateReason": "",
        "ConnectionString": "",
        "RequireUpdate": "Yes"
    },
    {
        "SSLExpireTime": "",
        "RequestId": "B61DFDF9-627C-41BD-81C6-5DF77D2A63ED",
        "RequireUpdateReason": "",
        "ConnectionString": "",
        "RequireUpdate": "No"
    }
];

const createCache = (dbInstances, dbSslData, dbInstancesErr, dbSslErr) => {
    let instanceId = (dbInstances && dbInstances.length) ? dbInstances[0].DBInstanceId : null;
    return {
        rds: {
            DescribeDBInstances: {
                'cn-hangzhou': {
                    data: dbInstances,
                    err: dbInstancesErr
                },
            },
            DescribeDBInstanceSSL: {
                'cn-hangzhou': {
                    [instanceId]: {
                        data: dbSslData,
                        err: dbSslErr
                    }
                }
            }
        },
    };
};

describe('rdsSslEncryptionEnabled', function () {
    describe('run', function () {
        it('should FAIL if RDS instance does not have SSL encryption enabled', function (done) {
            const cache = createCache([describeDBInstances[0]], describeDBInstanceSSL[1]);
            rdsSslEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('RDS instance does not have SSL encryption enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if RDS instance has SSL encryption enabled', function (done) {
            const cache = createCache([describeDBInstances[0]], describeDBInstanceSSL[0]);
            rdsSslEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('RDS instance has SSL encryption enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no RDS DB instances found', function (done) {
            const cache = createCache([]);
            rdsSslEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No RDS DB instances found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query RDS DB instances', function (done) {
            const cache = createCache([], null, { err: 'Unable to query RDS DB instances' });
            rdsSslEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query RDS DB instances');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query RDS instance SSL info', function (done) {
            const cache = createCache([describeDBInstances[0]], {}, null, { err: 'Unable to query RDS instance SSL info' });
            rdsSslEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query RDS instance SSL info');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})