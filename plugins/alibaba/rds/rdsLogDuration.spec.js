var expect = require('chai').expect;
var rdsLogDuration = require('./rdsLogDuration.js');

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

const describeParameters = [
    {
        "RunningParameters": {
          "DBInstanceParameter": [
                {
                    "ParameterValue": "on",
                    "ParameterName": "log_duration",
                    "ParameterDescription": "Logs the duration of each completed SQL statement."
                },
                {
                    "ParameterValue": "off",
                    "ParameterName": "jit",
                    "ParameterDescription": "allow JIT compilation"
                },
                {
                    "ParameterValue": "0",
                    "ParameterName": "lock_timeout",
                    "ParameterDescription": "Sets the maximum allowed duration of any wait for a lock. A value of 0 turns off the timeout."
                },
                {
                    "ParameterValue": "off",
                    "ParameterName": "log_connections",
                    "ParameterDescription": "Logs each successful connection."
                },
                {
                    "ParameterValue": "off",
                    "ParameterName": "log_disconnections",
                    "ParameterDescription": "Logs end of a session, including duration."
                },
                {
                    "ParameterValue": "1000",
                    "ParameterName": "log_min_duration_statement",
                    "ParameterDescription": "SQL with execution time exceeding this value will be logged. Note that a too small value may cause performance degradation and increase the amount of logs."
                },
                {
                    "ParameterValue": "ddl",
                    "ParameterName": "log_statement",
                    "ParameterDescription": "Sets the type of statements logged. Setting it to all or mod will cause performance degradation and increase the amount of logs."
                },
                {
                    "ParameterValue": "-1",
                    "ParameterName": "old_snapshot_threshold",
                    "ParameterDescription": "Time before a snapshot is too old to read pages changed after the snapshot was taken."
                },
                {
                    "ParameterValue": "disable",
                    "ParameterName": "sql_firewall.firewall",
                    "ParameterDescription": "The parameter is to detemine running mode of sql_firewall extension."
                },
                {
                    "ParameterValue": "off",
                    "ParameterName": "ssl",
                    "ParameterDescription": "Enables SSL connections."
                },
                {
                    "ParameterValue": "TLSv1",
                    "ParameterName": "ssl_min_protocol_version",
                    "ParameterDescription": "Sets the minimum SSL/TLS protocol version to use"
                },
                {
                    "ParameterValue": "0",
                    "ParameterName": "statement_timeout",
                    "ParameterDescription": "Sets the maximum allowed duration of any statement. A value of 0 turns off the timeout."
                },
            ]
        },
        "EngineVersion": "13.0",
        "Engine": "PostgreSQL"
    },
    {
        "RunningParameters": {
            "DBInstanceParameter": [
                {
                    "ParameterValue": "off",
                    "ParameterName": "log_duration",
                    "ParameterDescription": "Logs the duration of each completed SQL statement."
                },
            ]
        }
    }
];

const createCache = (dbInstances, describeParameters, dbInstancesErr, describeParametersErr) => {
    let instanceId = (dbInstances && dbInstances.length) ? dbInstances[0].DBInstanceId : null;
    return {
        rds: {
            DescribeDBInstances: {
                'cn-hangzhou': {
                    data: dbInstances,
                    err: dbInstancesErr
                },
            },
            DescribeParameters: {
                'cn-hangzhou': {
                    [instanceId]: {
                        data: describeParameters,
                        err: describeParametersErr
                    }
                }
            }
        },
    };
};

describe('rdsLogDuration', function () {
    describe('run', function () {
        it('should FAIL if RDS DB instance does not have log_duration parameter enabled', function (done) {
            const cache = createCache(describeDBInstances, describeParameters[1]);
            rdsLogDuration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('RDS DB instance does not have log_duration parameter enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if RDS DB instance has log_duration parameter enabled', function (done) {
            const cache = createCache(describeDBInstances, describeParameters[0]);
            rdsLogDuration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('RDS DB instance has log_duration parameter enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no RDS DB instances found', function (done) {
            const cache = createCache([]);
            rdsLogDuration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No RDS DB instances found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query RDS DB instances', function (done) {
            const cache = createCache([], null, { err: 'Unable to query RDS DB instances' });
            rdsLogDuration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query RDS DB instances');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query DB parameters', function (done) {
            const cache = createCache([describeDBInstances[0]], {}, null, { err: 'Unable to query DB parameters' });
            rdsLogDuration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query DB parameters');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})