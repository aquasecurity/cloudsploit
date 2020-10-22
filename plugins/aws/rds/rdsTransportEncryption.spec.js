var expect = require('chai').expect;
var rdsTransportEncryption = require('./rdsTransportEncryption.js');

const describeDBInstances = [
    {
        "DBInstanceIdentifier": "database-1",
        "DBInstanceClass": "db.t2.micro",
        "Engine": "sqlserver-ex",
        "DBInstanceStatus": "available",
        "MasterUsername": "admin",
        "Endpoint": {
            "Address": "database-2.csumzsa0neyf.us-east-1.rds.amazonaws.com",
            "Port": 1433,
            "HostedZoneId": "Z2R2ITUGPM61AM"
        },
        "AllocatedStorage": 20,
        "InstanceCreateTime": "2020-09-19T22:40:13.061Z",
        "PreferredBackupWindow": "07:14-07:44",
        "VpcSecurityGroups": [
            {
                "VpcSecurityGroupId": "sg-aa941691",
                "Status": "active"
            }
        ],
        "DBParameterGroups": [
            {
                "DBParameterGroupName": "default.sqlserver-ex-14.0",
                "ParameterApplyStatus": "in-sync"
            }
        ],
        "AvailabilityZone": "us-east-1b",
        "DBInstanceArn": "arn:aws:rds:us-east-1:112233445566:db:database-1"
    },
    {
        "DBInstanceIdentifier": "database-2",
        "DBInstanceClass": "db.t2.micro",
        "Engine": "sqlserver-ex",
        "DBInstanceStatus": "available",
        "MasterUsername": "admin",
        "Endpoint": {
            "Address": "database-2.csumzsa0neyf.us-east-1.rds.amazonaws.com",
            "Port": 1433,
            "HostedZoneId": "Z2R2ITUGPM61AM"
        },
        "AllocatedStorage": 20,
        "InstanceCreateTime": "2020-09-19T22:40:13.061Z",
        "PreferredBackupWindow": "07:14-07:44",
        "VpcSecurityGroups": [
            {
                "VpcSecurityGroupId": "sg-aa941691",
                "Status": "active"
            }
        ],
        "DBParameterGroups": [
            {
                "DBParameterGroupName": "custom-sql-server-group",
                "ParameterApplyStatus": "in-sync"
            }
        ],
        "AvailabilityZone": "us-east-1b",
        "DBInstanceArn": "arn:aws:rds:us-east-1:112233445566:db:database-2"
    },
    {
        "DBInstanceIdentifier": "database-3",
        "DBInstanceClass": "db.t2.micro",
        "Engine": "postgresql",
        "DBInstanceStatus": "available",
        "MasterUsername": "admin",
        "Endpoint": {
            "Address": "database-2.csumzsa0neyf.us-east-1.rds.amazonaws.com",
            "Port": 1433,
            "HostedZoneId": "Z2R2ITUGPM61AM"
        },
        "AllocatedStorage": 20,
        "InstanceCreateTime": "2020-09-19T22:40:13.061Z",
        "PreferredBackupWindow": "07:14-07:44",
        "VpcSecurityGroups": [
            {
                "VpcSecurityGroupId": "sg-aa941691",
                "Status": "active"
            }
        ],
        "DBParameterGroups": [
            {
                "DBParameterGroupName": "custom-sql-server-group",
                "ParameterApplyStatus": "in-sync"
            }
        ],
        "AvailabilityZone": "us-east-1b",
        "DBInstanceArn": "arn:aws:rds:us-east-1:112233445566:db:database-2"
    }
];

const describeDBParameters = [
    {
        "ParameterName": "rds.force_ssl",
        "ParameterValue": "1",
        "Description": "Force SSL connections.",
        "Source": "system",
        "ApplyType": "static",
        "DataType": "boolean",
        "AllowedValues": "0,1",
        "IsModifiable": true,
        "MinimumEngineVersion": "14.00.1000.169.v1",
        "ApplyMethod": "pending-reboot"
    },
    {
        "ParameterName": "rds.force_ssl",
        "ParameterValue": "0",
        "Description": "Force SSL connections.",
        "Source": "system",
        "ApplyType": "static",
        "DataType": "boolean",
        "AllowedValues": "0,1",
        "IsModifiable": true,
        "MinimumEngineVersion": "14.00.1000.169.v1",
        "ApplyMethod": "pending-reboot"
    }
]

const createCache = (dbInstances, dbParameters) => {
    var dbParameterGroupName = (dbInstances[0] && dbInstances[0]) ? dbInstances[0].DBParameterGroups[0].DBParameterGroupName : null;
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    data: dbInstances
                },
            },
            describeDBParameters: {
                'us-east-1': {
                    [dbParameterGroupName]: {
                        data: {
                            Parameters: dbParameters
                        }
                    }
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing DB instances'
                    },
                },
            },
            describeDBParameters: {
                'us-east-1': {
                    err: {
                        message: 'error describing DB parameter groups'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        rds: {
            describeDBParameterGroups: {
                'us-east-1': null,
            },
            describeDBParameters: {
                'us-east-1': null,
            },
        },
    };
};

describe('rdsTransportEncryption', function () {
    describe('run', function () {
        it('should PASS if RDS DB instance has transport encryption enabled', function (done) {
            const cache = createCache([describeDBInstances[0]], [describeDBParameters[0]]);
            rdsTransportEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if RDS DB instance does not have transport encryption enabled', function (done) {
            const cache = createCache([describeDBInstances[1]], [describeDBParameters[1]]);
            rdsTransportEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no RDS DB instances found', function (done) {
            const cache = createCache([]);
            rdsTransportEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no RDS Sql Server instances found', function (done) {
            const cache = createCache([describeDBInstances[2]], [describeDBParameters[1]]);
            rdsTransportEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if no parameters found for RDS parameter group', function (done) {
            const cache = createCache([describeDBInstances[0]], []);
            rdsTransportEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to query for RDS DB instances', function (done) {
            const cache = createErrorCache();
            rdsTransportEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe RDS DB instances response not found', function (done) {
            const cache = createNullCache();
            rdsTransportEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
      