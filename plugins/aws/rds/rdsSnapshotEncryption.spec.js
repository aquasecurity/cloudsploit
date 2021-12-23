var expect = require('chai').expect;
var rdsSnapshotEncryption = require('./rdsSnapshotEncryption');

const describeDBSnapshots = [
    {
        "DBSnapshotIdentifier": "rds:database-1-2021-12-12-15-38",
        "DBInstanceIdentifier": "database-1",
        "SnapshotCreateTime": "2021-12-12T15:39:59.704000+00:00",
        "Engine": "mysql",
        "AllocatedStorage": 20,
        "Status": "available",
        "Port": 3306,
        "AvailabilityZone": "us-east-1b",
        "VpcId": "vpc-0f4f4575a74fac014",
        "InstanceCreateTime": "2021-12-12T15:38:41.792000+00:00",
        "MasterUsername": "admin",
        "EngineVersion": "8.0.23",
        "LicenseModel": "general-public-license",
        "SnapshotType": "automated",
        "OptionGroupName": "default:mysql-8-0",
        "PercentProgress": 100,
        "StorageType": "gp2",
        "Encrypted": true,
        "DBSnapshotArn": "arn:aws:rds:us-east-1:112233445566:snapshot:rds:database-1-2021-12-12-15-38",
        "IAMDatabaseAuthenticationEnabled": false,
        "ProcessorFeatures": [],
        "DbiResourceId": "db-SADO63QHGOLHYRTFW57ESZV3YY",
        "TagList": [],
        "OriginalSnapshotCreateTime": "2021-12-12T15:39:59.704000+00:00",
    },
    {
        "DBSnapshotIdentifier": "rds:database-1-2021-12-12-15-38",
        "DBInstanceIdentifier": "database-1",
        "SnapshotCreateTime": "2021-12-12T15:39:59.704000+00:00",
        "Engine": "mysql",
        "AllocatedStorage": 20,
        "Status": "available",
        "Port": 3306,
        "AvailabilityZone": "us-east-1b",
        "VpcId": "vpc-0f4f4575a74fac014",
        "InstanceCreateTime": "2021-12-12T15:38:41.792000+00:00",
        "MasterUsername": "admin",
        "EngineVersion": "8.0.23",
        "LicenseModel": "general-public-license",
        "SnapshotType": "automated",
        "OptionGroupName": "default:mysql-8-0",
        "PercentProgress": 100,
        "StorageType": "gp2",
        "Encrypted": false,
        "DBSnapshotArn": "arn:aws:rds:us-east-1:112233445566:snapshot:rds:database-1-2021-12-12-15-38",
        "IAMDatabaseAuthenticationEnabled": false,
        "ProcessorFeatures": [],
        "DbiResourceId": "db-SADO63QHGOLHYRTFW57ESZV3YY",
        "TagList": [],
        "OriginalSnapshotCreateTime": "2021-12-12T15:39:59.704000+00:00"
    }
];

const createCache = (dbSnapshots) => {
    return {
        rds: {
            describeDBSnapshots: {
                'us-east-1': {
                    err: null,
                    data: dbSnapshots
                },
            },
        }
    };
};

const createErrorCache = () => {
    return {
        rds: {
            describeDBSnapshots: {
                'us-east-1': {
                    err: {
                        message: 'error while describing RDS snapshots'
                    },
                },
            },
        }
    };
};

const createNullCache = () => {
    return {
        rds: {
            describeDBSnapshots: {
                'us-east-1': null,
            },
        }
    };
};

describe('rdsSnapshotEncryption', function () {
    describe('run', function () {
        it('should PASS if no RDS instance is found', function (done) {
            const cache = createCache([]);
            rdsSnapshotEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).includes('No RDS snapshots found');
                done();
            });
        });

        it('should PASS if RDS snapshot encryption is enabled', function (done) {
            const cache = createCache([describeDBSnapshots[0]]);
            rdsSnapshotEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).includes('Snapshot encryption is enabled via KMS key');
                done();
            });
        });

        it('should FAIL if RDS snapshot encryption is not enabled', function (done) {
            const cache = createCache([describeDBSnapshots[1]]);
            rdsSnapshotEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).includes('Snapshot encryption not enabled');
                done();
            });
        });

        it('should UNKNOWN if error while describing RDS DB snapshots', function (done) {
            const cache = createErrorCache();
            rdsSnapshotEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if unable to describe RDS DB snapshots', function (done) {
            const cache = createNullCache();
            rdsSnapshotEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
