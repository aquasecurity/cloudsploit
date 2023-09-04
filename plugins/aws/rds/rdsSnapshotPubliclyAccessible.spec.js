var expect = require('chai').expect;
const rdsSnapshotPubliclyAccessible = require('./rdsSnapshotPubliclyAccessible');

const describeDBSnapshots = [
    {
        "DBSnapshotIdentifier": "database-1-final-snapshot",
        "DBInstanceIdentifier": "database-1",
        "SnapshotCreateTime": "2022-01-24T15:41:26.234Z",
        "Engine": "mariadb",
        "AllocatedStorage": 20,
        "Status": "available",
        "Port": 3306,
        "AvailabilityZone": "us-east-1a",
        "VpcId": "vpc-0f4f4575a74fac014",
        "InstanceCreateTime": "2022-01-24T15:27:38.423Z",
        "MasterUsername": "admin",
        "EngineVersion": "10.5.13",
        "LicenseModel": "general-public-license",
        "SnapshotType": "manual",
        "OptionGroupName": "default:mariadb-10-5",
        "PercentProgress": 100,
        "StorageType": "gp2",
        "Encrypted": false,
        "DBSnapshotArn": "arn:aws:rds:us-east-1:000011112222:snapshot:database-1-final-snapshot",
        "IAMDatabaseAuthenticationEnabled": false,
        "ProcessorFeatures": [],
        "DbiResourceId": "db-AVTEMNYVJCF3INR3EROOHGZXQQ",
        "TagList": [],
        "OriginalSnapshotCreateTime": "2022-01-24T15:41:26.234Z",
        "SnapshotTarget": "region"
    }
];

const describeDBSnapshotAttributes = [
    {
        "ResponseMetadata": {
          "RequestId": "ef458f54-cf41-4d69-b4aa-014b141138c6"
        },
        "DBSnapshotAttributesResult": {
          "DBSnapshotIdentifier": "database-1-final-snapshot",
          "DBSnapshotAttributes": [
            {
              "AttributeName": "restore",
              "AttributeValues": []
            }
          ]
        }
    },
    {
        "ResponseMetadata": {
          "RequestId": "ef458f54-cf41-4d69-b4aa-014b141138c6"
        },
        "DBSnapshotAttributesResult": {
          "DBSnapshotIdentifier": "database-1-final-snapshot",
          "DBSnapshotAttributes": [
            {
              "AttributeName": "restore",
              "AttributeValues": ["all"]
            }
          ]
        }
      }
];

const createCache = (snapshot, attribute) => {
    let snapshotIdentifier = snapshot && snapshot.length ? snapshot[0].DBSnapshotIdentifier : null
    return {
        rds:{
            describeDBSnapshots: {
                'us-east-1': {
                    data: snapshot
                },
            },
            describeDBSnapshotAttributes: {
                'us-east-1': {
                    [snapshotIdentifier]: {
                        data: attribute
                    },
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        rds: {
            describeDBSnapshots: {
                'us-east-1': {
                    err: {
                        message: 'error describing snapshots'
                    },
                },
            },
            describeDBSnapshotAttributes: {
                'us-east-1': {
                    err: {
                        message: 'error describing snapshot attributes'
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
            describeDBSnapshotAttributes: {
                'us-east-1': null,
            },
        },
    };
};

describe('rdsSnapshotPubliclyAccessible', function () {
    describe('run', function () {
        it('should PASS if RDS nnapshot is not publicly accessible', function (done) {
            const cache = createCache([describeDBSnapshots[0]], describeDBSnapshotAttributes[0]);
            rdsSnapshotPubliclyAccessible.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('is not publicly exposed');
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should FAIL if RDS nnapshot is publicly accessible', function (done) {
            const cache = createCache([describeDBSnapshots[0]], describeDBSnapshotAttributes[1]);
            rdsSnapshotPubliclyAccessible.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('is publicly exposed');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no RDS nnapshots found', function (done) {
            const cache = createCache([]);
            rdsSnapshotPubliclyAccessible.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('No RDS snapshots');
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should UNKNOWN if error while describing Snapshot attributes', function (done) {
            const cache = createErrorCache();
            rdsSnapshotPubliclyAccessible.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        
        it('should not return anything if unable to describe Snapshot attributes', function (done) {
            const cache = createNullCache();
            rdsSnapshotPubliclyAccessible.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
        
        
    });
});
