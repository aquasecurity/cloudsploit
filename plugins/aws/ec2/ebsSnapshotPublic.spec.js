var expect = require('chai').expect;
var ebsSnapshotPublic = require('./ebsSnapshotPublic');

const describeSnapshots = [
    {
        "Description": "Created for testing",
        "Encrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/c48d9687-cdd3-4a1f-9d80-f92a7693c5d0",
        "OwnerId": "112233445566",
        "Progress": "100%",
        "SnapshotId": "snap-00317ba0e33942c5a",
        "StartTime": "2020-10-31T11:40:33.066Z",
        "State": "completed",
        "VolumeId": "vol-0065e2a7632d0d083",
        "VolumeSize": 1,
        "Tags": []
    },
    {
        "Description": "Created for testing",
        "Encrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/c48d9687-cdd3-4a1f-9d80-f92a7693c5d0",
        "OwnerId": "112233445566",
        "Progress": "100%",
        "SnapshotId": "snap-03fb4402f29407fa0",
        "StartTime": "2020-10-31T11:40:33.066Z",
        "State": "completed",
        "VolumeId": "vol-0065e2a7632d0d083",
        "VolumeSize": 1,
        "Tags": []
    }
];

const describeSnapshotAttribute = [
    {
        "CreateVolumePermissions": [ { Group: 'all' } ],
        "ProductCodes": [],
        "SnapshotId": "snap-00317ba0e33942c5a"
    },
    {
        "CreateVolumePermissions": [],
        "ProductCodes": [],
        "SnapshotId": "snap-03fb4402f29407fa0"
    }
];

const createCache = (describeSnapshots, describeSnapshotAttribute) => {
    var snapshotId = (describeSnapshots && describeSnapshots.length) ? describeSnapshots[0].SnapshotId : null;
    return {
        ec2: {
            describeSnapshots: {
                'us-east-1': {
                    data: describeSnapshots
                }
            },
            describeSnapshotAttribute: {
                'us-east-1': {
                    [snapshotId]: {
                        data: describeSnapshotAttribute
                    }
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeSnapshots: {
                'us-east-1': {
                    err: {
                        message: 'error describing EC2 snapshots'
                    }
                }
            },
            describeSnapshotAttribute: {
                'us-east-1': {
                    err: {
                        message: 'error describing EC2 snapshot attributes'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeSnapshots: {
                'us-east-1': null
            },
            describeSnapshotAttribute: {
                'us-east-1': null
            }
        }
    };
};

describe('ebsSnapshotPublic', function () {
    describe('run', function () {
        it('should PASS if no public EBS snapshots found', function (done) {
            const cache = createCache([describeSnapshots[1]], describeSnapshotAttribute[1]);
            ebsSnapshotPublic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if EBS snapshot is publicly shared to all AWS accounts', function (done) {
            const cache = createCache([describeSnapshots[0]], describeSnapshotAttribute[0]);
            ebsSnapshotPublic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no EBS volumes found', function (done) {
            const cache = createCache([]);
            ebsSnapshotPublic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should not return any results if describe EC2 snapshots response not found', function (done) {
            const cache = createNullCache();
            ebsSnapshotPublic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable tp describe EC2 snapshots', function (done) {
            const cache = createErrorCache();
            ebsSnapshotPublic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

    });
});