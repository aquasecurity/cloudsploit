var expect = require('chai').expect;
const ebsEncryptedSnapshots = require('./ebsEncryptedSnapshots');

const describeSnapshots = [
    {
        "Description": '',
        "Encrypted": true,
        "KmsKeyId": 'arn:aws:kms:us-east-1:111122223333:key/c48d9687-cdd3-4a1f-9d80-f92a7693c5d0',
        "OwnerId": '111122223333',
        "Progress": '100%',
        "SnapshotId": 'snap-0a97ac5b19a598f50',
        "StartTime": "2020-11-09T22:38:48.321Z",
        "State": 'completed',
        "VolumeId": 'vol-0ea73f15efe1c3f67',
        "VolumeSize": 8,
        "Tags": []
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
    {
        "Encrypted": false,
        "OwnerId": '111122223333',
        "SnapshotId": 'snap-0a97ac5b19a598f50'
    },
];


const createCache = (snapshots) => {
    return {
        ec2:{
            describeSnapshots: {
                'us-east-1': {
                    data: snapshots
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2:{
            describeSnapshots: {
                'us-east-1': {
                    err: {
                        message: 'error describing snapshots'
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeSnapshots: {
                'us-east-1': null,
            },
        },
    };
};

describe('ebsEncryptedSnapshots', function () {
    describe('run', function () {
        it('should PASS if no unencrypted snapshots found', function (done) {
            const cache = createCache([describeSnapshots[0]]);
            ebsEncryptedSnapshots.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should FAIL if EBS snapshot is unencrypted', function (done) {
            const cache = createCache([describeSnapshots[1]]);
            ebsEncryptedSnapshots.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
        
        it('should FAIL if more than 20 EBS snapshots are unencrypted', function (done) {
            const cache = createCache(describeSnapshots);
            ebsEncryptedSnapshots.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
        
        it('should PASS if no EBS snapshots present', function (done) {
            const cache = createCache([]);
            ebsEncryptedSnapshots.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should UNKNOWN if unable to describe snapshots', function (done) {
            const cache = createErrorCache();
            ebsEncryptedSnapshots.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        
        it('should not return anything if describe snapshots response not found', function (done) {
            const cache = createNullCache();
            ebsEncryptedSnapshots.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });


    });
});
