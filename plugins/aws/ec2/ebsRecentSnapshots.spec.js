let expect = require('chai').expect;
let ebsRecentSnapshots = require('./ebsRecentSnapshots');

var snapshotPass = new Date();
snapshotPass.setDate(snapshotPass.getDate() - 1);

var snapshotFail = new Date();
snapshotFail.setDate(snapshotFail.getDate() - 10);

const describeSnapshots = [
        {
           "Description": "",
           "Encrypted": false,
           "OwnerId": "193063503752",
           "Progress": "100%",
           "SnapshotId": "snap-06c4f7f6004cecfe5",
           "StartTime": snapshotPass,
           "State": "completed",
           "VolumeId": "vol-02c402f5a6a02c6e7",
           "VolumeSize": 8,
            "Tags": [],

          },

    {
        "Description": "Created for testing",
        "Encrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/c48d9687-cdd3-4a1f-9d80-f92a7693c5d0",
        "OwnerId": "112233445566",
        "Progress": "100%",
        "SnapshotId": "snap-023f96b23f5b82f59",
        "StartTime": snapshotFail,
        "State": "completed",
        "VolumeId": "vol-0025f6823d19c56d9",
        "VolumeSize": 1,
        "Tags": []
    },
    {

        "Description": "Created for testing",
        "Encrypted": false,
        "OwnerId": "112233445566",
        "Progress": "100%",
        "SnapshotId": "snap-03fb4402f29407fa0",
        "StartTime": "2020-10-31T11:40:33.066Z",
        "State": "completed",
        "VolumeId": "vol-02c402f5a6a02c6e7",
        "VolumeSize": 1,
        "Tags": []
    }
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
                    }
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeSnapshots: {
                'us-east-1': null
            }
        },
    };
};

describe('ebsRecentSnapshots', function () {
    describe('run', function () {
        it('should PASS if EBS volume has snapshot within 7 days', function (done) {
            const cache = createCache([describeSnapshots[0]]);
            ebsRecentSnapshots.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('EBS volume has a recent snapshot');
                done();
            });
        });
        it('should FAIL if EBS volume have not snapshot within 7 days', function (done) {
            const cache = createCache([describeSnapshots[1]]);
            ebsRecentSnapshots.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('EBS volume does not have a recent snapshot');
                done();
            });
        });
        it('should UNKNOWN if error occurs while describe EBS snapshots or EBS volumes', function (done) {
            const cache = createErrorCache();
            ebsRecentSnapshots.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for EBS Snapshots: ');
                done();
            });
        });
        it('should PASS if No EBS snapshots present', function (done) {
            const cache = createCache([]);
            ebsRecentSnapshots.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No EBS snapshots present');
                done();
            });
        });
        it('should not return any results if unable to fetch EBS snapshots or EBS volumes', function (done) {
            const cache = createNullCache();
            ebsRecentSnapshots.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});