var expect = require('chai').expect;
const ebsSnapShotHasTags = require('./ebsSnapshotHasTags');

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
        "Tags": [{'key': 'value'}]
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

describe('ebsSnapShotHasTags', function () {
    describe('run', function () {
        it('should PASS if EBS snapshot has Tags', function (done) {
            const cache = createCache([describeSnapshots[1]]);
            ebsSnapShotHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('EBS Snapshot has tags');
                done();
            });
        });
        
        it('should FAIL if EBS snapshot does not have tags', function (done) {
            const cache = createCache([describeSnapshots[0]]);
            ebsSnapShotHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('EBS Snapshot does not have tags');
                done();
            });
        });
        
        it('should PASS if no EBS snapshots present', function (done) {
            const cache = createCache([]);
            ebsSnapShotHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No EBS snapshots found');
                done();
            });
        });
        
        it('should UNKNOWN if unable to describe snapshots', function (done) {
            const cache = createErrorCache();
            ebsSnapShotHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for EBS Snapshots');
                done();
            });
        });
    });
});
