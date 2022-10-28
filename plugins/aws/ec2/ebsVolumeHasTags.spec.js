var expect = require('chai').expect;
const ebsVolumeHasTags = require('./ebsVolumeHasTags');

describeVolumes = [
    {
        "Attachments": [],
        "AvailabilityZone": "us-east-1d",
        "CreateTime": "2020-09-01T03:40:13.595Z",
        "Encrypted": false,
        "Size": 8,
        "SnapshotId": "snap-06d919bfeced8496a",
        "State": "available",
        "VolumeId": "vol-0d7619e666a54b52a",
        "Iops": 100,
        "VolumeType": "gp2",
        "MultiAttachEnabled": false,
        'Tags': []
    },
    {
        "Attachments": [],
        "AvailabilityZone": "us-east-1d",
        "CreateTime": "2020-09-01T03:40:13.595Z",
        "Encrypted": false,
        "Size": 8,
        "SnapshotId": "snap-06d919bfeced8496a",
        "State": "available",
        "VolumeId": "vol-0d7619e666a54b52a",
        "Iops": 100,
        "VolumeType": "gp2",
        "MultiAttachEnabled": false,
        'Tags': [ {key : 'value'} ]
    }
]

const createCache = (volumes) => {
    return {
        ec2: {
            describeVolumes: {
                'us-east-1': {
                    data: volumes
                }
            }
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeVolumes: {
                'us-east-1': {
                    err: {
                        message: 'error describing ebs volumes'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeVolumes: {
                'us-east-1': null,
            },
        },
    };
};

describe('ebsVolumeHasTags', function () {
    describe('run', function () {
        it('should PASS if EBS volume has tags', function (done) {
            const cache = createCache([describeVolumes[1]]);
            ebsVolumeHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('EBS volume has tags');
                done();
            });
        });

        it('should FAIL if EBS volume does not have tags', function (done) {
            const cache = createCache([describeVolumes[0]]);
            ebsVolumeHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('EBS volume does not have tags');
                done();
            });
        });

        it('should PASS if no EBS volumes found', function (done) {
            const cache = createCache([]);
            ebsVolumeHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No EBS Volumes found');
                done();
            });
        });

        it('should UNKNOWN if error occurs while describe EBS volume', function (done) {
            const cache = createErrorCache();
            ebsVolumeHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for EBS Volumes');
                done();
            });
        });
    });
});