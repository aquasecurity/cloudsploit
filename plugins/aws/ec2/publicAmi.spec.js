var expect = require('chai').expect;
const publicAmi = require('./publicAmi');

const describeImages = [
    {
        ImageId: 'ami-0b8afcbfa2e909c96',
        OwnerId: '111122223333',
        State: 'available',
        Public: false, 
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: true
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c96',
        OwnerId: '111122223333',
        State: 'available',
        Public: true, 
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: true
            }
        }],
    },
]

const createCache = (images) => {
    return {
        ec2:{
            describeImages: {
                'us-east-1': {
                    data: images
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2:{
            describeImages: {
                'us-east-1': {
                    err: {
                        message: 'error describing images'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeImages: {
                'us-east-1': null,
            },
        },
    };
};


describe('publicAmi', function () {
    describe('run', function () {
        it('should PASS if no public AMIs found', function (done) {
            const cache = createCache([describeImages[0]]);
            publicAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if AMI is public', function (done) {
            const cache = createCache([describeImages[1]]);
            publicAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should PASS if no AMIs found', function (done) {
            const cache = createCache([]);
            publicAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe images', function (done) {
            const cache = createErrorCache();
            publicAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe images response not found', function (done) {
            const cache = createNullCache();
            publicAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
