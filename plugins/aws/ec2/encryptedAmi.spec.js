var expect = require('chai').expect;
const encryptedAmi = require('./encryptedAmi');

const describeImages = [
    {
        ImageId: 'ami-0b8afcbfa2e909c96',
        OwnerId: '111122223333',
        State: 'available',
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
        ImageId: 'ami-0b8afcbfa2e909c01',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c02',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c03',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c04',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c05',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c06',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c07',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c08',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c09',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c10',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c11',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c12',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c13',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c14',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c15',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c16',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c17',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c18',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c19',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c20',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    },
    {
        ImageId: 'ami-0b8afcbfa2e909c21',
        OwnerId: '111122223333',
        State: 'available',
        BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: {
              DeleteOnTermination: true,
              SnapshotId: 'snap-06889b875f1df9e9f',
              VolumeSize: 8,
              VolumeType: 'gp2',
              Encrypted: false
            }
        }],
    }
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


describe('encryptedAmi', function () {
    describe('run', function () {
        it('should PASS if no AMIs with unencrypted volumes found', function (done) {
            const cache = createCache([describeImages[0]]);
            encryptedAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if no AMIs with unencrypted volumes found', function (done) {
            const cache = createCache([describeImages[1]]);
            encryptedAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if more than 20 unencrypted AMI EBS volumes found', function (done) {
            const cache = createCache(describeImages);
            encryptedAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no AMIs found', function (done) {
            const cache = createCache([]);
            encryptedAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe images', function (done) {
            const cache = createErrorCache();
            encryptedAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe images response is not found', function (done) {
            const cache = createNullCache();
            encryptedAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
