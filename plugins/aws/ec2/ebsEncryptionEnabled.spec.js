var expect = require('chai').expect;
const ebsEncryptionEnabled = require('./ebsEncryptionEnabled');

const describeVolumes = [
    {
        "Encrypted": false,
        "VolumeId": "vol-0ebea24b6b5ab89d5",
        "Iops": 100,
        "VolumeType": "gp2",
        "MultiAttachEnabled": false
    },
    {
        
        "Encrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:000011112222:key/mykmskey",
        "VolumeId": "vol-0c3475c8999065481",
        "Iops": 300,
        "VolumeType": "gp2",
        "MultiAttachEnabled": false
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "Origin": "AWS_KMS",
            "KeyManager": "AWS",    
        }
    },
    {
        "KeyMetadata": {   
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
        }
    }
];

const createCache = (volumes, keys) => {
    return {
        ec2: {
            describeVolumes: {
                'us-east-1': {
                    data: volumes
                },
            }
        },
        kms: {
            describeKey: {
                'us-east-1': {
                    'mykmskey': {
                        data: keys
                    }
                }
            }
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeVolumes: {
                'us-east-1': null,
            }
        },
        kms: {
            describeKey: {
                'us-east-1': null,
            },
        },
    };
};

describe('ebsEncryptionEnabled', function () {
    describe('run', function () {
        it('should PASS if EBS volume is encrypted', function (done) {
            const cache = createCache([describeVolumes[1]], describeKey[1]);
            ebsEncryptionEnabled.run(cache, { ebs_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if EBS volume is unencrypted', function (done) {
            const cache = createCache([describeVolumes[0]], describeKey[0]);
            ebsEncryptionEnabled.run(cache, {  ebs_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if No EBS volumes present', function (done) {
            const cache = createCache([],[]);
            ebsEncryptionEnabled.run(cache, {  ebs_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
      
        it('should not return any results if unable to fetch EBS volumes', function (done) {
            const cache = createNullCache();
            ebsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should WARN if EBS volume is not encrypted to target encryption level', function (done) {
            const cache = createCache([describeVolumes[1]], describeKey[0]);
            ebsEncryptionEnabled.run(cache, {  ebs_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

    });
});