var async = require('async');
var helpers = require('../../../helpers/aws');

const encryptionLevelMap = {
    none: 0,
    sse: 1,
    awskms: 2,
    awscmk: 3,
    externalcmk: 4,
    cloudhsm: 5,
    0: 'none',
    1: 'sse',
    2: 'awskms',
    3: 'awscmk',
    4: 'externalcmk',
    5: 'cloudhsm',
};

function getEncryptionLevel(kmsKey) {
    if (kmsKey.Origin === 'AWS_KMS') {
        if (kmsKey.KeyManager === 'AWS') {
            return 2;
        } else if (kmsKey.KeyManager === 'CUSTOMER') {
            return 3;
        }
    }
    if (kmsKey.Origin === 'EXTERNAL') {
        return 4;
    }
    if (kmsKey.Origin === 'AWS_CLOUDHSM') {
        return 5;
    }
}

module.exports = {
    title: 'EBS Encryption Enabled',
    category: 'EC2',
    description: 'Ensures EBS volumes are encrypted at rest',
    more_info: 'EBS volumes should have at-rest encryption enabled through AWS using KMS. If the volume is used for a root volume, the instance must be launched from an AMI that has been encrypted as well.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html',
    recommended_action: 'Enable encryption for EBS volumes.',
    apis: ['EC2:describeVolumes', 'KMS:describeKey', 'KMS:listKeys'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
                'EBS is a HIPAA-compliant solution that provides automated encryption ' +
                'of EC2 instance data at rest.',
        pci: 'PCI requires proper encryption of cardholder data at rest. EBS ' +
             'encryption should be enabled for all volumes storing this type ' +
             'of data.'
    },
    settings: {
        ebs_encryption_level: {
            name: 'EBS Minimum Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms',
        },
        ebs_result_limit: {
            name: 'EBS Result Limit',
            description: 'If the number of results is greater than this value, combine them into one result',
            regex: '^[0-9]*$',
            default: '20',
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var targetEncryptionLevel = encryptionLevelMap[settings.ebs_encryption_level || this.settings.ebs_encryption_level.default];
        var ebsResultLimit = parseInt(settings.ebs_result_limit || this.settings.ebs_result_limit.default);

        async.each(regions.ec2, function(region, rcb) {
            var describeVolumes = helpers.addSource(cache, source, ['ec2', 'describeVolumes', region]);

            if (!describeVolumes) return rcb();
            if (describeVolumes.err || !describeVolumes.data) {
                helpers.addResult(results, 3, 'Unable to query for EBS volumes: ' + helpers.addError(describeVolumes), region);
                return rcb();
            }
            if (!describeVolumes.data.length) {
                helpers.addResult(results, 0, 'No EBS volumes present', region);
                return rcb();
            }

            var unencryptedVolumes = [];
            var poorlyEncryptedVolumes = [];
            var kmsErrors = [];

            for (let volume of describeVolumes.data) {
                if (!volume.Encrypted || !volume.KmsKeyId){
                    unencryptedVolumes.push(volume.VolumeId);
                    continue;
                }
                var kmsKeyId = volume.KmsKeyId.split('/')[1];
                var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, kmsKeyId]);
                if (!describeKey || describeKey.err || !describeKey.data) {
                    kmsErrors.push({ kmsKeyId, err: helpers.addError(describeKey) });
                    continue;
                }
                var encryptionLevel = getEncryptionLevel(describeKey.data.KeyMetadata);
                if (encryptionLevel < targetEncryptionLevel) {
                    poorlyEncryptedVolumes.push(volume.VolumeId);
                }
            }

            if (unencryptedVolumes.length) {
                if (unencryptedVolumes.length > ebsResultLimit) {
                    helpers.addResult(results, 2, `More than ${ebsResultLimit} EBS volumes are unencrypted`, region);
                } else {
                    unencryptedVolumes.forEach(volume => helpers.addResult(results, 2, 'EBS volume is unencrypted', region, volume));
                }
            }
            if (poorlyEncryptedVolumes.length) {
                if (poorlyEncryptedVolumes.length > ebsResultLimit) {
                    helpers.addResult(results, 1, `More than ${ebsResultLimit} EBS volumes are not encrypted to ${encryptionLevelMap[targetEncryptionLevel]}`, region);
                } else {
                    poorlyEncryptedVolumes.forEach(volume => helpers.addResult(results, 1, `EBS volume is not encrypted to ${encryptionLevelMap[targetEncryptionLevel]}`, region, volume));
                }
            }
            if (kmsErrors.length) {
                if (kmsErrors.length > ebsResultLimit) {
                    helpers.addResult(results, 3, `More than ${ebsResultLimit} errors describing kms keys happened`, region);
                } else {
                    kmsErrors.forEach(({err, kmsKeyId}) => helpers.addResult(results, 3, `Could not describe KMS key: ${err}`, region, kmsKeyId));
                }
            }

            if (!unencryptedVolumes.length && !poorlyEncryptedVolumes.length && !kmsErrors.length) {
                helpers.addResult(results, 0, `All volumes encrypted to at least ${encryptionLevelMap[targetEncryptionLevel]}`, region);
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
