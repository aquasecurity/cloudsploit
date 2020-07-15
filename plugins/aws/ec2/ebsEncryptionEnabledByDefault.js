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
    title: 'EBS Encryption Enabled By Default',
    category: 'EC2',
    description: 'Ensure the setting for Encryption by default is enabled',
    more_info: 'An AWS account may be configured such that, for a particular region(s), it will be mandatory that new EBS volumes and snapshot copies are encrypted.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default',
    recommended_action: 'Enable EBS Encryption by Default',
    apis: ['EC2:getEbsEncryptionByDefault', 'EC2:getEbsDefaultKmsKeyId', 'KMS:describeKey', 'KMS:listKeys', 'KMS:listAliases'],
    settings: {
        ebs_encryption_level: {
            name: 'EBS Minimum Encryption Level',
            description: 'In order (lowest to highest) none=no encryption; awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(none|awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms',
        },
    },


    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var targetEncryptionLevel = encryptionLevelMap[settings.ebs_encryption_level || this.settings.ebs_encryption_level.default];

        async.each(regions.ec2, function(region, rcb){
            var getEbsEncryptionByDefault = helpers.addSource(cache, source,
                ['ec2', 'getEbsEncryptionByDefault', region]);
            var getEbsDefaultKmsKeyId = helpers.addSource(cache, source,
                ['ec2', 'getEbsDefaultKmsKeyId', region]);

            if (!getEbsEncryptionByDefault) return rcb();
            if (!getEbsDefaultKmsKeyId) return rcb();

            if (!getEbsEncryptionByDefault.data && targetEncryptionLevel !== 0) {
                helpers.addResult(results, 2,
                    'encryption by default is disabled, and the settings indicate that "none" is not the desired encryption level. enabling of "EBS encryption by default" is required', region);
                return rcb();
            }
            var kmsKeyId = ""
            if (getEbsDefaultKmsKeyId.data.split('/')[0] === 'alias') {
                var listAliases = helpers.addSource(cache, source,
                ['kms', 'listAliases', region]);
                listAliases.data.forEach(function(alias){
                    if (alias.AliasName == getEbsDefaultKmsKeyId.data) {
                        kmsKeyId = alias.TargetKeyId;
                    }
                });
            } else {
                kmsKeyId = getEbsDefaultKmsKeyId.data.split('/')[1];
            }
            var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, kmsKeyId]);
            if (!describeKey) return rcb();
            var encryptionLevel = getEncryptionLevel(describeKey.data.KeyMetadata);

            if (encryptionLevel < targetEncryptionLevel) {
                helpers.addResult(results, 2,
                    encryptionLevelMap[encryptionLevel].concat(' is the level of encryption, which is less than the target level, ', encryptionLevelMap[targetEncryptionLevel], ' raising level of encryption is required'), region);
                return rcb();
            } else {
                helpers.addResult(results, 0,
                    encryptionLevelMap[encryptionLevel].concat(' is the level of encryption, which is greater than or equal to the target level, ', encryptionLevelMap[targetEncryptionLevel]), region);
                return rcb();
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
