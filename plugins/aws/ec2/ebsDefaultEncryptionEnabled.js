var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EBS Encryption Enabled By Default',
    category: 'EC2',
    description: 'Ensure the setting for encryption by default is enabled',
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
        var targetEncryptionLevel = helpers.encryptionLevelMap[settings.ebs_encryption_level || this.settings.ebs_encryption_level.default];

        async.each(regions.ec2, function(region, rcb){
            var getEbsEncryptionByDefault = helpers.addSource(cache, source,
                ['ec2', 'getEbsEncryptionByDefault', region]);

            if (!getEbsEncryptionByDefault) return rcb();

            if (getEbsEncryptionByDefault.err) {
                helpers.addResult(results, 3,
                    'Unable to query for ebs encryption by default: ' + helpers.addError(getEbsEncryptionByDefault), region);
                return rcb();
            }

            if (!getEbsEncryptionByDefault.data) {
                helpers.addResult(results, 2,
                    'EBS default encryption is disabled', region);
                return rcb();
            }

            var getEbsDefaultKmsKeyId = helpers.addSource(cache, source,
                ['ec2', 'getEbsDefaultKmsKeyId', region]);

            if (!getEbsDefaultKmsKeyId || getEbsDefaultKmsKeyId.err || !getEbsDefaultKmsKeyId.data) {
                helpers.addResult(results, 3,
                    'Unable to query for ebs default kms key id: ' + helpers.addError(getEbsDefaultKmsKeyId), region);
                return rcb();
            }

            var kmsKeyId = '';
            var isPredefinedAlias = false;
            if (getEbsDefaultKmsKeyId.data.split('/')[0] === 'alias') {
                var listAliases = helpers.addSource(cache, source, ['kms', 'listAliases', region]);

                if (!listAliases || listAliases.err || !listAliases.data) {
                    helpers.addResult(results, 3, 'Unable to query for list aliases: ' + helpers.addError(listAliases), region);
                    return rcb();
                }

                listAliases.data.forEach(function(alias){
                    if (alias.AliasName === getEbsDefaultKmsKeyId.data) {
                        if (alias.TargetKeyId) {
                            kmsKeyId = alias.TargetKeyId;
                        }
                        else {
                            isPredefinedAlias = true;
                        }
                    }
                });
            } else {
                kmsKeyId = getEbsDefaultKmsKeyId.data.split('/')[1];
            }

            var encryptionLevel;
            if (!isPredefinedAlias) {
                var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, kmsKeyId]);
                
                if (!describeKey || describeKey.err || !describeKey.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for describe key: ' + helpers.addError(describeKey), region);
                    return rcb();
                }

                encryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata);
            } else {
                encryptionLevel = 2; //awskms
            }

            if (encryptionLevel < targetEncryptionLevel) {
                helpers.addResult(results, 2,
                    `EBS default encryption is enabled but current encryption level ${helpers.encryptionLevelMap[encryptionLevel]} is less than the target level ${helpers.encryptionLevelMap[targetEncryptionLevel]}`, region);
            } else {
                helpers.addResult(results, 0,
                    `EBS default encryption is enabled and current encryption level ${helpers.encryptionLevelMap[encryptionLevel]} is greater than or equal to the target level ${helpers.encryptionLevelMap[targetEncryptionLevel]}`, region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
