var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Connect Wisdom Domain Encrypted',
    category: 'Connect',
    domain: 'Content Delivery',
    description: 'Ensure that Wisdom domains created under Amazon Connect instances are using desired KMS encryption level.',
    more_info: 'All user data stored in Amazon Connect Wisdom is encrypted at rest using encryption keys stored in AWS Key Management Service. Additionally, you can provide customer managed KMS keys in order to gain more control over encryption/decryption processes.',
    recommended_action: 'Ensure that Amazon Connect Wisdom domains have encryption enabled.',
    link: 'https://docs.aws.amazon.com/connect/latest/adminguide/encryption-at-rest.html',
    apis: ['Wisdom:listAssistants', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        wisdom_desired_encryption_level: {
            name: 'Connect Wisdom Domain Desired Encryption Level',
            description: 'In order (lowest to highest) \
                awskms=AWS-managed KMS; \
                awscmk=Customer managed KMS; \
                externalcmk=Customer managed externally sourced KMS; \
                cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.wisdom_desired_encryption_level || this.settings.wisdom_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.wisdom, function(region, rcb){
            var listDomains = helpers.addSource(cache, source,
                ['wisdom', 'listAssistants', region]);

            if (!listDomains) return rcb();

            if (listDomains.err || !listDomains.data) {
                helpers.addResult(results, 3,
                    'Unable to query Connect Wisdom domains: ' + helpers.addError(listDomains), region);
                return rcb();
            }

            if (!listDomains.data.length) {
                helpers.addResult(results, 0, 'No Connect Wisdom domains found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let domain of listDomains.data) {
                let resource = domain.assistantArn;

                if (domain.serverSideEncryptionConfiguration && domain.serverSideEncryptionConfiguration.kmsKeyId) {
                    let encryptionKey = domain.serverSideEncryptionConfiguration.kmsKeyId;
                    var keyId = encryptionKey.split('/')[1] ? encryptionKey.split('/')[1] : encryptionKey;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]);

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, encryptionKey);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else {
                    currentEncryptionLevel = 2; //awskms
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `Wisdom domain is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Wisdom domain is encrypted with ${currentEncryptionLevelString} \
                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
