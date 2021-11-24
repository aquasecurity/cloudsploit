var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'FinSpace Environment Encrypted',
    category: 'FinSpace',
    domain: 'Content Delivery',
    description: 'Ensure that AWS FinSpace Environments are using desired encryption level.',
    more_info: 'Amazon FinSpace is a fully managed data management and analytics service that makes it easy to store, catalog, and prepare financial industry data at scale.' +
               'To encrypt this data, use a KMS key with desired encrypted level to meet regulatory compliance requirements within your organization.',
    recommended_action: 'Create FinSpace Environment with customer-manager keys (CMKs).',
    link: 'https://docs.aws.amazon.com/finspace/latest/userguide/data-encryption.html',
    apis: ['Finspace:listEnvironments', 'KMS:describeKey', 'KMS:listKeys'],
    settings: {
        finspace_environment_encryption: {
            name: 'FinSpace Environment Encryption',
            description: 'In order (lowest to highest) awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.finspace_environment_encryption || this.settings.finspace_environment_encryption.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.ecr, function(region, rcb){
            var listEnvironments = helpers.addSource(cache, source,
                ['finspace', 'listEnvironments', region]);

            if (!listEnvironments) return rcb();

            if (listEnvironments.err || !listEnvironments.data) {
                helpers.addResult(results, 3, `Unable to query FinSpace Environment: ${helpers.addError(listEnvironments)}`, region);
                return rcb();
            }


            if (!listEnvironments.data.length) {
                helpers.addResult(results, 0, 'No FinSpace Environment  found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let environment of listEnvironments.data) {
                if (!environment.environmentArn) continue;
                let resource = environment.environmentArn;

                if (environment.kmsKeyId) {

                    var keyId = environment.kmsKeyId.split('/')[1] ? environment.kmsKeyId.split('/')[1] : environment.kmsKeyId;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]);  

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, environment.kmsKeyId);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else {
                    helpers.addResult(results, 3,
                        `No Default Encryption key found invalid or Unknown Error : ${helpers.addError(describeKey)}`, region);
                    return rcb();
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `FinSpace Environment is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `FinSpace Environment encrypted with ${currentEncryptionLevelString} \
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