var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ECR Repository Encrypted',
    category: 'ECR',
    domain: 'Containers',
    description: 'Ensures that the ECR Repository is Encrypted',
    more_info: 'Amazon ECR Repository encrypts your data with AWS-manager sse keys by default.' +
               'Encrypt your files using customer-managed keys in order to gain more granular control over encryption/decryption process.',
    recommended_action: 'Create ECR Repository with customer-manager keys (CMKs).',
    link: 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/Repositories.html',
    apis: ['ECR:describeRepositories', 'KMS:describeKey', 'KMS:listKeys'],
    settings: {
        ecr_repository_desired_encryption_level: {
            name: 'ECR Repository Encryption',
            description: 'In order (lowest to highest) sse=AWS-managed AES256;awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(sse|awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.ecr_repository_desired_encryption_level || this.settings.ecr_repository_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.ecr, function(region, rcb){
            var describeRepositories = helpers.addSource(cache, source,
                ['ecr', 'describeRepositories', region]);
               
            if (!describeRepositories) return rcb();
            
            if (describeRepositories.err || !describeRepositories.data) {
                helpers.addResult(results, 3, `Unable to query ECR Repository: ${helpers.addError(describeRepositories)}`, region);
                return rcb();
            }
            
            if (!describeRepositories.data.length) {
                helpers.addResult(results, 0, 'No ECR Repository  found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let repository of describeRepositories.data) {
                if (!repository.repositoryArn) continue;

                let resource = repository.repositoryArn;

                if ( repository.encryptionConfiguration &&
                    repository.encryptionConfiguration.encryptionType &&
                    repository.encryptionConfiguration.encryptionType.toUpperCase() == 'AES256') {
                    currentEncryptionLevel = 1;
                } else if (repository.encryptionConfiguration && repository.encryptionConfiguration.kmsKey) {
                    let kmsKey = repository.encryptionConfiguration.kmsKey;
                    var keyId = kmsKey.split('/')[1] ? kmsKey.split('/')[1] : kmsKey;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]);  

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, kmsKey);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else {
                    helpers.addResult(results, 2,
                        'ECR Repository does not have encryption enabled',
                        region, resource);
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `ECR repository is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `ECR repository encrypted with ${currentEncryptionLevelString} \
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
