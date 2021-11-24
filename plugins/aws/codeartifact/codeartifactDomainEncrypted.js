var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CodeArtifact Domain Encrypted',
    category: 'CodeArtifact',
    domain: 'Application Integration',
    description: 'Ensures that AWS CodeArtifact domains have encryption enabled with desired encryption level.',
    more_info: 'CodeArtifact domains make it easier to manage multiple repositories across an organization. By default, domain assets are encrypted with AWS-managed KMS key. ' +
        'Encrypt them using customer-managed keys in order to gain more granular control over encryption/decryption process',
    recommended_action: 'Encrypt CodeArtifact domains with desired encryption level',
    link: 'https://docs.aws.amazon.com/codeartifact/latest/ug/domain-create.html',
    apis: ['CodeArtifact:listDomains', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        codeartifact_domain_encryption_level: {
            name: 'CodeArtifact Domain Target Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.codeartifact_domain_encryption_level || this.settings.codeartifact_domain_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.codeartifact, function(region, rcb){
            var listDomains = helpers.addSource(cache, source,
                ['codeartifact', 'listDomains', region]);

            if (!listDomains) return rcb();

            if (listDomains.err || !listDomains.data) {
                helpers.addResult(results, 3,
                    `Unable to list CodeArtifact domains: ${helpers.addError(listDomains)}`, region);
                return rcb();
            }

            if (!listDomains.data.length) {
                helpers.addResult(results, 0,
                    'No CodeArtifact domains found', region);
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
                if (!domain.arn) continue;

                let resource = domain.arn;
                if (domain.encryptionKey) {
                    var kmsKeyId = domain.encryptionKey.split('/')[1] ? domain.encryptionKey.split('/')[1] : domain.encryptionKey;
    
                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, kmsKeyId]);
    
                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, domain.encryptionKey);
                        continue;
                    }
    
                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
    
                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
                        helpers.addResult(results, 0,
                            `CodeArtifact domain is encrypted with ${currentEncryptionLevelString} \
                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `CodeArtifact domain is encrypted with ${currentEncryptionLevelString} \
                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'CodeArtifact domain does not have encryption enabled for assets',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};