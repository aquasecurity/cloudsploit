var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Environment Template Encrypted',
    category: 'Proton',
    domain: 'Databases',
    description: 'Ensure that AWS Proton environment template is encrypted with desired level.',
    more_info: 'AWS Proton encrypts sensitive data in your template bundles at rest in the S3 bucket where you store your template bundles using AWS-managed keys. Use customer-managed keys (CMKs) in order to meet regulatory compliance requirements within your organization.',
    recommended_action: 'Create Proton environment template with customer-manager keys (CMKs)',
    link: 'https://docs.aws.amazon.com/proton/latest/adminguide/data-protection.html',
    apis: ['Proton:listEnvironmentTemplates','Proton:getEnvironmentTemplate', 'KMS:describeKey', 'KMS:listKeys'],
    settings: {
        proton_environmenttemplate_desired_encryption_level: {
            name: 'Environment Template Desired Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.proton_environmenttemplate_desired_encryption_level || this.settings.proton_environmenttemplate_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.proton, function(region, rcb){        
            var listEnvironmentTemplates = helpers.addSource(cache, source,
                ['proton', 'listEnvironmentTemplates', region]);

            if (!listEnvironmentTemplates) return rcb();

            if (listEnvironmentTemplates.err || !listEnvironmentTemplates.data) {
                helpers.addResult(results, 3,
                    'Unable to query Environment Template: ' + helpers.addError(listEnvironmentTemplates), region);
                return rcb();
            }

            if (!listEnvironmentTemplates.data.length) {
                helpers.addResult(results, 0, 'No Environment Template found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }
         
            for (let template of listEnvironmentTemplates.data) {
                if (!template.arn) continue;

                let resource = template.arn;
                
                var getEnvironmentTemplate = helpers.addSource(cache, source,
                    ['proton', 'getEnvironmentTemplate', region, template.name]);  
                    
                if (!getEnvironmentTemplate || getEnvironmentTemplate.err || !getEnvironmentTemplate.data ||
                    !getEnvironmentTemplate.data.environmentTemplate) {
                    helpers.addResult(results, 3,
                        `Unable to get Environment Template description: ${helpers.addError(getEnvironmentTemplate)}`,
                        region, resource);
                    continue;
                } 

                if (getEnvironmentTemplate.data.environmentTemplate.encryptionKey) {
                    var encryptionKey = getEnvironmentTemplate.data.environmentTemplate.encryptionKey;
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
                        `Proton environment template is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Proton environment template is encrypted with ${currentEncryptionLevelString} \
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
