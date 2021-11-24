var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AppFlow Flow Encrypted',
    category: 'AppFlow',
    domain: 'Application Integration',
    description: 'Ensure that your Amazon AppFlow flows are encrypted with desired encryption level.',
    more_info: 'Amazon AppFlow encrypts your access tokens, secret keys, and data in transit and data at rest with AWS-manager keys by default. ' +
        'Encrypt them using customer-managed keys in order to gain more granular control over encryption/decryption process.',
    recommended_action: 'Create AppFlow flows with customer-manager keys (CMKs).',
    link: 'https://docs.aws.amazon.com/appflow/latest/userguide/data-protection.html',
    apis: ['Appflow:listFlows', 'Appflow:describeFlow', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        appflow_flow_encryption_level: {
            name: 'AppFlow flow Target Encryption Level',
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
            desiredEncryptionLevelString: settings.appflow_flow_encryption_level || this.settings.appflow_flow_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.appflow, function(region, rcb){
            var listFlows = helpers.addSource(cache, source,
                ['appflow', 'listFlows', region]);

            if (!listFlows) return rcb();

            if (listFlows.err || !listFlows.data) {
                helpers.addResult(results, 3,
                    `Unable to list AppFlow flows: ${helpers.addError(listFlows)}`, region);
                return rcb();
            }

            if (!listFlows.data.length) {
                helpers.addResult(results, 0,
                    'No AppFlow flows found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let flow of listFlows.data) {
                if (!flow.flowName || !flow.flowArn) continue;

                let resource = flow.flowArn;

                let describeFlow = helpers.addSource(cache, source,
                    ['appflow', 'describeFlow', region, flow.flowName]);

                if (!describeFlow || describeFlow.err || !describeFlow.data) {
                    helpers.addResult(results, 3,
                        `Unable to describe flow: ${helpers.addError(describeFlow)}`, region, resource);
                    continue;
                }

                if (describeFlow.data.kmsArn) {
                    var kmsKeyId = describeFlow.data.kmsArn.split('/')[1] ? describeFlow.data.kmsArn.split('/')[1] : describeFlow.data.kmsArn;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, kmsKeyId]);

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, describeFlow.data.kmsArn);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else {
                    currentEncryptionLevel = 2; //awskms
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `AppFlow flow is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `AppFlow flow is encrypted with ${currentEncryptionLevelString} \
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