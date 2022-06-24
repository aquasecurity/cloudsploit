var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SES Email Messages Encrypted',
    category: 'SES',
    domain: 'Content Delivery',
    description: 'Ensure that Amazon SES email messages are encrypted before delivering them to specified buckets.',
    more_info: 'Amazon SES email messages should be encrypted in case they are being delivered to S3 bucket to meet regulatory compliance requirements within your organization.',
    recommended_action: 'Enable encryption for SES email messages if they are being delivered to S3 in active rule-set .',
    link: 'https://docs.aws.amazon.com/kms/latest/developerguide/services-ses.html',
    apis: ['SES:describeActiveReceiptRuleSet', 'KMS:listKeys', 'KMS:describeKey', 'STS:getCallerIdentity'],
    settings: {
        ses_email_desired_encryption_level: {
            name: 'SES Email Desired Encryption Level',
            description: 'Desired encryption level for email messages to encrypt them before they get saves on S3',
            regex: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.ses_email_desired_encryption_level || this.settings.ses_email_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ses, function(region, rcb){
            var describeActiveReceiptRuleSet = helpers.addSource(cache, source,
                ['ses', 'describeActiveReceiptRuleSet', region]);

            if (!describeActiveReceiptRuleSet) return rcb();
            
            if (describeActiveReceiptRuleSet.err && describeActiveReceiptRuleSet.err.message &&
                describeActiveReceiptRuleSet.err.message.includes('Unavailable Operation')) return rcb();

            if (describeActiveReceiptRuleSet.err || !describeActiveReceiptRuleSet.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SES active rule set: ' + helpers.addError(describeActiveReceiptRuleSet), region);
                return rcb();
            }

            if (!describeActiveReceiptRuleSet.data.Metadata) {
                helpers.addResult(results, 0, 'No SES active rule set found', region);
                return rcb();
            }

            let ruleSetName = describeActiveReceiptRuleSet.data.Metadata.Name;
            let resource = `arn:${awsOrGov}:ses:${region}:${accountId}:receipt-rule-set/${ruleSetName}`;

            if (!describeActiveReceiptRuleSet.data.Rules || !describeActiveReceiptRuleSet.data.Rules.length) {
                helpers.addResult(results, 0, 'SES active rule set does not have any rules', region, resource);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let rule of describeActiveReceiptRuleSet.data.Rules) {
                if (!rule.Name) continue;

                let resource = `arn:${awsOrGov}:ses:${region}:${accountId}:receipt-rule-set/${ruleSetName}:receipt-rule/${rule.Name}`;

                if (!rule.Enabled) {
                    helpers.addResult(results, 0, 'SES active rule set rule is not enabled', region, resource);
                    continue;
                }

                let s3Action = rule.Actions.find(action => action.S3Action);
                if (!s3Action) helpers.addResult(results, 0, 'SES active rule set rule does not have action to deliver to S3', region, resource);
                else {
                    if (s3Action.S3Action.KmsKeyArn) {
                        if (s3Action.S3Action.KmsKeyArn.includes('alias/aws/ses')) currentEncryptionLevel = 2;
                        else {
                            let kmsKeyId = s3Action.S3Action.KmsKeyArn.split('/')[1] ? s3Action.S3Action.KmsKeyArn.split('/')[1] : s3Action.S3Action.KmsKeyArn;
    
                            var describeKey = helpers.addSource(cache, source,
                                ['kms', 'describeKey', region, kmsKeyId]);
        
                            if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                                helpers.addResult(results, 3,
                                    `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                                    region, s3Action.KmsKeyArn);
                                return rcb();
                            }

                            currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                        }

                        let currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
    
                        if (currentEncryptionLevel >= desiredEncryptionLevel) {
                            helpers.addResult(results, 0,
                                `SES active rule set rule is using ${currentEncryptionLevelString} \
                                which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                                region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                `SES active rule set rule is using ${currentEncryptionLevelString} \
                                which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                                region, resource);
                        }
                    } else {
                        helpers.addResult(results, 2,
                            'SES active rule set rule does not have encryption enabled for email messages being delivered to S3',
                            region, resource);
                    }
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};