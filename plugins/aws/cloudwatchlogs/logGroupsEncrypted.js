var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudWatch Log Groups Encrypted (CMK)',
    category: 'CloudWatchLogs',
    domain: 'Compliance',
    description: 'Ensures that the CloudWatch Log retention period is set above a specified length of time.',
    more_info: 'Retention settings can be used to specify how long log events are kept in CloudWatch Logs. Expired log events get deleted automatically.',
    recommended_action: 'Ensure CloudWatch logs are retained for at least 90 days.',
    link: 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html',
    apis: ['CloudWatchLogs:describeLogGroups', 'KMS:describeKey', 'KMS:listKeys'],
    settings: {
        cloudwatch_log_groups_encryption: {
            name: 'CloudWatch Log Group Ecryption',
            description: 'If set, CloudWatchLogs log groups should have a customer managed key(CMK) instead of default KMS ',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        
        var config = {
            desiredEncryptionLevelString: settings.cloudwatch_log_groups_encryption || this.settings.cloudwatch_log_groups_encryption.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.cloudwatchlogs, function(region, rcb){
            var describeLogGroups = helpers.addSource(cache, source,
                ['cloudwatchlogs', 'describeLogGroups', region]);

            if (!describeLogGroups) return rcb();

            if (describeLogGroups.err || !describeLogGroups.data) {
                helpers.addResult(results, 3, `Unable to query CloudWatch Logs log groups: ${helpers.addError(describeLogGroups)}`, region);
                return rcb();
            }

            if (!describeLogGroups.data.length) {
                helpers.addResult(results, 0, 'No CloudWatch Logs log groups found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let logGroup of describeLogGroups.data) {
                if (!logGroup.arn) continue;

                let resource = logGroup.arn;

                if (!logGroup.kmsKeyId) {
                    currentEncryptionLevel = 2; //awskms
                } else {
                    var kmsKeyId = logGroup.kmsKeyId.split('/')[1] ? logGroup.kmsKeyId.split('/')[1] : logGroup.kmsKeyId;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, kmsKeyId]);  

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, kmsKeyId);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                }

                
                
                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                
                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `CloudWatch Logs log group is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `CloudWatch Logs log group is encrypted with ${currentEncryptionLevelString} \
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
