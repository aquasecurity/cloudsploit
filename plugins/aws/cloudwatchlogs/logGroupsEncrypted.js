var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudWatch Log Groups Encrypted',
    category: 'CloudWatchLogs',
    domain: 'Compliance',
    description: 'Ensure that the CloudWatch Log groups are encrypted using desired encryption level.',
    more_info: 'Log group data is always encrypted in CloudWatch Logs. You can optionally use AWS Key Management Service for this encryption. ' +
        'After you associate a customer managed key with a log group, all newly ingested data for the log group is encrypted using this key. ' +
        'This data is stored in encrypted format throughout its retention period. CloudWatch Logs decrypts this data whenever it is requested.',
    recommended_action: 'Ensure CloudWatch Log groups have encryption enabled with desired AWS KMS key',
    link: 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html',
    apis: ['CloudWatchLogs:describeLogGroups', 'KMS:describeKey', 'KMS:listKeys'],
    settings: {
        cloudwatchlog_groups_desired_encryption_level: {
            name: 'CloudWatch Log Groups Target Ecryption Level',
            description: 'In order (lowest to highest) awskms=AWS managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        
        var config = {
            desiredEncryptionLevelString: settings.cloudwatchlog_groups_desired_encryption_level || this.settings.cloudwatchlog_groups_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.cloudwatchlogs, function(region, rcb){
            var describeLogGroups = helpers.addSource(cache, source,
                ['cloudwatchlogs', 'describeLogGroups', region]);

            if (!describeLogGroups) return rcb();

            if (describeLogGroups.err || !describeLogGroups.data) {
                helpers.addResult(results, 3, `Unable to query CloudWatch log groups: ${helpers.addError(describeLogGroups)}`, region);
                return rcb();
            }

            if (!describeLogGroups.data.length) {
                helpers.addResult(results, 0, 'No CloudWatch log groups found', region);
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
                            region, logGroup.kmsKeyId);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                
                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `CloudWatch log group is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `CloudWatch log group is encrypted with ${currentEncryptionLevelString} \
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
