var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Exported Findings Encrypted',
    category: 'GuardDuty',
    domain: 'Management and Governance',
    description: 'Ensure that GuardDuty Export Findings is encrypted',
    more_info: 'GuardDuty data, such as findings, is encrypted at rest using AWS owned customer master keys (CMK). Additionally, you can use your use key (CMKs) in order to gain more control over data encryption/decryption process.',
    link: 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_exportfindings.html',
    recommended_action: 'Create GuardDuty Export Findings with customer-manager keys (CMKs) present in your account',
    apis: ['GuardDuty:listDetectors', 'GuardDuty:listPublishingDestinations', 'GuardDuty:describePublishingDestination', 'KMS:describeKey', 'KMS:listKeys', 'STS:getCallerIdentity'],
    settings: {
        exported_findings_desired_encryption_level: {
            name: 'GuardDuty Export Findings Desired Encryption Level',
            description: 'In order (lowest to highest) awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var defaultRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);

        var config = {
            desiredEncryptionLevelString: settings.exported_findings_desired_encryption_level || this.settings.exported_findings_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        var listDetectors = helpers.addSource(cache, source,
            ['guardduty', 'listDetectors', region]);

        if (!listDetectors) return callback(null, results, source);

        if (listDetectors.err || !listDetectors.data) {
            helpers.addResult(results, 3,
                'Unable to query for GuardDuty detectors: ' + helpers.addError(listDetectors));
            return callback(null, results, source);
        }

        if (!listDetectors.data.length) {
            helpers.addResult(results, 0, 'No GuardDuty detectors found');
            return callback(null, results, source);
        }

        var listKeys = helpers.addSource(cache, source,
            ['kms', 'listKeys', region]);

        if (!listKeys || listKeys.err || !listKeys.data) {
            helpers.addResult(results, 3,
                `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
            return callback(null, results, source);
        }

        async.each(listDetectors.data, function(detectorId, cb){
            if (!detectorId) return cb();
 
            var listPublishingDestinations = helpers.addSource(cache, source,
                ['guardduty', 'listPublishingDestinations', region, detectorId]);

            if (!listPublishingDestinations || listPublishingDestinations.err || !listPublishingDestinations.data) {
                helpers.addResult(results, 3,
                    'Unable to query for GuardDuty publishing destination lists: ' + detectorId + ': ' + helpers.addError(listPublishingDestinations), region);
                return cb();
            }

            if (!listPublishingDestinations.data.Destinations.length) {
                helpers.addResult(results, 0,
                    'Guardduty findings export is not configured'), region, resource);
                return cb();
            }

            for (let destination of listPublishingDestinations.data.Destinations) {
                var resource = `arn:${awsOrGov}:guardduty:${region}:${accountId}:detector/${detectorId}/publishingDestination/${ destination.DestinationId}`;

                var describePublishingDestination = helpers.addSource(cache, source,
                    ['guardduty', 'describePublishingDestination', region, destination.DestinationId]);
                
                if (!describePublishingDestination ||
                describePublishingDestination.err ||
                !describePublishingDestination.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for GuardDuty describing publishing destination: ' + detectorId + ': ' + helpers.addError(describePublishingDestination), region, resource);
                    return cb();
                }

                if (describePublishingDestination.data.DestinationProperties && 
                describePublishingDestination.data.DestinationProperties.KmsKeyArn) {
                    var KmsKey =  describePublishingDestination.data.DestinationProperties.KmsKeyArn;
                    var keyId = KmsKey.split('/')[1] ? KmsKey.split('/')[1] : KmsKey;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]);  

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, KmsKey);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);

                } else currentEncryptionLevel = 2; //awskms

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `GuardDuty findings export is configured to use ${currentEncryptionLevelString} \
                    which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `GuardDuty Export Findings is encrypted with ${currentEncryptionLevelString} \
                    which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                }
            }
            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};