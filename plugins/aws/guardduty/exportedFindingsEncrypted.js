var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Exported Findings Encrypted',
    category: 'GuardDuty',
    domain: 'Management and Governance',
    description: 'Ensure that GuardDuty findings export is encrypted using desired KMS encryption level.',
    more_info: 'GuardDuty data, such as findings, is encrypted at rest using AWS owned customer master keys (CMK). ' +
        'Additionally, you can use your use key (CMKs) in order to gain more control over data encryption/decryption process.',
    link: 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_exportfindings.html',
    recommended_action: 'Encrypt GuardDuty Export Findings with customer-manager keys (CMKs)',
    apis: ['GuardDuty:listDetectors', 'GuardDuty:listPublishingDestinations', 'GuardDuty:describePublishingDestination', 'KMS:describeKey', 'KMS:listKeys', 'STS:getCallerIdentity'],
    settings: {
        findings_desired_encryption_level: {
            name: 'GuardDuty Findings Target Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.regions(settings);

        var defaultRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);

        var config = {
            desiredEncryptionLevelString: settings.findings_desired_encryption_level || this.settings.findings_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(region.guardduty, function(region, rcb){
            var listDetectors = helpers.addSource(cache, source,
                ['guardduty', 'listDetectors', region]);

            if (!listDetectors) return rcb();

            if (listDetectors.err || !listDetectors.data) {
                helpers.addResult(results, 3,
                    'Unable to query for GuardDuty detectors: ' + helpers.addError(listDetectors), region);
                return rcb();
            }

            if (!listDetectors.data.length) {
                helpers.addResult(results, 0, 'No GuardDuty detectors found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let detectorId of listDetectors.data) {
                if (!detectorId) continue;

                const resource = 'arn:' + awsOrGov + ':guardduty:' + region + ':' + accountId + ':detector/' + detectorId;
                
                var listPublishingDestinations = helpers.addSource(cache, source,
                    ['guardduty', 'listPublishingDestinations', region, detectorId]);
    
                if (!listPublishingDestinations ||
                    listPublishingDestinations.err ||
                    !listPublishingDestinations.data ||
                    !listPublishingDestinations.data.Destinations) {
                    helpers.addResult(results, 3,
                        'Unable to query for GuardDuty publishing destinations: ' + helpers.addError(listPublishingDestinations),
                        region, resource);
                    continue;
                }
    
                if (!listPublishingDestinations.data.Destinations.length) {
                    helpers.addResult(results, 0,
                        'Guardduty findings export is not configured',
                        region, resource);
                    continue;
                }

                for (let destination of listPublishingDestinations.data.Destinations) {
                    let resource = `arn:${awsOrGov}:guardduty:${region}:${accountId}:detector/${detectorId}/publishingDestination/${destination.DestinationId}`;
        
                    var describePublishingDestination = helpers.addSource(cache, source,
                        ['guardduty', 'describePublishingDestination', region, destination.DestinationId]);
                    
                    if (!describePublishingDestination ||
                        describePublishingDestination.err ||
                        !describePublishingDestination.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for GuardDuty publishing destination: ' + helpers.addError(describePublishingDestination),
                            region, resource);
                        continue;
                    }
        
                    if (describePublishingDestination.data.DestinationProperties && 
                        describePublishingDestination.data.DestinationProperties.KmsKeyArn) {
                        var kmsKey =  describePublishingDestination.data.DestinationProperties.KmsKeyArn;
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
        
                    } else  currentEncryptionLevel = 2; //awskms
        
                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
    
                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
                        helpers.addResult(results, 0,
                            `GuardDuty findings export is using ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `GuardDuty findings export is using ${currentEncryptionLevelString} \
                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
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