var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'IoT SiteWise Data Encrypted',
    category: 'IoT SiteWise',
    domain: 'Application Integration',
    description: 'Ensure that AWS IoT SiteWise is using desired encryption level for data at-rest.',
    more_info: 'AWS IoT SiteWise encrypts data such as your asset property values and aggregate values by default.'+
        'It is recommended to use customer managed keys in order to gain more control over data encryption/decryption process.',
    link: 'https://docs.aws.amazon.com/iot-sitewise/latest/userguide/encryption-at-rest.html',
    recommended_action: 'Update IoT SiteWise encryption configuration to use a CMK.',
    apis: ['IoTSiteWise:describeDefaultEncryptionConfiguration', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        iot_sitewise_data_desired_encryption_level: {
            name: 'IoT SiteWise Data Target Encryption Level',
            description: 'In order (lowest to highest)  awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk',
        }
    },
   
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.iot_sitewise_data_desired_encryption_level || this.settings.iot_sitewise_data_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.iotsitewise, function(region, rcb){
            var describeDefaultEncryptionConfiguration = helpers.addSource(cache, source,
                ['iotsitewise', 'describeDefaultEncryptionConfiguration', region]);

            if (!describeDefaultEncryptionConfiguration) return rcb();

            if (describeDefaultEncryptionConfiguration.err || !describeDefaultEncryptionConfiguration.data) {
                helpers.addResult(results, 3, `Unable to query IoT SiteWise encryption configuration: ${helpers.addError(describeDefaultEncryptionConfiguration)}`, region);
                return rcb();
            }
            
            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            if (describeDefaultEncryptionConfiguration.data.encryptionType == 'KMS_BASED_ENCRYPTION' &&
                describeDefaultEncryptionConfiguration.data.kmsKeyArn) {
                let kmsKeyArn = describeDefaultEncryptionConfiguration.data.kmsKeyArn;
                var kmsKeyId = kmsKeyArn.split('/')[1] ? kmsKeyArn.split('/')[1] : kmsKeyArn;

                var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, kmsKeyId]);

                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                    helpers.addResult(results, 3,
                        `Unable to query KMS key: ${helpers.addError(describeKey)}`, region, kmsKeyArn);
                    return rcb();
                }

                currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
            } else currentEncryptionLevel = 2; //awskms
 
            var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

            if (currentEncryptionLevel >= desiredEncryptionLevel) {
                helpers.addResult(results, 0,
                    `IoT SiteWise is configured to use encryption at level ${currentEncryptionLevelString} which is greater than or equal to desired level ${config.desiredEncryptionLevelString}`,
                    region);
            } else {
                helpers.addResult(results, 2,
                    `IoT SiteWise is configured to use encryption at level ${currentEncryptionLevelString} which is less than desired level ${config.desiredEncryptionLevelString}`,
                    region);
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};