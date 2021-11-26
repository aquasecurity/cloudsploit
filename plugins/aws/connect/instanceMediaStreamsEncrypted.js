var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Connect Instance Media Streams Encrypted',
    category: 'Connect',
    domain: 'Content Delivery',
    description: 'Ensure that Amazon Connect instances have encryption enabled for media streams being saved on Kinesis Video Stream.',
    more_info: 'In Amazon Connect, you can capture customer audio during an interaction with your contact center by sending the audio to a Kinesis video stream. ' +
            'All data put into a Kinesis video stream is encrypted at rest using AWS-managed KMS keys. Use customer-managed keys instead, in order to meet regulatory compliance requirements within your organization.',
    link: 'https://docs.aws.amazon.com/connect/latest/adminguide/enable-live-media-streams.html',
    recommended_action: 'Modify Connect instance data storage configuration and enable encryption for media streams',
    apis: ['Connect:listInstances', 'Connect:listInstanceMediaStreamStorageConfigs', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        connect_media_streams_encryption_level: {
            name: 'Connect Media Streams Target Encryption Level',
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
            desiredEncryptionLevelString: settings.connect_media_streams_encryption_level || this.settings.connect_media_streams_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.connect, function(region, rcb){
            var listInstances = helpers.addSource(cache, source,
                ['connect', 'listInstances', region]);

            if (!listInstances) return rcb();

            if (listInstances.err || !listInstances.data) {
                helpers.addResult(results, 3,
                    `Unable to query Connect instances: ${helpers.addError(listInstances)}`, region);
                return rcb();
            }

            if (!listInstances.data.length) {
                helpers.addResult(results, 0, 'No Connect instances found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let instance of listInstances.data) {
                if (!instance.Arn) continue;

                var resource = instance.Arn;

                var listInstanceMediaStreamStorageConfigs = helpers.addSource(cache, source,
                    ['connect', 'listInstanceMediaStreamStorageConfigs', region, instance.Id]);

                if (!listInstanceMediaStreamStorageConfigs || listInstanceMediaStreamStorageConfigs.err || !listInstanceMediaStreamStorageConfigs.data ||
                    !listInstanceMediaStreamStorageConfigs.data.StorageConfigs) {
                    helpers.addResult(results, 3,
                        `Unable to describe Connect instance media streams storage config: ${helpers.addError(listInstanceMediaStreamStorageConfigs)}`,
                        region, resource);
                    continue;
                }

                if (!listInstanceMediaStreamStorageConfigs.data.StorageConfigs.length) {
                    helpers.addResult(results, 0,
                        'Connect instance does not have any media streams enabled',
                        region, resource);
                    continue;
                }

                let storageConfig = listInstanceMediaStreamStorageConfigs.data.StorageConfigs[0];

                if (storageConfig.KinesisVideoStreamConfig) {
                    if (storageConfig.KinesisVideoStreamConfig.EncryptionConfig &&
                        storageConfig.KinesisVideoStreamConfig.EncryptionConfig.KeyId) {
                        let kmsKeyArn = storageConfig.KinesisVideoStreamConfig.EncryptionConfig.KeyId;
                        let keyId = kmsKeyArn.split('/')[1] ? kmsKeyArn.split('/')[1] : kmsKeyArn;

                        var describeKey = helpers.addSource(cache, source,
                            ['kms', 'describeKey', region, keyId]);  
    
                        if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                            helpers.addResult(results, 3,
                                `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                                region, kmsKeyArn);
                            continue;
                        }
                        currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                    } else {
                        currentEncryptionLevel= 2; //awskms
                    }
                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
                
                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
                        helpers.addResult(results, 0,
                            `Connect instance is using ${currentEncryptionLevelString} for media streams encryption\
                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `Connect instance is using ${currentEncryptionLevelString} for media streams encryption\
                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    }
                   
                } else {
                    helpers.addResult(results, 3,
                        'Unable to find Connect instance media streams Config',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
