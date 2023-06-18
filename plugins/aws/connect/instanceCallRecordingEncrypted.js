var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Connect Instance Call Recording Encrypted',
    category: 'Connect',
    domain: 'Content Delivery',
    description: 'Ensure that Amazon Connect instances have encryption enabled for call recordgins being saved on S3.',
    more_info: 'You can configure Amazon Connect instance to save recordings for incoming call to be saved on S3. When you save ' +
        'such data on S3, enable encryption for the data and use a KMS key with desired encrypted level to meet regulatory compliance requirements within your organization.',
    link: 'https://docs.aws.amazon.com/connect/latest/adminguide/encryption-at-rest.html',
    recommended_action: 'Modify Connect instance data storage configuration and enable encryption for call recordings',
    apis: ['Connect:listInstances', 'Connect:listInstanceCallRecordingStorageConfigs', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        connect_call_recording_encryption_level: {
            name: 'Connect Call Resording Encryption Level',
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
            desiredEncryptionLevelString: settings.connect_call_recording_encryption_level || this.settings.connect_call_recording_encryption_level.default
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

                var listInstanceCallRecordingStorageConfigs = helpers.addSource(cache, source,
                    ['connect', 'listInstanceCallRecordingStorageConfigs', region, instance.Id]);

                if (!listInstanceCallRecordingStorageConfigs || listInstanceCallRecordingStorageConfigs.err || !listInstanceCallRecordingStorageConfigs.data ||
                    !listInstanceCallRecordingStorageConfigs.data.StorageConfigs) {
                    helpers.addResult(results, 3,
                        `Unable to describe Connect instance call recording storage config: ${helpers.addError(listInstanceCallRecordingStorageConfigs)}`,
                        region, resource);
                    continue;
                }

                if (!listInstanceCallRecordingStorageConfigs.data.StorageConfigs.length) {
                    helpers.addResult(results, 0,
                        'Connect instance does not have any storage config for call recordings',
                        region, resource);
                    continue;
                }

                let storageConfig = listInstanceCallRecordingStorageConfigs.data.StorageConfigs[0];

                if (storageConfig.S3Config) {
                    if (storageConfig.S3Config.EncryptionConfig &&
                        storageConfig.S3Config.EncryptionConfig.KeyId) {
                        let kmsKeyArn = storageConfig.S3Config.EncryptionConfig.KeyId;
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

                        var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                        if (currentEncryptionLevel >= desiredEncryptionLevel) {
                            helpers.addResult(results, 0,
                                `Connect instance is using ${currentEncryptionLevelString} for call recordings encryption\
                                which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                                region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                `Connect instance is using ${currentEncryptionLevelString} for call recordings encryption\
                                which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                                region, resource);
                        }
                    } else {
                        helpers.addResult(results, 2,
                            'Connect instance does not have encryption enabled for call recordings',
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 3,
                        'Unable to find Connect instance call recording S3 config',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
