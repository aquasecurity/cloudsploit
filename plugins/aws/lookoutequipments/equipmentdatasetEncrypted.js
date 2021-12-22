var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'LookoutEquipment Dataset Encrypted',
    category: 'LookoutEquipment',
    domain: 'Content Delivery',
    description: 'Ensure that Amazon LookoutEquipment Dataset is encrypted using desired KMS encryption level',
    more_info: 'Amazon Lookout for Equipment encrypts your data at rest with your choice of an encryption key.If you dont specify an encryption key, your data is encrypted with AWS owned key by default.' +
        'So by using customer-managed keys instead you will gain more granular control over encryption/decryption process.',
    recommended_action: 'Create Amazon LookoutEquipment Dataset with customer-manager keys (CMKs)',
    link: 'https://docs.aws.amazon.com/lookout-for-equipment/latest/ug/encryption-at-rest.html',
    apis: ['LookoutEquipment:listDatasets','LookoutEquipment:describeDataset', 'KMS:describeKey', 'KMS:listKeys'],
    settings: {
        lookoutequipment_dataset_desired_encryption_level: {
            name: 'LookoutEquipment Dataset Desired Encryption Level',
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
            desiredEncryptionLevelString: settings.lookoutequipment_dataset_desired_encryption_level || this.settings.lookoutequipment_dataset_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.lookoutequipment, function(region, rcb){        
            var listDatasets = helpers.addSource(cache, source,
                ['lookoutequipment', 'listDatasets', region]);

            if (!listDatasets) return rcb();

            if (listDatasets.err || !listDatasets.data) {
                helpers.addResult(results, 3,
                    'Unable to query LookoutEquipment Dataset: ' + helpers.addError(listDatasets), region);
                return rcb();
            }

            if (!listDatasets.data.length) {
                helpers.addResult(results, 0, 'No LookoutEquipment Datasets found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let dataset of listDatasets.data) {
                if (!dataset.DatasetArn) continue;

                let resource = dataset.DatasetArn;

                var describeDataset = helpers.addSource(cache, source,
                    ['lookoutequipment', 'describeDataset', region, dataset.DatasetName]);


                if (!describeDataset || describeDataset.err || !describeDataset.data) {
                    helpers.addResult(results, 3,
                        `Unable to get LookoutEquipment Dataset: ${helpers.addError(describeDataset)}`,
                        region, resource);
                    continue;
                } 

                if (describeDataset.data.ServerSideKmsKeyId) {
                    var KmsKey = describeDataset.data.ServerSideKmsKeyId;
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
                } else {
                    currentEncryptionLevel = 2; //awskms
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `LookoutEquipment Datasets is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `LookoutEquipment Datasets is encrypted with ${currentEncryptionLevelString} \
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