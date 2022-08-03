var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MQ Broker Encrypted',
    category: 'MQ',
    domain: 'Application Integration',
    description: 'Ensure that Amazon MQ brokers have data ecrypted at-rest feature enabled.',
    more_info: 'Amazon MQ encryption at rest provides enhanced security by encrypting your data using encryption keys stored in the AWS Key Management Service (KMS).',
    recommended_action: 'Enabled data at-rest encryption feature for MQ brokers',
    link: 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/data-protection.html#data-protection-encryption-at-rest',
    apis: ['MQ:listBrokers', 'MQ:describeBroker', 'KMS:describeKey', 'KMS:listKeys'],
    settings: {
        mq_broker_desired_encryption_level: {
            name: 'MQ Broker Target Encryption Level',
            description: 'In order (lowest to highest) sse=AWS-owned CMK awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(sse|awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.mq_broker_desired_encryption_level || this.settings.mq_broker_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.mq, function(region, rcb){        
            var listBrokers = helpers.addSource(cache, source,
                ['mq', 'listBrokers', region]);
                    
            if (!listBrokers) return rcb();

            if (listBrokers.err || !listBrokers.data) {
                helpers.addResult(results, 3,
                    'Unable to query MQ brokers: ' + helpers.addError(listBrokers), region);
                return rcb();
            }

            if (!listBrokers.data.length) {
                helpers.addResult(results, 0, 'No MQ brokers found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }
            
            for (let broker of listBrokers.data) {
                if (!broker.BrokerArn) continue;
               
                let resource = broker.BrokerArn;

                if (broker.EngineType && broker.EngineType.toUpperCase() == 'RABBITMQ') {
                    helpers.addResult(results, 0, `AWS itself controls encryption for ${broker.EngineType.toUpperCase()} broker type`, region);
                    continue;
                }

                var describeBroker = helpers.addSource(cache, source,
                    ['mq', 'describeBroker', region, broker.BrokerId]);
                
                if (!describeBroker || describeBroker.err || !describeBroker.data) {
                    helpers.addResult(results, 3,
                        `Unable to describe MQ broker: ${helpers.addError(describeBroker)}`,
                        region, resource);
                    continue;
                } 
               
                if (describeBroker.data.EncryptionOptions &&
                   describeBroker.data.EncryptionOptions.KmsKeyId) {

                    let KmsKeyId = describeBroker.data.EncryptionOptions.KmsKeyId;
                    var keyId = KmsKeyId.split('/')[1] ? KmsKeyId.split('/')[1] : KmsKeyId;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]);  

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, KmsKeyId);
                        continue;
                    }
                
                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else if (describeBroker.data.EncryptionOptions &&
                    describeBroker.data.EncryptionOptions.UseAwsOwnedKey) {
                    currentEncryptionLevel = 1;
                } else {
                    currentEncryptionLevel = 2;
                }
            
                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `MQ Broker data at-rest is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `MQ Broker data at-rest is encrypted with ${currentEncryptionLevelString} \
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
