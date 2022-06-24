var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SQS Encryption Enabled',
    category: 'SQS',
    domain: 'Application Integration',
    description: 'Ensure SQS queues are encrypted using keys of desired encryption level',
    more_info: 'Messages sent to SQS queues can be encrypted using KMS server-side encryption. Existing queues can be modified to add encryption with minimal overhead.'+
        'Use customer-managed keys instead in order to gain more granular control over encryption/decryption process.',
    recommended_action: 'Enable encryption using KMS Customer Master Keys (CMKs) for all SQS queues.',
    link: 'http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html',
    apis: ['SQS:listQueues', 'SQS:getQueueAttributes', 'KMS:listAliases', 'KMS:listKeys', 
        'KMS:describeKey', 'STS:getCallerIdentity'],
    settings: {
        sqs_queues_desired_encryption_level: {
            name: 'SQS Queues Target Encryption Level',
            description: 'In order (lowest to highest) sse=SSE-SQS; awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(sse|awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var config = {
            desiredEncryptionLevelString: settings.sqs_queues_desired_encryption_level || this.settings.sqs_queues_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.sqs, function(region, rcb){        
            var listQueues = helpers.addSource(cache, source,
                ['sqs', 'listQueues', region]);

            if (!listQueues) return rcb();

            if (listQueues.err) {
                helpers.addResult(results, 3,
                    'Unable to query SQS queues: ' + helpers.addError(listQueues), region);
                return rcb();
            }

            if (!listQueues.data || !listQueues.data.length) {
                helpers.addResult(results, 0, 'No SQS queues found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            var listAliases = helpers.addSource(cache, source,
                ['kms', 'listAliases', region]);

            if (!listAliases || listAliases.err || !listAliases.data) {
                helpers.addResult(results, 3,
                    `Unable to query for KMS aliases: ${helpers.addError(listAliases)}`,
                    region);
                return rcb();
            }

            var keyArn;
            var kmsAliasArnMap = {};
            listAliases.data.forEach(function(alias){
                keyArn = alias.AliasArn.replace(/:alias\/.*/, ':key/' + alias.TargetKeyId);
                kmsAliasArnMap[alias.AliasName] = keyArn;
            });
         
            for (let queue of listQueues.data) {
                let resource = `arn:${awsOrGov}:sqs:${region}:${accountId}:${queue}`;
                
                var getQueueAttributes = helpers.addSource(cache, source,
                    ['sqs', 'getQueueAttributes', region, queue]);  
                    
                if (!getQueueAttributes || getQueueAttributes.err || !getQueueAttributes.data ||
                    !getQueueAttributes.data.Attributes) {
                    helpers.addResult(results, 3,
                        `Unable to get SQS queues description: ${helpers.addError(getQueueAttributes)}`,
                        region, resource);
                    continue;
                }

                if (!getQueueAttributes.data.Attributes.KmsMasterKeyId &&
                    getQueueAttributes.data.Attributes.SqsManagedSseEnabled === 'false') {
                    helpers.addResult(results, 2,
                        'SQS queues does not have encryption enabled',
                        region, resource);
                    continue;
                }

                if (getQueueAttributes.data.Attributes.KmsMasterKeyId) {
                    var encryptionKey = getQueueAttributes.data.Attributes.KmsMasterKeyId;
                    let kmsKeyArn = (encryptionKey.startsWith('alias/')) ?
                        (kmsAliasArnMap[encryptionKey]) ? kmsAliasArnMap[encryptionKey] :
                            encryptionKey : encryptionKey;
                
                    var keyId = kmsKeyArn.split('/')[1] ? kmsKeyArn.split('/')[1] : kmsKeyArn;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]);

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, kmsKeyArn);
                        continue;
                    }
                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);

                } else currentEncryptionLevel = 1; //sse
                            
                let currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `SQS queue is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `SQS queue is encrypted with ${currentEncryptionLevelString} \
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