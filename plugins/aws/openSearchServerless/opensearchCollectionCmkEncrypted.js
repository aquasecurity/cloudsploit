var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Collection CMK Encryption',
    category: 'OpenSearch',
    domain: 'Serverless',
    severity: 'High',
    description: 'Ensures that OpenSearch Serverless collections are encrypted with KMS Customer Master Keys (CMKs).',
    more_info: 'OpenSearch Serverless should use KMS Customer Master Keys (CMKs) instead of AWS managed keys for encryption in order to have full control over data encryption and decryption.',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-encryption.html',
    recommended_action: 'Update the encryption policy and customer managed key for encryption.',
    apis: ['OpenSearchServerless:listEncryptionSecurityPolicies',  'OpenSearchServerless:listCollections',
        'OpenSearchServerless:getEncryptionSecurityPolicy','KMS:describeKey', 'KMS:listKeys'],
    settings: {
        opensearch_collection_desired_encryption_level: {
            name: 'OpenSearch Collection Target Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms'
        }
    },
    realtime_triggers: ['opensearchserverless:CreateCollection', 'opensearchserverless:DeleteCollection'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.opensearch_collection_desired_encryption_level || this.settings.opensearch_collection_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;


        async.each(regions.opensearchserverless, function(region, rcb){
            var listCollections = helpers.addSource(cache, source, 
                ['opensearchserverless', 'listCollections', region]);
            
            if (!listCollections) return rcb();

            if ( !listCollections.data || listCollections.err) {
                helpers.addResult(results, 3,
                    'Unable to list OpenSearch collections: ' + helpers.addError(listCollections), region);
                return rcb();
            }

            if (!listCollections.data.length){
                helpers.addResult(results, 0, 'No OpenSearch collections found', region);
                return rcb();
            }

            var listSecurityPolicies = helpers.addSource(cache, source,
                ['opensearchserverless', 'listEncryptionSecurityPolicies', region]);

            if (!listSecurityPolicies && listSecurityPolicies.err || !listSecurityPolicies.data) {
                helpers.addResult(results, 3,
                    'Unable to query list OpenSearch security policies: ' + helpers.addError(listSecurityPolicies), region);
                return rcb();
            }

            if (!listSecurityPolicies.data.length) {
                helpers.addResult(results, 2, 'No OpenSearch security policies found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            let policyMap = {};
            for (let policy of listSecurityPolicies.data){
                var getSecurityPolicy = helpers.addSource(cache, source,
                    ['opensearchserverless', 'getEncryptionSecurityPolicy', region, policy.name]);

                let securityPolicy;
                if (getSecurityPolicy && getSecurityPolicy.data && getSecurityPolicy.data.securityPolicyDetail && getSecurityPolicy.data.securityPolicyDetail.policy){
                    securityPolicy = getSecurityPolicy.data.securityPolicyDetail.policy;

                    for (let collection of listCollections.data){
                        let found = securityPolicy.Rules.find(rule => rule.Resource.indexOf(`collection/${collection.name}`) > -1 &&
                                rule.ResourceType == 'collection');

                        if (!found) continue;

                        if (securityPolicy.AWSOwnedKey){
                            currentEncryptionLevel = 2; //awskms  
                        } else {
                            if (securityPolicy.KmsARN) {
                                var kmsKeyId = securityPolicy.KmsARN.split('/')[1] ? securityPolicy.KmsARN.split('/')[1] : securityPolicy.KmsARN;

                                var describeKey = helpers.addSource(cache, source,
                                    ['kms', 'describeKey', region, kmsKeyId]);  
                                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                                    helpers.addResult(results, 3,
                                        `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                                        region, securityPolicy.KmsARN);
                                    return rcb();
                                }

                                currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                            }
                            if (found && !policyMap[collection.arn]){
                                
                                policyMap[collection.arn] = currentEncryptionLevel;
                                break;
                            }
                        }
                    }
                }
            }

            for (let col of listCollections.data){
                if (policyMap[col.arn] >= desiredEncryptionLevel){
                    helpers.addResult(results, 0,  `OpenSearch collection is encrypted with ${helpers.ENCRYPTION_LEVELS[policyMap[col.arn]]} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`, region, col.arn);
                } else {
                    helpers.addResult(results, 2, `OpenSearch collection is encrypted with ${helpers.ENCRYPTION_LEVELS[2]} \
                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`, region, col.arn);
                }    
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
