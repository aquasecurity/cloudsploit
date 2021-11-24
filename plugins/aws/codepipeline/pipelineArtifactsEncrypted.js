var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Pipeline Artifacts Encrypted',
    category: 'CodePipeline',
    domain: 'Application Integration',
    description: 'Ensure that AWS CodePipeline is using desired encryption level to encrypt pipeline artifacts being stored in S3.',
    more_info: 'CodePipeline creates an S3 artifact bucket and default AWS managed key when you create a pipeline.'+
    'By default, these artifacts are encrypted using default AWS-managed S3 key. Use customer-managed key for encryption in order to to gain more granular control over encryption/decryption process.',
    recommended_action: 'Ensure customer-manager keys (CMKs) are being used for CodePipeline pipeline artifacts.',
    link: 'https://docs.aws.amazon.com/codepipeline/latest/userguide/S3-artifact-encryption.html',
    apis: ['CodePipeline:listPipelines','CodePipeline:getPipeline', 'KMS:describeKey',
        'KMS:listKeys', 'STS:getCallerIdentity', 'KMS:listAliases'],
    settings: {
        pipeline_artifacts_desired_encryption_level: {
            name: 'Pipeline Artifacts Desired Encrypted Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var defaultRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);

        var config = {
            desiredEncryptionLevelString: settings.pipeline_artifacts_desired_encryption_level || this.settings.pipeline_artifacts_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.codepipeline, function(region, rcb){        
            var listPipelines = helpers.addSource(cache, source,
                ['codepipeline', 'listPipelines', region]);

            if (!listPipelines) return rcb();

            if (listPipelines.err || !listPipelines.data) {
                helpers.addResult(results, 3,
                    'Unable to query Pipeline Artifacts: ' + helpers.addError(listPipelines), region);
                return rcb();
            }

            if (!listPipelines.data.length) {
                helpers.addResult(results, 0, 'No Pipeline Artifacts found', region);
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
                kmsAliasArnMap[alias.AliasArn] = keyArn;
            });

            for (let pipeline of listPipelines.data) {
                let resource = `arn:${awsOrGov}:codepipeline:${region}:${accountId}:${pipeline.name}`;

                var getPipeline = helpers.addSource(cache, source,
                    ['codepipeline', 'getPipeline', region, pipeline.name]);

                if (!getPipeline || getPipeline.err || !getPipeline.data ) {
                    helpers.addResult(results, 3,
                        `Unable to get Pipeline Artifacts description: ${helpers.addError(getPipeline)}`,
                        region, resource);
                    continue;
                } 
               
                if (getPipeline.data.pipeline && 
                    getPipeline.data.pipeline.artifactStore &&
                    getPipeline.data.pipeline.artifactStore.encryptionKey &&
                    getPipeline.data.pipeline.artifactStore.encryptionKey.id) {
                    var kmsKey =  getPipeline.data.pipeline.artifactStore.encryptionKey.id;
                    var kmsKeyArn = (kmsAliasArnMap[kmsKey]) ? kmsAliasArnMap[kmsKey] : null;
                 
                    if (!kmsKeyArn) {
                        helpers.addResult(results, 3,
                            'Unable to get Key Id for KMS Key Arn',
                            region, kmsKey);
                        continue;
                    }
        
                    var keyId = kmsKeyArn.split('/')[1] ? kmsKeyArn.split('/')[1] : kmsKeyArn; 
                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]);   

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, kmsKey);
                        continue;

                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else {
                    currentEncryptionLevel=2; //awskms
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `Pipeline artifacts are encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Pipeline artifacts are encrypted with ${currentEncryptionLevelString} \
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