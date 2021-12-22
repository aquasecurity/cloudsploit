var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Model Data Encrypted',
    category: 'LookoutVision',
    domain: 'Management and Governance',
    description: 'Ensure that LookoutVision model data is encrypted using desired KMS encryption level',
    more_info: 'By default, trained models and manifest files are encrypted in Amazon S3 using server-side encryption with KMS keys stored in AWS Key Management Service (SSE-KMS).'+
        'You can also use customer-managed keys instead in order to gain more granular control over encryption/decryption process.',
    link: 'https://docs.aws.amazon.com/lookout-for-vision/latest/developer-guide/security-data-encryption.html',
    recommended_action: 'Create LookoutVision model with customer-manager keys (CMKs) present in your account',
    apis: ['LookoutVision:listProjects', 'LookoutVision:listModels', 'LookoutVision:describeModel', 'KMS:describeKey', 'KMS:listKeys'],
    settings: {
        model_data_desired_encryption_level: {
            name: 'LookoutVision Data Target Encryption Level',
            description: 'In order (lowest to highest) sse=S3-SSE; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(sse|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var config = {
            desiredEncryptionLevelString: settings.model_data_desired_encryption_level || this.settings.model_data_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        var listProjects = helpers.addSource(cache, source,
            ['lookoutvision', 'listProjects', region]);

        if (!listProjects) return callback(null, results, source);

        if (listProjects.err || !listProjects.data) {
            helpers.addResult(results, 3,
                'Unable to query for LookoutVision projects: ' + helpers.addError(listProjects));
            return callback(null, results, source);
        }

        if (!listProjects.data.length) {
            helpers.addResult(results, 0, 'No LookoutVision projects found');
            return callback(null, results, source);
        }

        var listKeys = helpers.addSource(cache, source,
            ['kms', 'listKeys', region]);

        if (!listKeys || listKeys.err || !listKeys.data) {
            helpers.addResult(results, 3,
                `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
            return callback(null, results, source);
        }

        async.each(listProjects.data, function(project, cb){
            if (!project.ProjectName) return cb();

            var listModels = helpers.addSource(cache, source,
                ['lookoutvision', 'listModels', region, project.ProjectName]);
                // console.log(listModels.data);

            if (!listModels || listModels.err || !listModels.data) {
                helpers.addResult(results, 3,
                    'Unable to query for LookoutVision models: ' + project.ProjectName + ': ' + helpers.addError(listModels), region);
                return cb();
            }

            if (!listModels.data.Models || !listModels.data.Models.length) {
                helpers.addResult(results, 3,
                    'Unable to query for LookoutVision models descriptions: '  + helpers.addError(listModels), region);
                return cb();
            }

            for (let model of listModels.data.Models) {
                if (!model.ModelArn) continue;

                let resource = model.ModelArn;

                var describeModel = helpers.addSource(cache, source,
                    ['lookoutvision', 'describeModel', region, model.ModelVersion]);

                if (!describeModel ||
                    describeModel.err ||
                    !describeModel.data) {
                    helpers.addResult(results, 3,
                        'Unable to get LookoutVision models: ' + project.ProjectName + ': ' + helpers.addError(describeModel), region, resource);
                    continue;
                }

                if (describeModel.data.ModelDescription && 
                    describeModel.data.ModelDescription.KmsKeyId) {
                    var KmsKey =  describeModel.data.ModelDescription.KmsKeyId;
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
                    currentEncryptionLevel = 1; //sse
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `LookoutVision model data is encrypted with ${currentEncryptionLevelString} \
                    which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `LookoutVision model data is encrypted with ${currentEncryptionLevelString} \
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