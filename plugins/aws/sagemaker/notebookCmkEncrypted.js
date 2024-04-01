var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Notebook Instance CMK Encrypted',
    category: 'AI & ML',
    domain: 'Compute',
    severity: 'High',
    description: 'Ensure Notebook instances are encrypted with desired encryption level.',
    more_info: 'AWS Sagemaker notebook instance should have data encryption enabled with KMS Customer Master Key (CMK) instead of AWS-managed Key for cross-account access and in order to gain more granular control over encryption/decryption process.',
    recommended_action: 'Encrypt Sagemaker notebook instance with desired encryption level.',
    link: 'https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html',
    apis: ['SageMaker:listNotebookInstances','SageMaker:describeNotebookInstance', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        notebook_desired_encryption_level: {
            name: 'Notebook Instance Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(sse|awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk',
        }
    },
    realtime_triggers: ['sagemaker:CreateNotebookInstance', 'sagemaker:DeleteNotebookInstance'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var config = {
            desiredEncryptionLevelString: settings.notebook_desired_encryption_level || this.settings.notebook_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;


        async.each(regions.sagemaker, function(region, rcb){
            var listNotebookInstances = helpers.addSource(cache, source,
                ['sagemaker', 'listNotebookInstances', region]);

            if (!listNotebookInstances) return rcb();

            if (listNotebookInstances.err) {
                helpers.addResult(results, 3,
                    'Unable to query for Notebook Instances: ' +
                    helpers.addError(listNotebookInstances), region);
                return rcb();
            }

            if (!listNotebookInstances.data || !listNotebookInstances.data.length) {
                helpers.addResult(
                    results, 0, 'No Notebook Instances found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let instance of listNotebookInstances.data) {
                if (!instance.NotebookInstanceArn || !instance.NotebookInstanceName) continue;

                var instanceArn = instance.NotebookInstanceArn;
                
                var describeInstance = helpers.addSource(cache, source,
                    ['sagemaker', 'describeNotebookInstance', region, instance.NotebookInstanceName]);
                
                if (!describeInstance) continue;
                
                if (describeInstance.err || !describeInstance.data || describeInstance.data.length) {
                    helpers.addResult(
                        results, 3, 'Unable to query for Notebook Instance: ' +
                        helpers.addError(describeInstance), region); 
                        continue;
                }

                if (describeInstance.data.KmsKeyId) {

                    let kmsKeyId = describeInstance.data.KmsKeyId;
                    var keyId = kmsKeyId.split('/')[1] ? kmsKeyId.split('/')[1] : kmsKeyId;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]);  

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, kmsKeyId);
                            continue ;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                    
                } else {
                    currentEncryptionLevel = 1; //sse
                }
                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `Notebook instance data at-rest is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, instanceArn);
                } else {
                    helpers.addResult(results, 2,
                        `Notebook instance at-rest is encrypted with ${currentEncryptionLevelString} \
                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, instanceArn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
