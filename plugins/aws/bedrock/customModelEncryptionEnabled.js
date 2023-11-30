var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Custom Model Encryption Enabled',
    category: 'BedRock',
    domain: 'Machine Learning',
    description: 'Ensure that an Amazon Bedrock custom model is encrypted by AWS KMS Customer Master Keys.',
    more_info: 'When you encrypt AWS Bedrock custom model using your own AWS KMS Customer Master Keys (CMKs) for enhanced protection, you have full control over who can use the encryption keys to access your custom model.',
    recommended_action: 'Encrypt Bedrock custom model using AWS KMS Customer Master Keys',
    link: 'https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-custom-job.html',
    apis: ['Bedrock:listCustomModels', 'Bedrock:getCustomModel'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.bedrock, function(region, rcb){
            var listCustomModels = helpers.addSource(cache, source,
                ['bedrock', 'listCustomModels', region]);

            if (!listCustomModels) return rcb();

            if (listCustomModels.err && listCustomModels.err.message.includes('This service may not be available in')) {
                helpers.addResult(results, 0, 'Bedrock service is not available in this region', region);
                return rcb();
            }

            if (listCustomModels.err || !listCustomModels.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Bedrock custom model list: ${helpers.addError(listCustomModels)}`, region);
                return rcb();
            }

            if (!listCustomModels.data.length) {
                helpers.addResult(results, 0, 'No Bedrock custom model found', region);
                return rcb();
            }


            for (let model of listCustomModels.data){
                if (!model.modelArn|| !model.modelName) continue;
               
                let resource = model.modelArn;

                let getCustomModel = helpers.addSource(cache, source,
                    ['bedrock', 'getCustomModel', region, model.modelName]);

    
                if (!getCustomModel || getCustomModel.err || !getCustomModel.data) {
                    helpers.addResult(results, 3, `Unable to describe Bedrock custom model : ${helpers.addError(getCustomModel)}`, region, resource);
                    continue;
                }

                if (getCustomModel.data.modelKmsKeyArn) {
                    helpers.addResult(results, 0,
                        'Bedrock custom model have CMK encryption enabled',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Bedrock custom model does not have CMK encryption enabled',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
