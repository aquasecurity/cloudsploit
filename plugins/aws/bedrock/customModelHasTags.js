var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Custom Model Has Tags',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Low',
    description: 'Ensures that Bedrock Custom model has tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/bedrock/latest/userguide/tagging.html',
    recommended_action: 'Modify Bedrock Custom model and add tags.',
    apis: ['Bedrock:listCustomModels','ResourceGroupsTaggingAPI:getResources'],
    realtime_triggers: ['bedrock:TagResource','bedrock:UntagResource', 'bedrock:DeleteCustomModel'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.bedrock, function(region, rcb){
            var listCustomModels = helpers.addSource(cache, source,
                ['bedrock', 'listCustomModels', region]);

            if (!listCustomModels) return rcb();

            if (listCustomModels.err && listCustomModels.err.message.includes('Unknown operation')) {
                helpers.addResult(results, 0,
                    'Custom model service is not available in this region', region);
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

            const arnList = [];
            for (let model of listCustomModels.data){
                if (!model.modelArn) continue;
                
                arnList.push(model.modelArn);
            }

            helpers.checkTags(cache, 'Bedrock custom model', arnList, region, results, settings);
            return rcb();

        }, function(){
            callback(null, results, source);
        });
    }
}; 
