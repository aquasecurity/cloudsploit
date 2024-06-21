var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS Bedrock In Use',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Low',
    description: 'Ensures that AWS Bedrock service is in use within your AWS account.',
    more_info: 'AWS Bedrock provides access to high-performing foundation models from leading AI startups and Amazon through a unified API, enabling easy experimentation, customization, and deployment of generative AI applications with robust security and privacy features.',
    link: 'https://docs.aws.amazon.com/bedrock/latest/userguide/what-is-bedrock.html',
    recommended_action: 'Use Bedrock service to utilize top foundation models with strong security and customization.',
    apis: ['Bedrock:listCustomModels'],
    realtime_triggers: ['bedrock:DeleteCustomModel'],

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
                helpers.addResult(results, 2, 'Bedrock service is not in use', region);
                return rcb();
            } else {
                helpers.addResult(results, 0, 'Bedrock service is in use', region);
                return rcb();

            }

        }, function(){
            callback(null, results, source);
        });
    }
};
