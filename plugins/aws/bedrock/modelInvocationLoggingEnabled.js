var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Bedrock Model Invocation Logging Enabled',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Low',
    description: 'Ensure that Amazon Bedrock model invocation logging is enabled.',
    more_info: 'With invocation logging enabled, you can collect the full request data, response data, and metadata associated with all calls performed in account. This detailed logging provides valuable insights into model usage patterns, helps in troubleshooting, and enhances security by allowing for thorough analysis of model interactions. It also facilitates compliance with auditing requirements, offering a comprehensive record of model invocations.',
    recommended_action: 'Enable invocation logging for Amazon Bedrock models.',
    link: 'https://docs.aws.amazon.com/bedrock/latest/userguide/settings.html#model-invocation-logging',
    apis: ['Bedrock:getModelInvocationLoggingConfiguration'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.bedrock, function(region, rcb){
            var invocationLoggingConfiguration = helpers.addSource(cache, source,
                ['bedrock', 'getModelInvocationLoggingConfiguration', region]);

            if (!invocationLoggingConfiguration) return rcb();

            if (invocationLoggingConfiguration.err) {
                helpers.addResult(results, 3,
                    `Unable to query for Bedrock custom model list: ${helpers.addError(invocationLoggingConfiguration)}`, region);
                return rcb();
            }


            if (!invocationLoggingConfiguration.data) {
                helpers.addResult(results, 2, 'Invocation logging is not enabled for bedrock models', region);
            } else {
                helpers.addResult(results, 0, 'Invocation logging is enabled for bedrock models', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
