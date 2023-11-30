var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Bedrock Model Invocation Logging Enabled',
    category: 'BedRock',
    domain: 'Machine Learning',
    description: 'Ensure that an Amazon Bedrock model invocation logging is enabled.',
    more_info: 'With invocation logging, you can collect the full request data, response data, and metadata associated with all calls performed in account.',
    recommended_action: 'Enable invocation logging for bedrock mdoels',
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

            if (invocationLoggingConfiguration.err && invocationLoggingConfiguration.err.message.includes('This service may not be available in')) {
                helpers.addResult(results, 0, 'Bedrock service is not available in this region', region);
                return rcb();
            } else if (invocationLoggingConfiguration.err ) {
                helpers.addResult(results, 3,
                    `Unable to query for Invocation Logging Configuration: ${helpers.addError(invocationLoggingConfiguration)}`, region); 
                return rcb();   
            }

            if (!invocationLoggingConfiguration.data) {
                helpers.addResult(results, 2, 'Invocation logging configuration is not enabled for bedrock models', region);
            
            } else {
                helpers.addResult(results, 0, 'Invocation logging configuration is enabled for bedrock models', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

