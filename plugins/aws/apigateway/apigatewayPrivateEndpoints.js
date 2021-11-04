var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Gateway Private Endpoints',
    category: 'API Gateway',
    domain: 'Availability',
    description: 'Ensures that Amazon API Gateway APIs are only accessible through private endpoints.',
    more_info: 'API Gateway APIs should be only accessible through private endpoints to ensure API security.',
    recommended_action: 'Set API Gateway API endpoint configuration to private',
    link: 'https://aws.amazon.com/blogs/compute/introducing-amazon-api-gateway-private-endpoints',
    apis: ['APIGateway:getRestApis'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.apigateway, function(region, rcb){
            var getRestApis = helpers.addSource(cache, source,
                ['apigateway', 'getRestApis', region]);

            if (!getRestApis) return rcb();

            if (getRestApis.err || !getRestApis.data) {
                helpers.addResult(results, 3,
                    `Unable to query for API Gateway Rest APIs: ${helpers.addError(getRestApis)}`, region);
                return rcb();
            }

            if (!getRestApis.data.length) {
                helpers.addResult(results, 0, 'No API Gateway Rest APIs found', region);
                return rcb();
            }

            getRestApis.data.forEach(api => {
                if (!api.id || !api.name) return;
                var apiArn = `arn:${awsOrGov}:apigateway:${region}::/restapis/${api.id}`;

                if (!api.endpointConfiguration || !api.endpointConfiguration.types || !api.endpointConfiguration.types.length) {
                    helpers.addResult(results, 2,
                        `API Gateway API "${api.name}" does not have endpoint configuration enabled`,
                        region, apiArn);
                }

                var publicEndpoint = api.endpointConfiguration.types.find(type => type.toUpperCase() !== 'PRIVATE');

                if (publicEndpoint) {
                    helpers.addResult(results, 2,
                        `API Gateway API "${api.name}" is accessible through public endpoints`,
                        region, apiArn);
                } else {
                    helpers.addResult(results, 0,
                        `API Gateway API "${api.name}" is only accessible through private endpoints`,
                        region, apiArn);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
