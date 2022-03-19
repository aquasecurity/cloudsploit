var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Gateway Response Caching',
    category: 'API Gateway',
    domain: 'Availability',
    description: 'Ensure that response caching is enabled for your Amazon API Gateway REST APIs.',
    more_info: 'A REST API in API Gateway is a collection of resources and methods that are integrated with backend HTTP endpoints, Lambda functions, or other AWS services.You can enable API caching in Amazon API Gateway to cache your endpoint responses. ' +
        'With caching, you can reduce the number of calls made to your endpoint and also improve the latency of requests to your API.',
    recommended_action: 'Modify API Gateway API stages to enable API cache',
    link: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html',
    apis: ['APIGateway:getRestApis', 'APIGateway:getStages'],

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
                    `Unable to query for API Gateway rest APIs: ${helpers.addError(getRestApis)}`, region);
                return rcb();
            }

            if (!getRestApis.data.length) {
                helpers.addResult(results, 0, 'No API Gateway rest APIs found', region);
                return rcb();
            }

            for (let api of getRestApis.data){
                if (!api.id) continue;
                var apiArn = `arn:${awsOrGov}:apigateway:${region}::/restapis/${api.id}`;

                var getStages = helpers.addSource(cache, source,
                    ['apigateway', 'getStages', region, api.id]);

                if (!getStages || getStages.err || !getStages.data || !getStages.data.item) {
                    helpers.addResult(results, 3,
                        `Unable to query for API Gateway rest API Stages: ${helpers.addError(getStages)}`,
                        region, apiArn);
                    continue;
                }

                if (!getStages.data.item.length) {
                    helpers.addResult(results, 0,
                        'No rest API Stages found',
                        region, apiArn);
                    continue;
                }

                getStages.data.item.forEach(stage => {
                    if (!stage.stageName) return;

                    var stageArn = `arn:${awsOrGov}:apigateway:${region}::/restapis/${api.id}/stages/${stage.stageName}`;

                    if (stage.cacheClusterEnabled) {
                        helpers.addResult(results, 0,
                            'Response caching is enabled for API Gateway API stage',
                            region, stageArn);
                    } else {
                        helpers.addResult(results, 2,
                            'Response caching is not enabled for API Gateway API stage',
                            region, stageArn);
                    }
                });
            }

            rcb();

        }, function(){
            callback(null, results, source);
        });
    }
};