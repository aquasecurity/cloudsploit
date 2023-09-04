var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Gateway Default Endpoint Disabled',
    category: 'API Gateway',
    domain: 'Availability',
    description: 'Ensure default execute-api endpoint is disabled for your API Gateway.',
    more_info: 'By default, clients can invoke your API by using the execute-api endpoint that API Gateway generates for your API. To ensure that clients can access your API only by using a custom domain name, disable the default execute-api endpoint.',
    recommended_action: 'Modify API Gateway to disable default execute-api endpoint.',
    link: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html',
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

                if (api.disableExecuteApiEndpoint) {
                    helpers.addResult(results, 0,
                        `API Gateway "${api.name}" is not accessible through default endpoint`,
                        region, apiArn);
                } else {
                    helpers.addResult(results, 2,
                        `API Gateway "${api.name}" is accessible through default endpoint`,
                        region, apiArn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};