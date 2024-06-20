var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Gateway V2 Authorization',
    category: 'API Gateway',
    domain: 'Availability',
    severity: 'High',
    description: 'Ensures that Amazon API Gateway V2 APIs are using authorizer.',
    more_info: 'API Gateway V2 APIs should be configured to use authorizer to enforce security measures and restrict access to API to only authorized users or processes.',
    recommended_action: 'Modify API Gateway V2 configuration and ensure that appropriate authorizers are set up for each API.',
    link: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html',
    apis: ['ApiGatewayV2:getApis','ApiGatewayV2:getAuthorizers'],
    realtime_triggers: ['ApiGatewayV2:createApi','ApiGatewayV2:deleteApi','ApiGatewayV2:importApi','ApiGatewayV2:createAuthorizer','ApiGatewayV2:deleteAuthorizer'],
    
    run: function(cache, settings, callback) {
        console.log('here');
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.apigatewayv2, function(region, rcb){
            var getApis = helpers.addSource(cache, source,
                ['apigatewayv2', 'getApis', region]);

            if (!getApis) return rcb();

            if (getApis.err || !getApis.data) {
                helpers.addResult(results, 3,
                    `Unable to query for API Gateway V2 APIs: ${helpers.addError(getApis)}`, region);
                return rcb();
            }

            if (!getApis.data.length) {
                helpers.addResult(results, 0, 'No API Gateway V2 APIs found', region);
                return rcb();
            }

            getApis.data.forEach(api => {
                if (!api.ApiId) return;

                var apiArn = `arn:${awsOrGov}:apigateway:${region}::/apis/${api.ApiId}`;

                var getAuthorizers = helpers.addSource(cache, source,
                    ['apigatewayv2', 'getAuthorizers', region, api.ApiId]);
          
                if (!getAuthorizers || getAuthorizers.err || !getAuthorizers.data || !getAuthorizers.data.Items) {
                    helpers.addResult(results, 3,
                        `Unable to query for API Gateway V2 authorizers: ${helpers.addError(getAuthorizers)}`,
                        region, apiArn);
                    return;
                }

                if (!getAuthorizers.data.Items.length) {
                    helpers.addResult(results, 2,
                        'No authorizers found for API Gateway V2 API',
                        region, apiArn );
                } else {
                    helpers.addResult(results, 0,
                        'Authorizers found for API Gateway V2 API',
                        region, apiArn);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

        