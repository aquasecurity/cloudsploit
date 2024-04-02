var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Gateway Authorization',
    category: 'API Gateway',
    domain: 'Availability',
    severity: 'High',
    description: 'Ensures that Amazon API Gateway APIs are using authorizer',
    more_info: 'API Gateway API should be using authorizer to enforce security measures and control access to API resources.',
    recommended_action: 'Modify API Gateway configuration and ensure that appropriate authorizers are set up for each API.',
    link: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html',
    apis: ['APIGateway:getRestApis', 'APIGateway:getAuthorizers'],
    realtime_triggers: ['apigateway:CreateRestApi','apigateway:DeleteRestApi','apigateway:ImportRestApi','apigateway:CreateAuthorizer','apigateway:DeleteAuthorizer'],
    
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
                if (!api.id) return;

                var apiArn = `arn:${awsOrGov}:apigateway:${region}::/restapis/${api.id}`;

                var getAuthorizers = helpers.addSource(cache, source,
                    ['apigateway', 'getAuthorizers', region, api.id]);
          
                if (!getAuthorizers || getAuthorizers.err || !getAuthorizers.data || !getAuthorizers.data.items) {
                    helpers.addResult(results, 3,
                        `Unable to query for API Gateway Authorizers: ${helpers.addError(getAuthorizers)}`,
                        region, apiArn);
                    return;
                }

                if (!getAuthorizers.data.items.length) {
                    helpers.addResult(results, 2,
                        'No authorizers found for API Gateway Rest API ',
                        region, apiArn );
                } else {
                    helpers.addResult(results, 0,
                        'Authorizers found for API Gateway Rest API ',
                        region, apiArn);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

        