var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Gateway Request validation',
    category: 'API Gateway',
    domain: 'Availability',
    severity: 'Medium',
    description: 'Ensures that Amazon API Gateway method has request validation enabled.',
    more_info: 'Enabling request validation for API Gateway allows to perform basic validation of an API request before proceeding with the integration request. When request validation fails, API Gateway immediately fails the request reduceing unnecessary calls to the backend.',
    recommended_action: 'Modify API Gateway configuration and ensure that appropriate request validators are set up for each API.',
    link: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-request-validation.html',
    apis: ['APIGateway:getRestApis', 'APIGateway:getRequestValidators'],
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

                var getRequestValidators = helpers.addSource(cache, source,
                    ['apigateway', 'getRequestValidators', region, api.id]);
          
                if (!getRequestValidators || getRequestValidators.err || !getRequestValidators.data || !getRequestValidators.data.items) {
                    helpers.addResult(results, 3,
                        `Unable to query for API Gateway Request Validators: ${helpers.addError(getRequestValidators)}`,
                        region, apiArn);
                    return;
                }

                if (!getRequestValidators.data.items.length) {
                    helpers.addResult(results, 2,
                        'No request validators found for API Gateway Rest API',
                        region, apiArn );
                } else {
                    helpers.addResult(results, 0,
                        'Request validators found for API Gateway Rest API',
                        region, apiArn);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

        