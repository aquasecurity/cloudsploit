var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Gateway V2 Access Logging',
    category: 'API Gateway',
    domain: 'Availability',
    severity: 'Medium',
    description: 'Ensures that Amazon API Gateway V2 APIs stages have access logging enabled.',
    more_info: 'API Gateway V2 access logs provide detailed information about APIs and how the caller accessed the API. These logs are useful for applications for security and access audits which helps to analyze traffic patterns and to troubleshoot issues.',
    recommended_action: 'Modify API Gateway V2 configuration and ensure that access logging is configured for each stage.',
    link: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-logging.html',
    apis: ['ApiGatewayV2:getApis','ApiGatewayV2:getStages'],
    realtime_triggers: ['ApiGatewayV2:createApi','ApiGatewayV2:deleteApi','ApiGatewayV2:importApi','ApiGatewayv2:CreateStage','ApiGatewayv2:UpdateStage','ApiGatewayv2:DeleteStage'],

    run: function(cache, settings, callback) {
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

                var getStages = helpers.addSource(cache, source,
                    ['apigatewayv2', 'getStages', region, api.ApiId]);

                if (!getStages || getStages.err || !getStages.data || !getStages.data.Items) {
                    helpers.addResult(results, 3,
                        `Unable to query for API Gateway V2 API Stages: ${helpers.addError(getStages)}`,
                        region, apiArn);
                    return;
                }

                if (!getStages.data.Items.length) {
                    helpers.addResult(results, 0,
                        'No API Gateway V2 API Stages found',
                        region, apiArn);
                    return;
                }

                getStages.data.Items.forEach(stage => {
                    if (!stage.StageName) return;

                    var stageArn = `arn:${awsOrGov}:apigateway:${region}::/apis/${api.ApiId}/stages/${stage.StageName}`;
                    if (stage.AccessLogSetting) {
                        helpers.addResult(results, 0,
                            'API Gateway V2 API stage has access logging enabled',
                            region, stageArn);
                    } else {
                        helpers.addResult(results, 2,
                            'API Gateway V2 API stage does not have access logging enabled',
                            region, stageArn);
                    }
                });

            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

        