var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Gateway CloudWatch Logs',
    category: 'API Gateway',
    domain: 'Availability',
    description: 'Ensures that Amazon API Gateway API stages have Amazon CloudWatch Logs enabled.',
    more_info: 'API Gateway API stages should have Amazon CloudWatch Logs enabled to help debug issues related to request execution or client access to your API.',
    recommended_action: 'Modify API Gateway API stages to enable CloudWatch Logs',
    link: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html',
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
                    `Unable to query for API Gateway Rest APIs: ${helpers.addError(getRestApis)}`, region);
                return rcb();
            }

            if (!getRestApis.data.length) {
                helpers.addResult(results, 0, 'No API Gateway Rest APIs found', region);
                return rcb();
            }

            async.each(getRestApis.data, function(api, cb){
                if (!api.id) return cb();
                var apiArn = `arn:${awsOrGov}:apigateway:${region}::/restapis/${api.id}`;

                var getStages = helpers.addSource(cache, source,
                    ['apigateway', 'getStages', region, api.id]);

                if (!getStages || getStages.err || !getStages.data || !getStages.data.item) {
                    helpers.addResult(results, 3,
                        `Unable to query for API Gateway Rest API Stages: ${helpers.addError(getStages)}`,
                        region, apiArn);
                    return cb();
                }

                if (!getStages.data.item.length) {
                    helpers.addResult(results, 0,
                        'No Rest API Stages found',
                        region, apiArn);
                    return cb();
                }

                getStages.data.item.forEach(stage => {
                    if (!stage.stageName) return;

                    var stageArn = `arn:${awsOrGov}:apigateway:${region}::/restapis/${api.id}/stages/${stage.stageName}`;
                    if (stage.methodSettings && stage.methodSettings['*/*'] && stage.methodSettings['*/*'].loggingLevel) {
                        helpers.addResult(results, 0,
                            'API Gateway API stage has CloudWatch Logs enabled',
                            region, stageArn);
                    } else {
                        helpers.addResult(results, 2,
                            'API Gateway API stage does not have CloudWatch Logs enabled',
                            region, stageArn);
                    }
                });

                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
