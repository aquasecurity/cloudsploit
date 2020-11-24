var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Gateway WAF Enabled',
    category: 'API Gateway',
    description: 'Ensures that API Gateway APIs are associated with a Web Application Firewall.',
    more_info: 'API Gateway APIs should be associated with a Web Application Firewall to ensure API security.',
    recommended_action: 'Associate API Gateway API with Web Application Firewall',
    link: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html',
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
                helpers.addResult(results, 0,
                    'No API Gateway Rest APIs found', region);
                return rcb();
            }

            async.each(getRestApis.data, function(api, cb){
                if (!api.id) return cb();

                var apiArn = `arn:${awsOrGov}:apigateway:${region}::/restapis/${api.id}`;

                var getStages = helpers.addSource(cache, source,
                    ['apigateway', 'getStages', region, api.id]);

                if (!getStages || getStages.err || !getStages.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for API Gateway Rest API Stages: ${helpers.addError(getStages)}`,
                        region, apiArn);
                    return cb();
                }

                if (!getStages.data.item || !getStages.data.item.length) {
                    helpers.addResult(results, 0,
                        'No Rest API Stages found',
                        region, apiArn);
                    return cb();
                }

                getStages.data.item.forEach(stage => {
                    if (!stage.stageName) return;

                    var stageArn = `arn:${awsOrGov}:apigateway:${region}::/restapis/${api.id}/stages/${stage.stageName}`;
                    if (stage.webAclArn) {
                        helpers.addResult(results, 0,
                            'API Gateway Stage has WAF enable',
                            region, stageArn);
                    } else {
                        helpers.addResult(results, 2,
                            'API Gateway Stage does not have WAF enabled',
                            region, stageArn);
                    }
                });

                cb();
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
