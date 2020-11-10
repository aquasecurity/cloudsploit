var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Gateway WAF Enabled',
    category: 'API Gateway',
    description: 'Ensures that API Gateway APIs are associated with Web Application Firewall.',
    more_info: 'API Gateway APIs should be associated with Web Application Firewall to ensure API security.',
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
                var resource = `arn:${awsOrGov}:apigateway:${region}::/restapis/${api.id}`;
                var unassociatedStages = [];

                var getStages = helpers.addSource(cache, source,
                    ['apigateway', 'getStages', region, api.id]);

                if (!getStages) return cb();

                if (getStages.err || !getStages.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for API Gateway Rest API Stages: ${helpers.addError(getStages)}`,
                        region, resource);
                    return cb();
                }

                if (!getStages.data.item || !getStages.data.item.length) {
                    helpers.addResult(results, 0,
                        'No API Gateway Rest API Stages found',
                        region, resource);
                    return cb();
                }

                getStages.data.item.forEach(stage => {
                    if (!stage.webAclArn && stage.stageName) {
                        unassociatedStages.push(stage.stageName);
                    }
                });

                if (!unassociatedStages.length) {
                    helpers.addResult(results, 0,
                        `API Gateway API "${api.id}" has WAF enabled for all stages`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `API Gateway API "${api.id}" does not have WAF enabled for these stages: ${unassociatedStages.join(', ')}`,
                        region, resource);
                }

                cb();
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};