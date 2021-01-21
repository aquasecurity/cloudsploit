var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Gateway Client Certificate',
    category: 'API Gateway',
    description: 'Ensures that Amazon API Gateway API stages use client certificates.',
    more_info: 'API Gateway API stages should use client certificates to ensure API security authorization.',
    recommended_action: 'Attach client certificate to API Gateway API stages',
    link: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-client-side-ssl-authentication.html',
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

                    if (stage.clientCertificateId) {
                        helpers.addResult(results, 0,
                            'API Gateway API stage uses a client certificate',
                            region, stageArn);
                    } else {
                        helpers.addResult(results, 2,
                            'API Gateway API stage does not use a client certificate',
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
