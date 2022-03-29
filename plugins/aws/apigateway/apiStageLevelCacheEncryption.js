var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Stage-Level Cache Encryption',
    category: 'API Gateway',
    domain: 'Availability',
    description: 'Ensure that your Amazon API Gateway REST APIs are configured to encrypt API cached responses.',
    more_info: 'It is strongly recommended to enforce encryption for API cached responses in order to protect your data from unauthorized access.',
    recommended_action: 'Modify API Gateway API stages to enable encryption on cache data',
    link: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/data-protection-encryption.html',
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
                        `Unable to query API Gateway stages: ${helpers.addError(getStages)}`,
                        region, apiArn);
                    continue;
                }

                if (!getStages.data.item.length) {
                    helpers.addResult(results, 0,
                        'No rest API Gateway stages found',
                        region, apiArn);
                    continue;
                }

                getStages.data.item.forEach(stage => {
                    if (!stage.stageName) return;

                    var stageArn = `arn:${awsOrGov}:apigateway:${region}::/restapis/${api.id}/stages/${stage.stageName}`;

                    if (!stage.methodSettings || !stage.methodSettings['*/*'] || !stage.methodSettings['*/*'].cachingEnabled) {
                        helpers.addResult(results, 0,
                            'Response caching is not enabled for the API stage', region, stageArn);
                        return;
                    }

                    if (stage.methodSettings['*/*'].cacheDataEncrypted) {
                        helpers.addResult(results, 0,
                            'API Gateway stage encrypts cache data',
                            region, stageArn);
                    } else {
                        helpers.addResult(results, 2,
                            'API Gateway stage does not encrypt cache data',
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
