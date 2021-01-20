var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Gateway Content Encoding',
    category: 'API Gateway',
    description: 'Ensures that Amazon API Gateway APIs have content encoding enabled.',
    more_info: 'API Gateway API should have content encoding enabled to enable compression of response payload.',
    recommended_action: 'Enable content encoding and set minimum compression size of API Gateway API response',
    link: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-gzip-compression-decompression.html',
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
                    `Unable to query for API Gateway Rest APIs: ${helpers.addError(getRestApis)}`, region);
                return rcb();
            }

            if (!getRestApis.data.length) {
                helpers.addResult(results, 0, 'No API Gateway Rest APIs found', region);
                return rcb();
            }

            getRestApis.data.forEach(api => {
                if (!api.id) return rcb();
                var apiArn = `arn:${awsOrGov}:apigateway:${region}::/restapis/${api.id}`;

                if (api.minimumCompressionSize) {
                    helpers.addResult(results, 0,
                        `API Gateway "${api.name}" has content encoding enabled`,
                        region, apiArn);
                } else {
                    helpers.addResult(results, 2,
                        `API Gateway "${api.name}" does not have content encoding enabled`,
                        region, apiArn);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
