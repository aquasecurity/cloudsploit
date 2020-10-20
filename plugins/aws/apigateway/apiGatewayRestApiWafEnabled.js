var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Gateway REST API WAF Enabled',
    category: 'API Gateway',
    description: 'Ensure that all API Gateway REST APIs have WAF enabled.',
    more_info: 'Enabling WAF allows control over requests to the API Gateway, allowing or denying traffic based off rules in the Web ACL',
    link: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html',
    recommended_action: '1. Enter the WAF service. 2. Enter Web ACLs and filter by the region the API Gateway is in. 3. If no Web ACL is found, Create a new Web ACL in the region the Gateway resides and in Resource type to associate with web ACL, select the API Gateway. ',
    apis: ['APIGateway:getRestApis', 'APIGateway:getStages'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.apigateway, function(region, lcb){

            var restApis = helpers.addSource(cache, source,
                ['apigateway', 'getRestApis', region]);

            if (!restApis) return lcb();

            if (restApis.err || !restApis.data) {
                helpers.addResult(results, 3, 'Unable to query for API Gateways: ' + helpers.addError(restApis), region);
                return lcb();
            }

            if (!restApis.data.length) {
                helpers.addResult(results, 0, 'No API Gateways found', region);
                return lcb();
            }

            async.each(restApis.data, (api, cb) => {
                var stages = helpers.addSource(cache, source, ['apigateway', 'getStages', region, api.id]);
                if (!stages) {
                    helpers.addResult(results, 3, 'Unable to query for REST API Stage: ' + helpers.addError(api.name), region, api.name);
                    return cb();
                }

                if (stages.err || !stages.data) {
                    helpers.addResult(results, 3, 'Unable to query for REST API Gateways: ' + helpers.addError(api.name), region, api.name);
                    return cb();
                }

                if (stages.data.item.length < 1) {
                    helpers.addResult(results, 0, 'REST API does not have any stages', region, api.name);
                    return cb();
                }

                stages.data.item.forEach(stage => {
                    if (!stage.webAclArn || stage.webAclArn.length < 1) {
                        helpers.addResult(results, 2, 'The REST API/stage does not have WAF enabled', region, api.name + '/' + stage.stageName);
                    } else {
                        helpers.addResult(results, 0, 'The REST API/stage has WAF enabled', region, api.name + '/' + stage.stageName);
                    }
                });
                cb();
            }, function() {
                lcb();
            });
        }, function() {
            callback(null, results, source)
        });
    }
};