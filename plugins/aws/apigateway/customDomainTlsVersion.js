var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Custom Domain TLS Version',
    category: 'API Gateway',
    domain: 'Availability',
    severity: 'High',
    description: 'Ensure API Gateway custom domains are using current minimum TLS version.',
    more_info: 'A security policy is a predefined combination of minimum TLS version and cipher suite offered by Amazon API Gateway. Choose either a TLS version 1.2 or TLS version 1.0 security policy.',
    recommended_action: 'Modify API Gateway custom domain security policy and specify new TLS version.',
    link: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html',
    apis: ['APIGateway:getDomainNames'],
    realtime_triggers: ['apigateway:CreateDomainName','apigateway:UpdateDomainName','apigateway:DeleteDomainName'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.apigateway, function(region, rcb){
            var getDomainNames = helpers.addSource(cache, source,
                ['apigateway', 'getDomainNames', region]);

            if (!getDomainNames) return rcb();

            if (getDomainNames.err || !getDomainNames.data) {
                helpers.addResult(results, 3,
                    `Unable to query for API Gateway Custom Domain: ${helpers.addError(getDomainNames)}`, region);
                return rcb();
            }
    
            if (!getDomainNames.data.length) {
                helpers.addResult(results, 0, 'No API Gateway Custom Domains found', region);
                return rcb();
            }
            for (let domain of getDomainNames.data){
                if (!domain.domainName) continue;

                var domainArn = `arn:${awsOrGov}:apigateway:${region}::/domainnames/${domain.domainName}`;

                if (domain.securityPolicy && domain.securityPolicy === 'TLS_1_2'){
                    helpers.addResult(results, 0,
                        `API Gateway Custom Domain is using current minimum TLS version ${domain.securityPolicy}`, region, domainArn);
                } else {
                    helpers.addResult(results, 2,
                        `API Gateway Custom Domain is using deprecated TLS version ${domain.securityPolicy}`, region, domainArn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};