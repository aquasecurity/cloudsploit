var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'API Instance TLS Version',
    category: 'ApiGateway',
    description: 'Ensure that API Gateway instances are using latest TLS version.',
    more_info: 'API Gateway instances should enforce TLS version 1.2.1 to ensure encryption of data in transit with updated features.',
    link: 'https://www.alibabacloud.com/help/doc-detail/115169.html',
    recommended_action: 'Configure latest TLS version for API Gateway instances',
    apis: ['ApiGateway:DescribeApis', 'ApiGateway:DescribeApiGroup', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const regions = helpers.regions(settings);
        var defaultRegion = helpers.defaultRegion(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', defaultRegion, 'data']);

        for (const region of regions.apigateway) {
            const describeApis = helpers.addSource(cache, source,
                ['apigateway', 'DescribeApis', region]);
            
            if (!describeApis) continue;

            if (describeApis.err || !describeApis.data){
                helpers.addResult(results, 3,
                    'Unable to describe APIs: ' + helpers.addError(describeApis), region);
                continue;
            }

            for (const api of describeApis.data) {
                if(!api.GroupId) continue;

                var resource = helpers.createArn('apigateway', accountId, 'api', api.ApiId, region);

                const describeApiGroup = helpers.addSource(cache, source,
                    ['apigateway', 'DescribeApiGroup', region, api.GroupId]);
                
                if (!describeApiGroup) continue;
    
                if (describeApiGroup.err || !describeApiGroup.data){
                    helpers.addResult(results, 3,
                        'Unable to describe API group: ' + helpers.addError(describeApiGroup), region, resource);
                    continue;
                }
                const apiGroup = describeApiGroup.data;
                let configEnabled = false;
                if (apiGroup.HttpsPolicy && apiGroup.HttpsPolicy == 'HTTPS2_TLS1_0') configEnabled = true;
                
                const status = configEnabled ? 0 : 2;
                helpers.addResult(results, status,
                    `API instance ${configEnabled ? 'has' : 'does not have'} latest TLS version`, region, resource);

            }

        }               

        callback(null, results, source);
    }
};