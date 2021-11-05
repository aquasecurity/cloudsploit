var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'API Protocol',
    category: 'APIGateway',
    domain: 'Availability',
    description: 'Ensure that API Gateway APIs have protocol set to HTTPS.',
    more_info: 'HTTPS protocol should be implemented for APIs to ensure encryption of data in transit.',
    link: 'https://www.alibabacloud.com/help/doc-detail/29478.htm',
    recommended_action: 'Enable HTTPS protocol for APIs',
    apis: ['ApiGateway:DescribeApis', 'ApiGateway:DescribeApi', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};

        const region = helpers.defaultRegion(settings);        
        const regions = helpers.regions(settings);
        const accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', region, 'data']);
        
        for (const region of regions.apigateway) {
            const describeApis = helpers.addSource(cache, source, 
                ['apigateway', 'DescribeApis', region]);
            
            if (!describeApis) continue;

            if (describeApis.err || !describeApis.data) {
                helpers.addResult(results, 3,
                    'Unable to describe APIs: ' + helpers.addError(describeApis), region);
                continue;
            }
    
            if (!describeApis.data.length) {
                helpers.addResult(results, 0, 'No APIs found', region);
                continue;
            }
    
            for (var api of describeApis.data) {
                if (!api.ApiId) continue;
                
                const resource = helpers.createArn('apigateway', accountId, 'api', api.ApiId);
                const describeApi = helpers.addSource(cache, source,
                    ['apigateway', 'DescribeApi', region, api.ApiId]);
                
                if (!describeApi || describeApi.err || !describeApi.data) {
                    helpers.addResult(results, 3,
                        'Unable to describe API: ' + helpers.addError(describeApi), region, resource);
                    continue;
                }

                let secure = false;
                if (describeApi.data &&
                    describeApi.data.RequestConfig && 
                    describeApi.data.RequestConfig.RequestProtocol &&
                    describeApi.data.RequestConfig.RequestProtocol.toUpperCase() === 'HTTPS') secure = true;
                
                const status = secure ? 0 : 2;
                helpers.addResult(results, status,
                    `API ${secure ? 'has' : 'does not have'} HTTPS protocol configured`, region, resource);
            }
        }               

        callback(null, results, source);
    }
};
