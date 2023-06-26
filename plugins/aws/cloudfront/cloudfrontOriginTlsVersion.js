var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFront Distribution Origins TLS Version',
    category: 'CloudFront',
    domain: 'Content Delivery',
    description: 'Ensures CloudFront Distribution custom origin TLS version is not deprecated.',
    more_info: 'The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS where possible.',
    link: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html',
    recommended_action: 'Modify cloudFront distribution and update the TLS version.',
    apis: ['CloudFront:listDistributions'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        const deprecatedVersion = [
            'SSLv3',
            'TLSv1',
            'TLSv1.1',
        ];
        var region = helpers.defaultRegion(settings);

        var listDistributions = helpers.addSource(cache, source,
            ['cloudfront', 'listDistributions', region]);

        if (!listDistributions) return callback(null, results, source);

        if (listDistributions.err || !listDistributions.data) {
            helpers.addResult(results, 3,
                'Unable to query for CloudFront distributions: ' + helpers.addError(listDistributions));
            return callback(null, results, source);
        }

        if (!listDistributions.data.length) {
            helpers.addResult(results, 0, 'No CloudFront distributions found');
            return callback(null, results, source);
        }
 
        for (let distribution of listDistributions.data){
            if (!distribution.ARN) continue;
            if (!distribution.Origins || !distribution.Origins.Items || !distribution.Origins.Items.length){
                helpers.addResult(results, 0, 'CloudFront distribution has no origins', 'global', distribution.ARN);
            } else {
                let origins = distribution.Origins.Items;
                for (let origin of origins){
                    if (!origin.CustomOriginConfig ||
                    !origin.CustomOriginConfig.OriginSslProtocols ||
                    !origin.CustomOriginConfig.OriginSslProtocols.Items) {
                        helpers.addResult(results, 0, 'CloudFront distribution does not have custom origins or origins do not have SSL protocol items', 'global', distribution.ARN);
                        continue;
                    }

                    let sslItems = origin.CustomOriginConfig.OriginSslProtocols.Items;
                    let isDeprecated = false;
                    for (let item of sslItems){
                        if (deprecatedVersion.includes(item)){
                            isDeprecated = true;
                            break;
                        } 
                    }
                    if (isDeprecated){
                        helpers.addResult(results, 2, 'CloudFront distribution custom origin TLS version is deprecated', 'global', distribution.ARN);
                    } else {
                        helpers.addResult(results, 0, 'CloudFront distribution custom origin TLS version is not deprecated', 'global', distribution.ARN);    
                    }   
                }
            }
        }
        callback(null, results, source);
    }
};
