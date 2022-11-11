var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFront TLS Weak Cipher',
    category: 'CloudFront',
    domain: 'Content Delivery',
    description: 'Ensures CloudFront Distribution TLS Version is not weak cipher suite.',
    more_info: 'The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS where possible.',
    link: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html',
    recommended_action: 'Modify cloudFront distribution and update the TLS version.',
    apis: ['CloudFront:listDistributions'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
       
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
            console.log(distribution.Origins.Items)
            if (!distribution.Origins || !distribution.Origins.Items || !distribution.Origins.Items.length){
                helpers.addResult(results, 0, 'CloudFront distribution has no origins', 'global', distribution.ARN);
            } else {
                let items = distribution.Origins.Items;
                for (let origin of items){
                    if (!origin.CustomOriginConfig) continue;

                    let originProtocolPolicy = origin.CustomOriginConfig.OriginProtocolPolicy.toLowerCase();

                    if (originProtocolPolicy == 'http-only' || originProtocolPolicy == 'match-viewer'){
                        helpers.addResult(results, 2, 'CloudFront distribution custom origin is not configured to use HTTPS only', 'global', distribution.ARN);
                    } else {
                        helpers.addResult(results, 0, 'CloudFront distribution custom origin is configured to use HTTPS only', 'global', distribution.ARN);
                    }
                }
            }
        }
        callback(null, results, source);
    }
};