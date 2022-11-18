var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFront TLS Deprecated Protocols',
    category: 'CloudFront',
    domain: 'Content Delivery',
    description: 'Ensures AWS CloudFront distribution is not using deprecated TLS Version.',
    more_info: 'Use latest TLS policy for CloudFront distribution to meet compliance and regulatory requirements within your organisation and to adhere to AWS security best policies.',
    link: 'https://aws.amazon.com/about-aws/whats-new/2020/07/cloudfront-tls-security-policy/',
    recommended_action: 'Modify cloudFront distribution and update the TLS version.',
    apis: ['CloudFront:listDistributions'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        const deprecatedTLSVersions = [
            'SSLv3',
            'TLSv1',
            'TLSv1_2016',
            'TLSv1.1_2016',
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
            
            if (distribution.ViewerCertificate && distribution.ViewerCertificate.MinimumProtocolVersion && !deprecatedTLSVersions.includes(distribution.ViewerCertificate.MinimumProtocolVersion)){
                helpers.addResult(results, 0, 'CloudFront distribution is not using deprecated TLS versions', 'global', distribution.ARN);
                
            } else {
                helpers.addResult(results, 2, 'CloudFront distribution is using deprecated TLS version', 'global', distribution.ARN);
            }
        }
        callback(null, results, source);
    }
};