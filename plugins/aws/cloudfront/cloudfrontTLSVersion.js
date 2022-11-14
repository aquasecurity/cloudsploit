var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFront TLS Version',
    category: 'CloudFront',
    domain: 'Content Delivery',
    description: 'Ensures CloudFront Distribution TLS Version is not Deprecated.',
    more_info: 'CloudFront now provides the CloudFront-Viewer-TLS header for use with origin request policies. CloudFront-Viewer-TLS is an HTTP header that includes the TLS version and cipher suite used to negotiate the viewer TLS connection.',
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
            
            if (deprecatedTLSVersions.includes(distribution.ViewerCertificate.MinimumProtocolVersion)){
                helpers.addResult(results, 2, 'CloudFront distribution\'s TLS version is deprecated', 'global', distribution.ARN);
            } else {
                helpers.addResult(results, 0, 'CloudFront distribution\'s TLS version is not deprecated', 'global', distribution.ARN);
            }
        }
        callback(null, results, source);
    }
};