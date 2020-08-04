var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFront WAF Enabled',
    category: 'CloudFront',
    description: 'Ensures CloudFront distributions have WAF enabled.',
    more_info: 'Enabling WAF allows control over requests to the Cloudfront Distribution, allowing or denying traffic based off rules in the Web ACL',
    link: 'https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-associating-cloudfront-distribution.html',
    recommended_action: '1. Enter the WAF service. 2. Enter Web ACLs and filter by global. 3. If no Web ACL is found, Create a new global Web ACL and in Resource type to associate with web ACL, select the Cloudfront Distribution. ',
    apis: ['CloudFront:listDistributions', 'CloudFront:getDistribution'],

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
        var badFlag = false;
        // loop through Instances for every reservation
        listDistributions.data.forEach(distribution => {
            if (!distribution.WebACLId ||
                distribution.WebACLId === '') {
                helpers.addResult(results, 2,
                    'The Cloudfront Distribution does not have WAF enabled', ['global'], distribution.ARN);
                badFlag = true;
            }
        });

        if (!badFlag) {
            helpers.addResult(results, 0, 'All CloudFront distributions have WAF enabled');
        }

        return callback(null, results, source);
    }
};