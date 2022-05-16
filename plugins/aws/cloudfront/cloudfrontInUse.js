var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFront Enabled',
    category: 'CloudFront',
    domain: 'Content Delivery',
    severity: 'LOW',
    description: 'Ensure that AWS CloudFront service is used within your AWS account.',
    more_info: 'Amazon CloudFront is a web service that speeds up distribution of your static and dynamic web content, such as .html, .css, .js, and image files, to your users. CloudFront delivers your content through a worldwide network of data centers called edge locations.',
    link: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html',
    recommended_action: 'Create CloudFront distributions as per requirement.',
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
                'Unable to list CloudFront distributions: ' + helpers.addError(listDistributions));
            return callback(null, results, source);
        }

        if (listDistributions.data.length) {
            helpers.addResult(results, 0, 
                'CloudFront service is in use', 
                'global');
        } else {
            helpers.addResult(results, 2,
                'CloudFront service is not in use', 
                'global');
        }

        return callback(null, results, source);
    }
};