var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFront Enabled',
    category: 'CloudFront',
    domain: 'Content Delivery',
    description: 'Ensure that AWS CloudFront service is used within your AWS account.',
    more_info: 'Amazon CloudFront is a web service that speeds up distribution of your static and dynamic web content, such as .html, .css, .js, and image files, to your users. CloudFront delivers your content through a worldwide network of data centers called edge locations.',
    link: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html',
    recommended_action: 'Check if CloudFront is in use or not by observing the data received.',
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

        if (listDistributions.data.length) {
            helpers.addResult(results, 0, 
                'AWS Cloudfront service is currently in use', 
                'global');
        } else {
            helpers.addResult(results, 2,
                'AWS Cloudfront service is not currently in use', 
                'global');
        }

        return callback(null, results, source);
    }
};