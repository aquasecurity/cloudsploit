var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFront Compress Objects Automatically',
    category: 'CloudFront',
    domain: 'Content Delivery',
    description: 'Ensure that your Amazon Cloudfront distributions are configured to automatically compress files(object).',
    more_info: ' Cloudfront data transfer is based on the total amount of data served, sending compressed files to the viewers is much less expensive than sending uncompressed files. ' +
               'To optimise your AWS cloud costs and speed up your web applications, configure your Cloudfront distributions to compress the web content served with compression enabled.',
    link: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html',
    recommended_action: 'Ensures that CloudFront is configured to automatically compress files',
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
                'Unable to query for CloudFront distributions: ' + helpers.addError(listDistributions), 'global');
            return callback(null, results, source);
        }

        if (!listDistributions.data.length) {
            helpers.addResult(results, 0, 'No CloudFront distributions found', 'global');
            return callback(null, results, source);
        }

        // loop through Instances for every reservation
        listDistributions.data.forEach(distribution => {
            if (distribution.DefaultCacheBehavior && distribution.DefaultCacheBehavior.Compress) {
                helpers.addResult(results, 0,
                    'CloudFront distribution is configured to compress files automatically', 'global', distribution.ARN);
            } else {
                helpers.addResult(results, 2,
                    'CloudFront distribution is not configured to compress files automatically', 'global', distribution.ARN);
            }
        });

        return callback(null, results, source);
    }
};