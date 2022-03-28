var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFront Distribution Field-Level Encryption',
    category: 'CloudFront',
    domain: 'Content Delivery',
    severity: 'MEDIUM',
    description: 'Ensure that field-level encryption is enabled for your Amazon CloudFront web distributions.',
    more_info: 'With Amazon CloudFront, you can enforce secure end-to-end connections to origin servers by using HTTPS. Field-level encryption adds an additional layer of security that lets you protect specific data throughout system processing so that only certain applications can see it.'+
        'Field-level encryption allows you to enable users to securely upload sensitive information to web servers. ',
    link: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/field-level-encryption.html',
    recommended_action: 'Enable field-level encryption for CloudFront distributions.',
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

        if (!listDistributions.data.length) {
            helpers.addResult(results, 0, 'No CloudFront distributions found');
            return callback(null, results, source);
        }

        listDistributions.data.forEach(distribution => {
            if (distribution.DefaultCacheBehavior &&
                distribution.DefaultCacheBehavior.FieldLevelEncryptionId) {
                helpers.addResult(results, 0,
                    'Distribution has field level encryption enabled', 'global', distribution.ARN);
            } else {
                helpers.addResult(results, 2,
                    'Distribution does not have field level encryption enabled', 'global', distribution.ARN);
            }
        });

        return callback(null, results, source);
    }
};