var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Shield Protections',
    category: 'Shield',
    description: 'Ensures AWS Shield Advanced is configured to protect account resources',
    more_info: 'Once AWS Shield Advanced is enabled, it can be applied to resources within the account including ELBs, CloudFront.',
    recommended_action: 'Enable AWS Shield Advanced on resources within the account.',
    link: 'https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html',
    apis: ['Shield:listProtections'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var listProtections = helpers.addSource(cache, source,
            ['shield', 'listProtections', region]);

        if (!listProtections) return callback(null, results, source);

        if (listProtections.err &&
            listProtections.err.code &&
            listProtections.err.code == 'ResourceNotFoundException') {
            helpers.addResult(results, 2, 'Shield subscription is not enabled');
            return callback(null, results, source);
        }

        if (listProtections.err || !listProtections.data) {
            helpers.addResult(results, 3,
                'Unable to query for Shield protections: ' + helpers.addError(listProtections));
            return callback(null, results, source);
        }

        if (!listProtections.data.length) {
            helpers.addResult(results, 2, 'Shield protections are not configured');
        } else {
            helpers.addResult(results, 0, 'Shield protections are configured on account resources');
        }

        return callback(null, results, source);
    }
};