var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Shield Advanced Enabled',
    category: 'Shield',
    description: 'Ensures AWS Shield Advanced is setup and properly configured',
    more_info: 'AWS Shield Advanced provides enhanced DDOS protection for all enrolled services within a subscribed account. Subscriptions should be active.',
    recommended_action: 'Enable AWS Shield Advanced for the account.',
    link: 'https://docs.aws.amazon.com/waf/latest/developerguide/ddos-overview.html#ddos-advanced',
    apis: ['Shield:describeSubscription'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var describeSubscription = helpers.addSource(cache, source,
            ['shield', 'describeSubscription', region]);

        if (!describeSubscription) return callback(null, results, source);

        if (describeSubscription.err &&
            describeSubscription.err.code &&
            describeSubscription.err.code == 'ResourceNotFoundException') {
            helpers.addResult(results, 2, 'Shield subscription is not enabled');
            return callback(null, results, source);
        }

        if (describeSubscription.err || !describeSubscription.data) {
            helpers.addResult(results, 3,
                'Unable to query for Shield subscription: ' + helpers.addError(describeSubscription));
            return callback(null, results, source);
        }

        if (!describeSubscription.data.EndTime) {
            helpers.addResult(results, 2, 'Shield subscription is not enabled');
            return callback(null, results, source);
        }

        var end = describeSubscription.data.EndTime;
        var now = new Date();
        var renewing = (describeSubscription.data.AutoRenew && describeSubscription.data.AutoRenew == 'ENABLED');

        if (now >= end) {
            helpers.addResult(results, 2, 'Shield subscription has expired');
            return callback(null, results, source);
        }

        var daysBetween = helpers.daysBetween(now, end);

        if (daysBetween <= 90 && !renewing) {
            helpers.addResult(results, 2, 'Shield subscription is expiring in ' + daysBetween + ' days and is not configured to auto-renew');
        } else if (!renewing) {
            helpers.addResult(results, 1, 'Shield subscription is expiring in ' + daysBetween + ' days and is not configured to auto-renew');
        } else {
            helpers.addResult(results, 0, 'Shield subscription is enabled, expiring in ' + daysBetween + ' days and is configured to auto-renew');
        }

        return callback(null, results, source);
    }
};