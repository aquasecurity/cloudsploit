var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DevOps Guru Notifications Enabled',
    category: 'DevOpsGuru',
    domain: 'Availability',
    description: 'Ensures SNS topic is set up for Amazon DevOps Guru.',
    more_info: 'Amazon DevOps Guru uses an SNS topic to notify you about important DevOps Guru events.',
    recommended_action: 'Add a notification channel to DevOps Guru',
    link: 'https://docs.aws.amazon.com/devops-guru/latest/userguide/setting-up.html',
    apis: ['DevOpsGuru:listNotificationChannels'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.devopsguru, function(region, rcb){
            var listNotificationChannels = helpers.addSource(cache, source,
                ['devopsguru', 'listNotificationChannels', region]);

            if (!listNotificationChannels) return rcb();

            if (listNotificationChannels.err || !listNotificationChannels.data) {
                helpers.addResult(results, 3,
                    `Unable to list notification channels: ${helpers.addError(listNotificationChannels)}`, region);
                return rcb();
            }

            if (listNotificationChannels.data.length) {
                helpers.addResult(results, 0, 'SNS notification is configured for DevOps Guru', region);
            } else {
                helpers.addResult(results, 2, 'SNS notification is not configured for DevOps Guru', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
