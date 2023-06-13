var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Azure Subscription Has Tags',
    category: 'Subscription',
    domain: 'Management',
    description: 'Ensures that Azure subscriptions have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify affected subscription and add tags.',
    link: 'https://learn.microsoft.com/en-us/dotnet/api/microsoft.azure.management.resourcemanager.models.subscription.tags',
    apis: ['subscriptions:getSubscription'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.subscriptions, function(location, rcb){

            var subscriptions = helpers.addSource(cache, source,
                ['subscriptions', 'getSubscription', location]);
            console.log(cache.subscriptions)
            if (!subscriptions) return rcb();

            if (subscriptions.err || !subscriptions.data) {
                helpers.addResult(results, 3, 'Unable to query for subscriptions: ' + helpers.addError(subscriptions), location);
                return rcb();
            }
            if (!subscriptions.data.length) {
                helpers.addResult(results, 0, 'No existing subscriptions found', location);
                return rcb();
            }
            console.log(subscriptions.data)
            for (let sub of subscriptions.data) { 
                if (!sub.id) continue;
                
                if (sub.tags && Object.keys(sub.tags).length > 0) {
                    helpers.addResult(results, 0, 'Subscription has tags', location, sub.id);
                } else {
                    helpers.addResult(results, 2, 'Subscription does not have tags', location, sub.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};