var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Subscription Tenant Transfer Policy',
    category: 'Subscription',
    domain: 'Management',
    severity: 'Medium',
    description: 'Ensures that subscriptions cannot be moved into or out of the Microsoft Entra tenant.',
    more_info: 'Subscription owners are able to move subscriptions into and out of a Microsoft Entra tenant. A subscription moved into a tenant may sit under a scope where other users hold elevated permissions, and a subscription moved out takes its resources with it. Blocking both transfer directions prevents loss of data and unapproved changes.',
    recommended_action: 'Set Subscription leaving Microsoft Entra tenant and Subscription entering Microsoft Entra tenant to Permit no one from the subscription policy management page.',
    link: 'https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/manage-azure-subscription-policy',
    apis: ['subscriptionPolicies:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.subscriptionPolicies, function(location, rcb) {

            var policies = helpers.addSource(cache, source,
                ['subscriptionPolicies', 'get', location]);

            if (!policies) return rcb();

            if (policies.err || !policies.data) {
                helpers.addResult(results, 3, 'Unable to query for subscription tenant policy: ' + helpers.addError(policies), location);
                return rcb();
            }

            if (!policies.data.length) {
                helpers.addResult(results, 0, 'No existing subscription tenant policy found', location);
                return rcb();
            }

            var policy = policies.data[0];

            if (policy.blockSubscriptionsLeavingTenant && policy.blockSubscriptionsIntoTenant) {
                helpers.addResult(results, 0, 'Subscriptions cannot be moved into or out of the tenant', location, policy.id);
            } else {
                helpers.addResult(results, 2, 'Subscriptions can be moved into or out of the tenant', location, policy.id);
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
