var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Event Hub Public Access',
    category: 'Event Hubs',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensures Microsoft Azure Event Hubs are not publicly accessible.',
    more_info: 'Configuring Azure Event Hubs namespace with public access poses a security risk. To mitigate this risk, it is advisable to limit access by allowing connections only from specific IP addresses or private networks.',
    recommended_action: 'Ensure that public network access is disabled for each Event Hubs namespace.',
    link: 'https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-ip-filtering#configure-public-access-when-creating-a-namespace',
    apis: ['eventHub:listEventHub', 'eventHub:listNetworkRuleSet'],
    realtime_triggers: ['microsofteventhub:namespaces:write', 'microsofteventhub:namespaces:delete', 'microsofteventhub:namespaces:networkrulesets:write'],
    settings: {
        check_selected_networks: {
            name: 'Check Selected Networks',
            description: 'Whether the IP addresses are configured',
            regex: '^(true|false)$',
            default: false,
        }
    },
    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        let config = {
            check_selected_networks: settings.check_selected_networks || this.settings.check_selected_networks.default
        };

        async.each(locations.eventHub, function (location, rcb) {
            var eventHubs = helpers.addSource(cache, source,
                ['eventHub', 'listEventHub', location]);

            if (!eventHubs) return rcb();

            if (eventHubs.err || !eventHubs.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Event Hubs namespaces: ' + helpers.addError(eventHubs), location);
                return rcb();
            }

            if (!eventHubs.data.length) {
                helpers.addResult(results, 0, 'No Event Hubs namespaces found', location);
                return rcb();
            }

            for (let eventHub of eventHubs.data) {
                if (!eventHub.id) continue;

                if (eventHub.sku && eventHub.sku.tier && eventHub.sku.tier.toLowerCase() === 'basic') {
                    helpers.addResult(results, 0,
                        'Event Hubs namespace tier is basic', location, eventHub.id);
                } else {
                    if (eventHub.publicNetworkAccess && eventHub.publicNetworkAccess.toLowerCase() === 'enabled') {
                        if (config.check_selected_networks) {
                            const listNetworkRuleSet = helpers.addSource(cache, source,
                                ['eventHub', 'listNetworkRuleSet', eventHub.id, location]);
                            if (!listNetworkRuleSet || listNetworkRuleSet.err || !listNetworkRuleSet.data) {
                                helpers.addResult(results, 3,
                                    'Unable to query Event Hubs network rule set: ' + helpers.addError(listNetworkRuleSet), location, eventHub.id);
                                continue;
                            }
                            if ((listNetworkRuleSet.data.ipRules && listNetworkRuleSet.data.ipRules.length > 0) || (listNetworkRuleSet.data.virtualNetworkRules && listNetworkRuleSet.data.virtualNetworkRules.length > 0)) {
                                helpers.addResult(results, 2,
                                    'Event Hubs namespace is publicly accessible', location, eventHub.id);
                            } else {
                                helpers.addResult(results, 0,
                                    'Event Hubs namespace is not publicly accessible', location, eventHub.id);
                            }
                        } else {
                            helpers.addResult(results, 2,
                                'Event Hubs namespace is publicly accessible', location, eventHub.id);
                        }
                    } else {
                        helpers.addResult(results, 0,
                            'Event Hubs namespace is not publicly accessible', location, eventHub.id);
                    }
                }
            }
            rcb();
        }, function () {
            callback(null, results, source);
        });
    }
};
