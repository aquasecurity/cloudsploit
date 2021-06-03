var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Virtual Network Peering',
    category: 'Virtual Networks',
    description: 'Ensures that Virtual Network has peering connection only with a virtual network in whitelisted subscription.',
    more_info: 'Virtual networks should only have peering connections with whitelisted virtual networks to meet your organization\'s security compliance requirements.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-peering-overview',
    recommended_action: 'Delete Peering Connection with the subscription which are not whitelisted',
    apis: ['virtualNetworks:listAll', 'virtualNetworkPeerings:list'],
    settings: {
        whitelisted_peering_subscriptions: {
            name: 'Whitelisted Peering Subscriptions',
            description: 'Subscription Ids for remote virtual networks which should be allowed for peering',
            regex: '/^([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12},?)+$/',
            default: ''
        },
        enable_virtual_network_peering: {
            name: 'Virtual Network Peering',
            description: 'This is an opt-in plugin. This value should be set to true to enable this plugin',
            regex: '^(true|false)$',
            default: 'false'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        const config = {
            peeringEnabled: settings.enable_virtual_network_peering || this.settings.enable_virtual_network_peering.default,
            whiteListedSubscriptions: settings.whitelisted_peering_subscriptions || this.settings.whitelisted_peering_subscriptions.default
        };

        if (config.peeringEnabled === 'false' && !config.whiteListedSubscriptions.length) {
            return callback(null, results, source);
        }

        async.each(locations.virtualNetworks, function(location, rcb){
            var virtualNetworks = helpers.addSource(cache, source, 
                ['virtualNetworks', 'listAll', location]);

            if (!virtualNetworks) return rcb();

            if (virtualNetworks.err || !virtualNetworks.data) {
                helpers.addResult(results, 3, 'Unable to query for Virtual Networks: ' + helpers.addError(virtualNetworks), location);
                return rcb();
            }

            if (!virtualNetworks.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Networks found', location);
                return rcb();
            } 
                
            async.each(virtualNetworks.data, function(virtualNetwork, scb){
                var virtualNetworkPeerings = helpers.addSource(cache, source, 
                    ['virtualNetworkPeerings', 'list', location, virtualNetwork.id]);
    
                if (!virtualNetworkPeerings || virtualNetworkPeerings.err || !virtualNetworkPeerings.data) {
                    helpers.addResult(results, 3, 'Unable to query for Virtual Network Peerings: ' + helpers.addError(virtualNetworkPeerings), location);
                    return scb();
                }
    
                if (!virtualNetworkPeerings.data.length) {
                    helpers.addResult(results, 0, 'No existing Virtual Network Peerings found', location);
                    return scb();
                }

                let unknownSubscriptions = [];
                virtualNetworkPeerings.data.forEach(peering => {
                    let subscriptionId = '';
                    if (peering.remoteVirtualNetwork && peering.remoteVirtualNetwork.id) {
                        subscriptionId = peering.remoteVirtualNetwork.id.split('/')[2];
                        if (!(config.whiteListedSubscriptions && config.whiteListedSubscriptions.includes(subscriptionId))) {
                            unknownSubscriptions.push(subscriptionId);
                        }
                    } 
                });

                if (unknownSubscriptions.length) {
                    helpers.addResult(results, 2, `Vitual network has peering with these unknown subscriptions: ${unknownSubscriptions.join(', ')}`, location, virtualNetwork.id);
                } else {
                    helpers.addResult(results, 0, 'Virtual network is connected with a virtual network in whitelisted subscription', location, virtualNetwork.id);
                }

                scb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};