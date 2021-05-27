var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Cross Subscription Network Peering',
    category: 'Virtual Networks',
    description: 'Ensures that Virtual Network is not connected with a virtual network in whitelisted subscription.',
    more_info: 'To meet your organization\'s security compliance requirements.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-peering-overview',
    recommended_action: 'Delete Peering Connection with the subscription which are not whitelisted',
    apis: ['virtualNetworks:listAll', 'virtualNetworkPeerings:list'],
    settings: {
        peering_denied_subscriptions: {
            name: 'Subcriptions, Virtual Network Peering Denied for',
            description: 'Subscription Ids, for which Virtual Network Peering in not allowed with current subscription networks',
            regex: '/^([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12},?)+$/',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        const config = {
            subscriptions: settings.peering_denied_subscriptions || this.settings.peering_denied_subscriptions.default
        };

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

                virtualNetworkPeerings.data.forEach(peering => {
                    let deniedSubscriptions = config.subscriptions.split(',');
                    let subscriptionId = '';
                    if (peering.remoteVirtualNetwork && peering.remoteVirtualNetwork.id) {
                        subscriptionId = peering.remoteVirtualNetwork.id.split('/')[2];
                    }

                    if (deniedSubscriptions.length && deniedSubscriptions.includes(subscriptionId)) {
                        helpers.addResult(results, 2, 'Virtual network is not connected with a virtual network in whitelisted subscription', location, virtualNetwork.id);
                    } else {
                        helpers.addResult(results, 0, 'Virtual network is connected with a virtual network in whitelisted subscription', location, virtualNetwork.id);
                    }
                });

                scb();
            }, function(){
                rcb(null, results, source);
            });
        }, function(){
            callback(null, results, source);
        });
    }
};