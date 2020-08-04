var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Multiple Subnets',
    category: 'Virtual Networks',
    description: 'Ensures that Virtual Networks have multiple networks to provide a layered architecture',
    more_info: 'A single network within a Virtual Network increases the risk of a broader blast radius in the event of a compromise.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-vnet-plan-design-arm',
    recommended_action: 'Create multiple networks/subnets in each Virtual Network and change the architecture to take advantage of public and private tiers.',
    apis: ['virtualNetworks:listAll'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

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
            } 
                
            virtualNetworks.data.forEach(virtualNetwork => {
                if (virtualNetwork.subnets &&
                    virtualNetwork.subnets.length > 1) {
                    helpers.addResult(results, 0,
                        'There are ' + virtualNetwork.subnets.length + 
                        ' different subnets used in the Virtual Network', location, virtualNetwork.id);
                } else if (virtualNetwork.subnets.length == 1) {
                    helpers.addResult(results, 2,
                        'Only one subnet in the Virtual Network is used', location, virtualNetwork.id);
                } else {
                    helpers.addResult(results, 0,
                        'The Virtual Network does not have any subnets', location, virtualNetwork.id);
                }
            });
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};