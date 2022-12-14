const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'DDoS Standard Protection Enabled',
    category: 'Virtual Networks',
    domain: 'Network Access Control',
    description: 'Ensures that DDoS Standard Protection is enabled for Microsoft Azure Virtual Networks',
    more_info: 'DDoS Protection Standard offers enhanced Distributed Denial-of-Service (DDoS) mitigation capabilities via adaptive tuning, attack alert notifications, and telemetry to protect against the impacts of large DDoS attacks for all the protected resources available within your Azure Virtual Networks.',
    recommended_action: 'Enable DDoS protection for virtual networks',
    link: 'https://azure.microsoft.com/en-us/blog/azure-ddos-protection-for-virtual-networks-generally-available/',
    apis: ['virtualNetworks:listAll'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualNetworks, (location, rcb) => {
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
            
            for (let virtualNetwork of virtualNetworks.data) {
                if (!virtualNetwork.id) continue;

                if (virtualNetwork.tags && Object.entries(virtualNetwork.tags).length > 0){
                    helpers.addResult(results, 0, 'Virtual Network has tags associated', location, virtualNetwork.id);
                } else {
                    helpers.addResult(results, 2, 'Virtual Network does not have tags associated', location, virtualNetwork.id);
                } 

            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
