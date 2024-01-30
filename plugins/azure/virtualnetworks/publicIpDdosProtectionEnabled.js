const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Public Ip Address DDos Protection',
    category: 'Public Ip Addresses',
    domain: 'Network Access Control',
    description: 'Ensures that DDoS Ip Protection is enabled for Microsoft Azure Public Ip Addresses',
    more_info: 'Enabling DDoS IP Protection on public ip adresses mitigates potential attacks, differentiating between malicious and legitimate traffic, by interacting with the client, and blocking malicious traffic.',
    recommended_action: 'Enable DDoS ip protection for Public Ip Addresses',
    link: 'https://learn.microsoft.com/en-us/azure/ddos-protection/manage-ddos-ip-protection-portal',
    apis: ['publicIpAddresses:list'],
    realtime_triggers: ['microsoftnetwork:publicipaddresses:write','microsoftnetwork:publicipaddresses:delete'],
    
    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.publicIpAddresses, (location, rcb) => {
            var publicIpAddresses = helpers.addSource(cache, source, 
                ['publicIpAddresses', 'list', location]);

            if (!publicIpAddresses) return rcb();

            if (publicIpAddresses.err || !publicIpAddresses.data) {
                helpers.addResult(results, 3, 'Unable to query for Public Ip Addresses: ' + helpers.addError(publicIpAddresses), location);
                return rcb();
            }

            if (!publicIpAddresses.data.length) {
                helpers.addResult(results, 0, 'No existing Public Ip Addresses found', location);
                return rcb();
            }
                
            publicIpAddresses.data.forEach(ipAddress => {
                if (ipAddress.ddosSettings && ipAddress.ddosSettings.protectionMode && ipAddress.ddosSettings.protectionMode.toLowerCase()== 'enabled') {
                    helpers.addResult(results, 0,
                        'Public Ip Address has DDoS ip protection enabled', location, ipAddress.id);
                } else {
                    helpers.addResult(results, 2,
                        'Public Ip Address does not have DDoS ip protection enabled', location, ipAddress.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
