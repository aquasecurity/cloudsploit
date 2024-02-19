const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Public IP Address DDos Protection',
    category: 'Virtual Networks',
    domain: 'Network Access Control',
    severity: 'Medium',
    description: 'Ensures that DDoS IP Protection is enabled for Microsoft Azure Public IP Addresses',
    more_info: 'Enabling DDoS IP Protection on public IP addresses mitigates potential attacks, differentiating between malicious and legitimate traffic, by interacting with the client, and blocking malicious traffic.',
    recommended_action: 'Enable IP specific DDoS protection for all public IP addresses.',
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
                helpers.addResult(results, 3, 'Unable to query for Public IP Addresses: ' + helpers.addError(publicIpAddresses), location);
                return rcb();
            }

            if (!publicIpAddresses.data.length) {
                helpers.addResult(results, 0, 'No existing Public IP Addresses found', location);
                return rcb();
            }
                
            publicIpAddresses.data.forEach(ipAddress => {
                if (ipAddress.ddosSettings && ipAddress.ddosSettings.protectionMode && ipAddress.ddosSettings.protectionMode.toLowerCase()== 'enabled') {
                    helpers.addResult(results, 0,
                        'Public IP Address has IP specific DDoS protection enabled', location, ipAddress.id);
                } else {
                    helpers.addResult(results, 2,
                        'Public IP Address does not have IP specific DDoS protection enabled', location, ipAddress.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
