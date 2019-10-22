var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'DNS Security Enabled',
    category: 'DNS',
    description: 'Ensures that DNS Security is enabled on all managed zones.',
    more_info: 'DNS Security is a feature that authenticates all responses to domain name lookups. This prevents attackers from committing DNS hijacking or man in the middle attacks.',
    link: 'https://cloud.google.com/dns/docs/dnssec?hl=en_US&_ga=2.190155811.-922741565.1560964300',
    recommended_action: '1. Enter the Cloud DNS Service. 2. Select the Managed Zone in question. 3. Enable DNSSEC.',
    apis: ['managedZones:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.managedZones, function(region, rcb){
            let managedZones = helpers.addSource(cache, source,
                ['managedZones', 'list', region]);

            if (!managedZones) return rcb();

            if (managedZones.err || !managedZones.data) {
                helpers.addResult(results, 3, 'Unable to query DNS Managed Zones: ' + helpers.addError(managedZones), region);
                return rcb();
            };

            if (!managedZones.data.length) {
                helpers.addResult(results, 0, 'No DNS Managed Zones present', region);
                return rcb();
            }
            var badManagedZones = [];
            managedZones.data.forEach(managedZone => {
               if (!managedZone.dnssecConfig ||
                    (managedZone.dnssecConfig &&
                        (!managedZone.dnssecConfig.state ||
                            (managedZone.dnssecConfig.state &&
                             managedZone.dnssecConfig.state !== 'on')))) {

                   badManagedZones.push(managedZone.name)
               }
            });

            if (badManagedZones.length) {
                var badManagedZonesStr = badManagedZones.join(', ');
                helpers.addResult(results, 2,
                    `The following Managed Zones do not have DNS Security Enabled: ${badManagedZonesStr}`, region);
            } else {
                helpers.addResult(results, 0, 'All DNS Managed Zones have DNS Security Enabled', region);
            }


            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}