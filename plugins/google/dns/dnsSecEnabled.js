var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'DNS Security Enabled',
    category: 'DNS',
    description: 'Ensures that DNS Security is enabled on all managed zones',
    more_info: 'DNS Security is a feature that authenticates all responses to domain name lookups. This prevents attackers from committing DNS hijacking or man in the middle attacks.',
    link: 'https://cloud.google.com/dns/docs/dnssec',
    recommended_action: 'Ensure DNSSEC is enabled for all managed zones in the cloud DNS service.',
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
                helpers.addResult(results, 3, 'Unable to query DNS managed zones: ' + helpers.addError(managedZones), region);
                return rcb();
            }

            if (!managedZones.data.length) {
                helpers.addResult(results, 0, 'No DNS managed zones found', region);
                return rcb();
            }

            managedZones.data.forEach(managedZone => {
               if (!managedZone.dnssecConfig ||
                    (managedZone.dnssecConfig &&
                        (!managedZone.dnssecConfig.state ||
                            (managedZone.dnssecConfig.state &&
                             managedZone.dnssecConfig.state !== 'on')))) {
                   helpers.addResult(results, 2,
                       `The managed zone does not have DNS security enabled`, region, managedZone.id);
               } else {
                   helpers.addResult(results, 0, 'The managed zone has DNS security enabled', region, managedZone.id);
               }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}