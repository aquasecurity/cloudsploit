var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'DNS Security Signing Algorithm',
    category: 'DNS',
    description: 'Ensures that DNS Security is not using the RSASHA1 algorithm for key or zone signing',
    more_info: 'DNS Security is a feature that authenticates all responses to domain name lookups. This prevents attackers from committing DNS hijacking or man in the middle attacks.',
    link: 'https://cloud.google.com/dns/docs/dnssec',
    recommended_action: 'Ensure that all managed zones using DNSSEC are not using the RSASHA1 algorithm for key or zone signing.',
    apis: ['managedZones:list', 'projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.managedZones, function(region, rcb){
            let managedZones = helpers.addSource(cache, source,
                ['managedZones', 'list', region]);

            if (!managedZones) return rcb();

            if (managedZones.err || !managedZones.data) {
                helpers.addResult(results, 3,
                    'Unable to query DNS managed zones: ' + helpers.addError(managedZones), region, null, null, managedZones.err);
                return rcb();
            }

            if (!managedZones.data.length) {
                helpers.addResult(results, 0, 'No DNS managed zones found', region);
                return rcb();
            }

            managedZones.data.forEach(managedZone => {
                let resource = helpers.createResourceName('zones', managedZone.name, project);

                if (managedZone.dnssecConfig &&
                    managedZone.dnssecConfig.state &&
                    managedZone.dnssecConfig.state === 'on' &&
                    managedZone.dnssecConfig.defaultKeySpecs &&
                    managedZone.dnssecConfig.defaultKeySpecs.length) {
                    managedZone.dnssecConfig.defaultKeySpecs.forEach(keySpec => {
                        if (keySpec.keyType === 'keySigning') {
                            if (keySpec.algorithm.toLowerCase() === 'rsasha1') {
                                helpers.addResult(results, 2,
                                    'RSASHA1 algorithm is being used for key signing', region, resource);
                            } else {
                                helpers.addResult(results, 0,
                                    'RSASHA1 algorithm is not being for key signing', region, resource);
                            }
                        } else if (keySpec.keyType === 'zoneSigning') {
                            if (keySpec.algorithm.toLowerCase() === 'rsasha1') {
                                helpers.addResult(results, 2,
                                    'RSASHA1 algorithm is being used for zone signing', region, resource);
                            } else {
                                helpers.addResult(results, 0,
                                    'RSASHA1 algorithm is not being used for zone signing', region, resource);
                            }
                        }
                    });
                } else {
                    // DNSSEC not enabled
                    helpers.addResult(results, 0,
                        'RSASHA1 algorithm is not being used for zone signing', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};