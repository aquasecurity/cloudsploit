var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'DNS Zone Labels Added',
    category: 'DNS',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensure Cloud DNS zones have labels added.',
    more_info: 'Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/dns/docs/zones',
    recommended_action: 'Ensure labels are added for all managed zones in the cloud DNS service.',
    apis: ['managedZones:list'],
    realtime_triggers : ['dns.managedZones.create, dns.managedZones.delete', 'dns.managedZones.patch'],

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
                helpers.addResult(results, 3, 'Unable to query DNS managed zones: ' + helpers.addError(managedZones), region, null, null, managedZones.err);
                return rcb();
            }

            if (!managedZones.data.length) {
                helpers.addResult(results, 0, 'No DNS managed zones found', region);
                return rcb();
            }

            managedZones.data.forEach(managedZone => {
                let resource = helpers.createResourceName('zones', managedZone.name, project);
           
                if (managedZone.labels &&
                    Object.keys(managedZone.labels).length) {
                    helpers.addResult(results, 0,
                        `${Object.keys(managedZone.labels).length} labels found for DNS managed zone`, region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'DNS managed zone does not have any labels', region, resource);
                }

            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};