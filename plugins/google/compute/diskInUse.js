var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Disk In Use',
    category: 'Compute',
    description: 'Ensure that there are no unused Compute disks.',
    more_info: 'Unused Compute disks should be deleted to prevent accidental exposure of data and to avoid unnecessary billing.',
    link: 'https://cloud.google.com/compute/docs/disks',
    recommended_action: 'Delete unused Compute disks.',
    apis: ['disks:list', 'projects:get'],
    settings: {
        disk_result_limit: {
            name: 'Disk In Use Result Limit',
            description: 'If the number of results is greater than this value, combine them into one result',
            regex: '^[0-9]*$',
            default: '20',
        }
    },
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var disk_result_limit = parseInt(settings.disk_result_limit || this.settings.disk_result_limit.default);

        var project = projects.data[0].name;

        async.each(regions.disks, (region, rcb) => {
            var noDisks = [];
            var zones = regions.zones;

            async.each(zones[region], function(zone, zcb) {
                var badDisks = [];
                var goodDisks = [];

                var disks = helpers.addSource(cache, source,
                    ['disks', 'list', zone]);

                if (!disks) return zcb();

                if (disks.err || !disks.data) {
                    helpers.addResult(results, 3,
                        'Unable to query compute disks', region, null, null, disks.err);
                    return zcb();
                }

                if (!disks.data.length) {
                    noDisks.push(zone);
                    return zcb();
                }

                disks.data.forEach(disk => {
                    if (!disk.id || !disk.creationTimestamp) return;

                    if (disk.users && disk.users.length) {
                        goodDisks.push(disk.name);
                    } else {
                        badDisks.push(disk.name);
                    }

                });

                if (!goodDisks.length && !badDisks.length) noDisks.push(zone);

                if (badDisks.length) {
                    if (badDisks.length > disk_result_limit) {
                        helpers.addResult(results, 2,
                            `${badDisks.length} disks are not in use`, region);
                    } else {
                        badDisks.forEach(disk => {
                            let resource = helpers.createResourceName('disks', disk, project, 'zone', zone);
                            helpers.addResult(results, 2,
                                'Disk is not in use', region, resource);
                        });
                    }
                }

                if (goodDisks.length) {
                    if (goodDisks.length > disk_result_limit) {
                        helpers.addResult(results, 0,
                            `${goodDisks.length} disks are in use`, region);
                    } else {
                        goodDisks.forEach(disk => {
                            let resource = helpers.createResourceName('disks', disk, project, 'zone', zone);
                            helpers.addResult(results, 0,
                                'Disk is in use', region, resource);
                        });
                    }
                }
                zcb();
            }, function() {
                if (noDisks.length) {
                    helpers.addResult(results, 0, `No compute disks found in following zones: ${noDisks.join(', ')}`, region);
                }
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
}; 