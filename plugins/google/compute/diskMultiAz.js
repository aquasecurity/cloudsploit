var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Disk MultiAz',
    category: 'Compute',
    description: 'Ensure that Compute disks have regional disk replication feature enabled for high availability.',
    more_info: 'Enabling regional disk replication will allow you to force attach a regional persistent disk to another VM instance in a different zone in the same region in case of a zonal outage.',
    link: 'https://cloud.google.com/compute/docs/disks/high-availability-regional-persistent-disk',
    recommended_action: 'Ensure that all Google compute disks have replica zones configured.',
    apis: ['disks:aggregatedList', 'projects:get'],
    settings: {
        disk_result_limit: {
            name: 'Disk MultiAz Result Limit',
            description: 'If the number of results is greater than this value, combine them into one result',
            regex: '^[0-9]*$',
            default: '20',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        var disk_result_limit = parseInt(settings.disk_result_limit || this.settings.disk_result_limit.default);

        let disks = helpers.addSource(cache, source,
            ['disks', 'aggregatedList', ['global']]);

        if (!disks) return callback(null, results, source);

        if (disks.err || !disks.data) {
            helpers.addResult(results, 3, 'Unable to query compute disks', 'global', null, null, disks.err);
            return callback(null, results, source);
        }

        let disksLocation = Object.keys(disks.data);


        disksLocation.forEach(location => {
            let disksInLocation = disks.data[location];

            var noDisks = false;
            var goodDisks = [];
            var badDisks = [];

            if (!disksInLocation || disksInLocation.warning || !disksInLocation.disks || !disksInLocation.disks.length) {
                noDisks = true;
            } else {
                disksInLocation.disks.forEach(disk => {
                    if (!disk.id || !disk.creationTimestamp) return;

                    if (disk && disk.replicaZones && disk.replicaZones.length) {
                        goodDisks.push(disk.name);
                    } else {
                        badDisks.push(disk.name);
                    }
                });
            }
            if (!goodDisks.length && !badDisks.length) noDisks = true;

            if (badDisks.length) {
                if (badDisks.length > disk_result_limit) {
                    helpers.addResult(results, 2,
                        `Regional Disk Replication is not enabled for ${badDisks.length} disks`, location);
                } else {
                    badDisks.forEach(disk => {
                        let resource;
                        if (location.includes('zone')) {
                            resource = helpers.createResourceName('disks', disk, project, 'zone', location.split('/')[1]);
                        } else {
                            resource = helpers.createResourceName('disks', disk, project, location.split('/')[1]);
                        }
                        helpers.addResult(results, 2,
                            'Regional Disk Replication is not enabled for disk', location, resource);
                    });
                }
            }

            if (goodDisks.length) {
                if (goodDisks.length > disk_result_limit) {
                    helpers.addResult(results, 0,
                        `Regional Disk Replication is enabled for ${goodDisks.length} disks`, location);
                } else {
                    goodDisks.forEach(disk => {
                        let resource;
                        if (location.includes('zone')) {
                            resource = helpers.createResourceName('disks', disk, project, 'zone', location.split('/')[1]);
                        } else {
                            resource = helpers.createResourceName('disks', disk, project, location.split('/')[1]);
                        }
                        helpers.addResult(results, 0,
                            'Regional Disk Replication is enabled for disk', location, resource);
                    });
                }
            }

            if (noDisks) {
                helpers.addResult(results, 0, 'No disks found', location, project);
            }
        });
        callback(null, results, source);

    }
};