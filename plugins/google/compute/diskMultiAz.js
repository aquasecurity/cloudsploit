var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Disk MultiAz',
    category: 'Compute',
    domain: 'Compute',
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
        var regions = helpers.regions();

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

        regions.all_regions.forEach(region => {
            var noDisks = [];
            var zones = regions.zones;
            var badDisks = [];
            var goodDisks = [];
            let disksInRegion = [];
            let regionData = disks.data[`regions/${region}`];

            if (regionData && regionData['disks'] && regionData['disks'].length) {
                disksInRegion = disks.data[`regions/${region}`].disks.map(disk => { return {...disk, locationType: 'region', location: region};});
            }
        
            zones[region].forEach(zone => {
                let disksInZone = [];
                let zoneData = disks.data[`zones/${zone}`];
               
                if (zoneData && zoneData['disks'] && zoneData['disks'].length) {
                    disksInZone = disks.data[`zones/${zone}`].disks.map(disk => { return {...disk, locationType: 'zone', location: zone};});
                }

                if (!disksInZone.length) {
                    noDisks.push(zone);
                }

                disksInRegion = disksInRegion.concat(disksInZone);
            });

            disksInRegion.forEach(disk => {
                if (!disk.id || !disk.creationTimestamp) return;
        
                if (disk && disk.replicaZones && disk.replicaZones.length) {
                    goodDisks.push(disk);
                } else {
                    badDisks.push(disk);
                }
            });

            if (badDisks.length) {
                if (badDisks.length > disk_result_limit) {
                    helpers.addResult(results, 2,
                        `Regional Disk Replication is not enabled for ${badDisks.length} disks`, region);
                } else {
                    badDisks.forEach(disk => {
                        let resource = helpers.createResourceName('disks', disk.name, project, disk.locationType, disk.location);
                        helpers.addResult(results, 2,
                            'Regional Disk Replication is not enabled for disk', region, resource);
                    });
                }
            }
        
            if (goodDisks.length) {
                if (goodDisks.length > disk_result_limit) {
                    helpers.addResult(results, 0,
                        `Regional Disk Replication is enabled for ${goodDisks.length} disks`, region);
                } else {
                    goodDisks.forEach(disk => {
                        let resource = helpers.createResourceName('disks', disk.name, project, disk.locationType, disk.location);
                        helpers.addResult(results, 0,
                            'Regional Disk Replication is enabled for disk', region, resource);
                    });
                }
            } 

            if (noDisks.length) {
                if (!goodDisks.length && !badDisks.length) {
                    helpers.addResult(results, 0, 'No compute disks found in the region', region);
                } else {
                    helpers.addResult(results, 0, `No compute disks found in following zones: ${noDisks.join(', ')}`, region);
                }
            }
        });
        callback(null, results, source);
    }
};

