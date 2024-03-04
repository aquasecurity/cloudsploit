var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Disk Labels Added',
    category: 'Compute',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that all Compute Disks have labels added.',
    more_info: 'Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/compute/docs/labeling-resources',
    recommended_action: 'Ensure labels are added to all Compute Disks.',
    apis: ['disks:aggregatedList'],
    realtime_triggers: ['compute.disks.insert','compute.disks.delete', 'compute.disks.setlabels'],
    
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

        let disks = helpers.addSource(cache, source,
            ['disks', 'aggregatedList', ['global']]);

        if (!disks) return callback(null, results, source);

        if (disks.err || !disks.data) {
            helpers.addResult(results, 3, 'Unable to query compute disks', 'global', null, null, disks.err);
            return callback(null, results, source);
        }

        disks.data.forEach(diskData => {
            regions.all_regions.forEach(region => {
                var noDisks = [];
                var zones = regions.zones;
                let disksInRegion = [];
                let regionData = diskData[`regions/${region}`];
    
                if (regionData && regionData['disks'] && regionData['disks'].length) {
                    disksInRegion = diskData[`regions/${region}`].disks.map(disk => { return {...disk, locationType: 'region', location: region};});
                }
            
                zones[region].forEach(zone => {
                    let disksInZone = [];
                    let zoneData = diskData[`zones/${zone}`];
                   
                    if (zoneData && zoneData['disks'] && zoneData['disks'].length) {
                        disksInZone = diskData[`zones/${zone}`].disks.map(disk => { return {...disk, locationType: 'zone', location: zone};});
                    }
    
                    if (!disksInZone.length) {
                        noDisks.push(zone);
                    }
    
                    disksInRegion = disksInRegion.concat(disksInZone);
                });
    
                disksInRegion.forEach(disk => {
                    if (!disk.id || !disk.creationTimestamp) return;
    
                    let resource = helpers.createResourceName('disks', disk.name, project, disk.locationType, disk.location);
    
                    if (disk.labels &&
                        Object.keys(disk.labels).length) {
                        helpers.addResult(results, 0,
                            `${Object.keys(disk.labels).length} labels found for compute disk`, region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Compute disk does not have any labels', region, resource);
                    }
    
                });
    
                if (noDisks.length) {
                    helpers.addResult(results, 0, `No compute disks found in following zones: ${noDisks.join(', ')}`, region);
                }
            });
        });
       
        callback(null, results, source);
    }
};