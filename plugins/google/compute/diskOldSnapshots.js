var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Disk Old Snapshots',
    category: 'Compute',
    description: 'Ensure that Compute disk snapshots are deleted after defined time period.',
    more_info: 'To optimize storage costs, make sure that there are no old disk snapshots in your GCP project.',
    link: 'https://cloud.google.com/compute/docs/disks/create-snapshots',
    recommended_action: 'Ensure that there are no snapshots older than specified number of days.',
    apis: ['snapshots:list', 'projects:get'],
    settings: {
        compute_disk_snapshot_life: {
            name: 'Disk Snapshot Result Life',
            description: 'Disk Snapshot will FAIL if its creation date is before this number of days in the past',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '30',
        },
        snapshot_result_limit: {
            name: 'Disk Snapshot Result Limit',
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

        var snapshot_result_limit = parseInt(settings.snapshot_result_limit || this.settings.snapshot_result_limit.default);

        var number_of_days = parseInt(settings.compute_disk_snapshot_life || this.settings.compute_disk_snapshot_life.default);
       
        var project = projects.data[0].name;

        let snapshots = helpers.addSource(cache, source,
            ['snapshots', 'list', 'global']);

        if (!snapshots) return callback(null, results, source);

        if (snapshots.err || !snapshots.data) {
            helpers.addResult(results, 3, 'Unable to query for disk snapshots: ' + helpers.addError(snapshots), 'global');
            return callback(null, results, source);
        }
        if (!snapshots.data.length) {
            helpers.addResult(results, 0, 'No disk snapshots found', 'global');
            return callback(null, results, source);
        }

        let oldSnapshots = [];
        let newSnapshots = [];
        
        snapshots.data.forEach(snapshot => {
            if (snapshot.creationTimestamp) {

                const daysSinceCreation = helpers.daysBetween(new Date(), new Date(snapshot.creationTimestamp));

                if (daysSinceCreation > number_of_days) {
                    oldSnapshots.push(snapshot.name);
                } else {
                    newSnapshots.push(snapshot.name);
                }
            }
        });

        if (oldSnapshots.length) {
            if (oldSnapshots.length > snapshot_result_limit) {
                helpers.addResult(results, 2,
                    `More than ${oldSnapshots.length} disk snapshots are older than ${number_of_days} days`, 'global');
            } else {
                oldSnapshots.forEach(snapshot => {
                    let resource = helpers.createResourceName('snapshot', snapshot , project, 'global');
                    helpers.addResult(results, 2,
                        `Disk snapshot is more than ${number_of_days} days old`, 'global', resource);
                });
            }
        }

        if (newSnapshots.length) {
            if (newSnapshots.length > snapshot_result_limit) {
                helpers.addResult(results, 0,
                    `More than ${newSnapshots.length} are newer than ${number_of_days} days`, 'global');
            } else {
                newSnapshots.forEach(snapshot => {
                    let resource = helpers.createResourceName('snapshots', snapshot , project, 'global');
                    helpers.addResult(results, 0,
                        `Disk snapshot is less than ${number_of_days} days old`, 'global', resource);
                });
            }
        }

        if (!oldSnapshots.length && !newSnapshots.length) {
            helpers.addResult(results, 0, 'No snapshots found in the project', 'global', project);
        }

        callback(null, results, source);

    }
};