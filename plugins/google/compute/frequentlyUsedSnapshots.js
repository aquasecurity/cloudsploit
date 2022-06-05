var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Frequently Used Snapshots',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensure that frequently used disks are created from images instead of snapshots to save networking cost.',
    more_info: 'If you are repeatedly using a snapshot in the same zone to create a persistent disk, save networking costs by using the snapshot once and creating an image of that snapshot. Store this image and use it to create your disk and start a VM instance.',
    link: 'https://cloud.google.com/compute/docs/disks/snapshot-best-practices#prepare_for_consistency',
    recommended_action: 'Ensure that your disk snapshots have images created from them.',
    apis: ['snapshots:list', 'images:list'],
    settings: {
        snapshots_to_check: {
            name: 'Snapshots to Check for Images',
            description: 'Comma separated string of snapshot names.',
            regex: '^([a-zA-Z0-9]+,)+$',
            default: ''
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

        var snapshots_to_check = settings.snapshots_to_check || this.settings.snapshots_to_check.default;
      
        if (!snapshots_to_check.length) return callback(null, results, source);

        snapshots_to_check = snapshots_to_check.split(',');
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

        let images = helpers.addSource(cache, source,
            ['images', 'list', 'global']);

        if (!images) return callback(null, results, source);

        if (images.err || !images.data) {
            helpers.addResult(results, 3, 'Unable to query for images: ' + helpers.addError(images), 'global');
            return callback(null, results, source);
        }

        let snapshotsToCheck = snapshots.data.filter(snapshot => snapshot.name && snapshots_to_check.includes(snapshot.name));
        
        if (!snapshotsToCheck || !snapshotsToCheck.length) {
            helpers.addResult(results, 0, 'Nothing to check', 'global', project);
            return callback(null, results, source);
        }

        snapshotsToCheck.forEach(snapshot => {

            let resource = helpers.createResourceName('snapshot', snapshot.name, project, 'global');

            if (snapshot.id && (images.data && images.data.length && images.data.find(image => image.sourceSnapshotId && image.sourceSnapshotId == snapshot.id))) {
                helpers.addResult(results, 0,
                    'Disk snapshot has an image created', 'global', resource);
            } else {
                helpers.addResult(results, 2,
                    'Disk snapshot does not have an image created', 'global', resource);
            }

        });

        callback(null, results, source);

    }
};