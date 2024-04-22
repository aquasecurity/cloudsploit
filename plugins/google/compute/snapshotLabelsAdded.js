var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Snapshot Labels Added',
    category: 'Compute',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that Compute disk snapshots have labels added.',
    more_info: 'Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/compute/docs/labeling-resources',
    recommended_action: 'Ensure labels are added to all Compute disk snapshots.',
    apis: ['snapshots:list'],
    realtime_triggers: ['compute.snapshots.insert', 'compute.snapshots.delete', 'compute.snapshots.setLabels'],

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

        var snapshotsFound = false;

        snapshots.data.forEach(snapshot => {
            if (snapshot.creationTimestamp) {

                snapshotsFound = true;
                let resource = helpers.createResourceName('snapshot', snapshot.name, project, 'global');

                if (snapshot.labels &&
                    Object.keys(snapshot.labels).length) {
                    helpers.addResult(results, 0,
                        `${Object.keys(snapshot.labels).length} labels found for compute disk snapshot`, 'global', resource);
                } else {
                    helpers.addResult(results, 2,
                        'Compute disk snapshot does not have any labels', 'global', resource);
                }

            }
        });

        if (!snapshotsFound) {
            helpers.addResult(results, 0, 'No snapshots found in the project', 'global', project);
        }

        callback(null, results, source);

    }
};