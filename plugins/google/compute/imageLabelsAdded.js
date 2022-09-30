var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Image Labels Added',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensure that all VM disk images have labels added.',
    more_info: 'Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/compute/docs/labeling-resources',
    recommended_action: 'Ensure labels are added to all disk images.',
    apis: ['images:list'],
    
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

        let images = helpers.addSource(cache, source,
            ['images', 'list', 'global']);

        if (!images || images.err || !images.data) {
            helpers.addResult(results, 3, 'Unable to query Disk Images: ' + helpers.addError(images), 'global');
            return callback(null, results, source);
        }

        if (!images.data.length) {
            helpers.addResult(results, 0, 'No Disk Images found', 'global');
            return callback(null, results, source);
        }
        
        images.data.forEach(image => {

            let resource = helpers.createResourceName('images', image.name, project, 'global');

            if (image.labels &&
                Object.keys(image.labels).length) {
                helpers.addResult(results, 0,
                    `${Object.keys(image.labels).length} labels found for disk image`, 'global', resource);
            } else {
                helpers.addResult(results, 2,
                    'Disk image does not have any labels', 'global', resource);
            }

        });
        callback(null, results, source);
    }
};