var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Enable Usage Export',
    category: 'Compute',
    description: 'Ensure that setting is configured to export Compute instances usage to Cloud Storage bucket.',
    link: 'https://cloud.google.com/compute/docs/logging/usage-export',
    more_info: 'Compute Engine lets you export detailed reports that provide information about the lifetime and usage of your Compute Engine resources to a Google Cloud Storage bucket using the usage export feature.',
    recommended_action: 'Ensure that Enable Usage Export setting is configured for your GCP project.',
    apis: ['projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0];

        let resource = helpers.createResourceName('projects', project.name);
        
        if (project.usageExportLocation && project.usageExportLocation.bucketName) {
            helpers.addResult(results, 0, 'Enable Usage Export is configured for project', 'global', resource);            
        } else {
            helpers.addResult(results, 2, 'Enable Usage Export is not configured for project', 'global', resource);            
        }

        return callback(null, results, source);

       
    }
};
