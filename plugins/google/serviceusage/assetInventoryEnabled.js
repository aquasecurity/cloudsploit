var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Asset Inventory Enabled',
    category: 'Service Usage',
    domain: 'Management and Governance',
    description: 'Ensure that Asset Inventory service is enabled for the project.',
    more_info: 'GCP Cloud Asset Inventory enables security analysis, resource change tracking, and compliance auditing for GCP resources and IAM policies.',
    link: 'https://cloud.google.com/asset-inventory/docs',
    recommended_action: 'Enable Asset Inventory service for the GCP project.',
    apis: ['projects:getWithNumber', 'services:listEnabled'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        let projects =  helpers.addSource(cache, source, 
            ['projects', 'getWithNumber', 'global']);

        
        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }
    
        let services = helpers.addSource(cache, source, 
            ['services', 'listEnabled', 'global']);

        if (!services || services.err || !services.data) {
            helpers.addResult(results, 3,
                'Unable to query services for project: ' + helpers.addError(services), 'global', null, null, (services) ? services.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        if (services.data && services.data.length && services.data.find(service => service.name && service.name.includes('cloudasset.googleapis.com'))) {
            helpers.addResult(results, 0,
                'Asset Inventory is enabled for the project', 'global', project);
        } else {
            helpers.addResult(results, 2,
                'Asset Inventory is not enabled for the project', 'global', project);
        }

        return callback(null, results, source);
    }
};
