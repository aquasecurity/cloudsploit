var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Dataset All Users Policy',
    category: 'BigQuery',
    description: 'Ensure that BigQuery datasets do not allow public read, write or delete access.',
    more_info: 'Granting permissions to allUsers or allAuthenticatedUsers allows anyone to access the dataset. Such access might not be desirable if sensitive data is being stored in the dataset.',
    link: 'https://cloud.google.com/bigquery/docs/dataset-access-controls',
    recommended_action: 'Ensure that each dataset is configured so that no member is set to allUsers or allAuthenticatedUsers.',
    apis: ['datasets:list', 'datasets:get', 'projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.datasets, function(region, rcb){
            let datasetsGet = helpers.addSource(cache, source,
                ['datasets', 'get', region]);

            if (!datasetsGet) return rcb();

            if (datasetsGet.err || !datasetsGet.data) {
                helpers.addResult(results, 3, 'Unable to query BigQuery datasets: ' + helpers.addError(datasetsGet), region);
                return rcb();
            }

            if (!datasetsGet.data.length) {
                helpers.addResult(results, 0, 'No BigQuery datasets found', region);
                return rcb();
            }

            async.each(datasetsGet.data, (dataset, dcb) => {
                if (!dataset.id) return dcb();

                let resource = helpers.createResourceName('datasets', dataset.id.split(':')[1] || dataset.id, project);
                var permissionStr = [];
                if (dataset.access) {
                    for (let rolePermission of dataset.access) {
                        if (!rolePermission['role']) continue;
                        for (let property in rolePermission) {

                            if (rolePermission[property] &&
                                (rolePermission[property].toLowerCase() == 'allusers' || rolePermission[property].toLowerCase() == 'allauthenticatedusers')) {
                                permissionStr.push(`${rolePermission['role']} access to ${rolePermission[property]}`);
                            }
                        }
                    }

                    if (permissionStr.length) {
                        helpers.addResult(results, 2,
                            `BigQuery dataset provides ${permissionStr.join(',')}`, region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'BigQuery dataset does not provide public access', region, resource);
                    }
                } else {
                    helpers.addResult(results, 0,
                        'BigQuery dataset does not provide public access', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
