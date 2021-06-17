var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Dataset All Users Policy',
    category: 'BigQuery',
    description: 'Ensure that BigQuery datasets do not allow public read, write or delete access.',
    more_info: 'Granting permissions to allUsers or allAuthenticatedUsers allows anyone to access the dataset. Such access might not be desirable if sensitive data is being stored in the dataset.',
    link: 'https://cloud.google.com/bigquery/docs/dataset-access-controls',
    recommended_action: 'Ensure that each dataset is configured so that no member is set to allUsers or allAuthenticatedUsers.',
    apis: ['datasets:list', 'datasets:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

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

                var permissionStr = [];
                if (dataset.access) {
                    for (let rolePermission of dataset.access) {
                        for (let property in rolePermission) {
                            if (!rolePermission['role']) continue;

                            if (rolePermission[property] &&
                                (rolePermission[property].toLowerCase() == 'allusers' || rolePermission[property].toLowerCase() == 'allauthenticatedusers')) {
                                permissionStr.push(`${rolePermission['role']} access to ${rolePermission[property]}`);
                            }
                        }
                    }

                    if (permissionStr.length) {
                        helpers.addResult(results, 2,
                            `BigQuery dataset provides ${permissionStr.join(',')}`, region, dataset.id);
                    } else {
                        helpers.addResult(results, 0,
                            'BigQuery dataset does not provide public access', region, dataset.id);
                    }
                } else {
                    helpers.addResult(results, 0,
                        'BigQuery dataset does not provide public access', region, dataset.id);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}