var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Dataset Labels Added',
    category: 'BigQuery',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensure that all BigQuery datasets have labels added.',
    more_info: 'Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/bigquery/docs/adding-labels',
    recommended_action: 'Ensure labels are added to all BigQuery datasets.',
    apis: ['datasets:list'],
    realtime_triggers:['bigquery.DatasetService.InsertDataset','datasetservice.update','bigquery.DatasetService.UpdateDataset','datasetservice.delete','bigquery.DatasetService.DeleteDataset','datasetservice.insert'],

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
            let datasets = helpers.addSource(cache, source,
                ['datasets', 'list', region]);

            if (!datasets) return rcb();

            if (datasets.err || !datasets.data) {
                helpers.addResult(results, 3, 'Unable to query BigQuery datasets', region, null, null, datasets.err);
                return rcb();
            }

            if (!datasets.data.length) {
                helpers.addResult(results, 0, 'No BigQuery datasets found', region);
                return rcb();
            }

            datasets.data.forEach(dataset => {
                if (!dataset.id) return;

                let resource = helpers.createResourceName('datasets', dataset.id.split(':')[1] || dataset.id, project);

                if (dataset.labels &&
                    Object.keys(dataset.labels).length) {
                    helpers.addResult(results, 0,
                        `${Object.keys(dataset.labels).length} labels found for BigQuery dataset`, region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'BigQuery dataset does not have any labels', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};