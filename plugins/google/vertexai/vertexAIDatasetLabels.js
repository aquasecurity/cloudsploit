var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Vertex AI Dataset Labels Added',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Low',
    description: 'Ensure that all Vertex AI datasets have labels added.',
    more_info: 'Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/resource-manager/docs/labels-overview',
    recommended_action: 'Ensure labels are added to all Vertex AI datasets.',
    apis: ['vertexAI:listDatasets'],
    realtime_triggers: ['aiplatform.DatasetService.CreateDataset', 'aiplatform.DatasetService.UpdateDataset', 'aiplatform.DatasetService.DeleteDataset'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.vertexAI, function(region, rcb){
            let datasets = helpers.addSource(cache, source,
                ['vertexAI', 'listDatasets', region]);

            if (!datasets) return rcb();

            if (datasets.err || !datasets.data) {
                helpers.addResult(results, 3, 'Unable to query Vertex AI datasets', region, null, null, datasets.err);
                return rcb();
            }

            if (!datasets.data.length) {
                helpers.addResult(results, 0, 'No existing Vertex AI datasets found', region);
                return rcb();
            }

            datasets.data.forEach(dataset => {
                if (dataset.labels &&
                    Object.keys(dataset.labels).length) {
                    helpers.addResult(results, 0,
                        `${Object.keys(dataset.labels).length} labels found for Vertex AI dataset`, region, dataset.name);
                } else {
                    helpers.addResult(results, 2,
                        'Vertex AI dataset does not have any labels', region, dataset.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
