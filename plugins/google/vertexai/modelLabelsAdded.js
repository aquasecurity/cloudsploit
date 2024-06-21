var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Vertex AI Model Labels Added',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Low',
    description: 'Ensure that all Vertex AI models have labels added.',
    more_info: 'Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/vertex-ai/docs/model-registry/model-labels',
    recommended_action: 'Ensure labels are added to all Vertex AI models.',
    realtime_triggers: ['aiplatform.ModelService.UpdateModel', 'aiplatform.ModelService.DeleteModel'],
    apis: ['vertexAI:listModels'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.vertexAI, function(region, rcb){
            let models = helpers.addSource(cache, source,
                ['vertexAI', 'listModels', region]);

            if (!models) return rcb();

            if (models.err || !models.data) {
                helpers.addResult(results, 3, 'Unable to query Vertex AI models', region, null, null, models.err);
                return rcb();
            }

            if (!models.data.length) {
                helpers.addResult(results, 0, 'No existing Vertex AI models found', region);
                return rcb();
            }

            models.data.forEach(model => {
                if (model.labels &&
                    Object.keys(model.labels).length) {
                    helpers.addResult(results, 0,
                        `${Object.keys(model.labels).length} labels found for Vertex AI model`, region, model.name);
                } else {
                    helpers.addResult(results, 2,
                        'Vertex AI model does not have any labels', region, model.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
