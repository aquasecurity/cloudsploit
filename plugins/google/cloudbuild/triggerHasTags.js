var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Trigger Has Tags',
    category: 'CloudBuild',
    domain: 'Application Integration',
    description: 'Ensure cloud build triggers have tags.',
    more_info: 'Tags are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/build/docs/automating-builds/create-manage-triggers',
    recommended_action: 'Ensure all cloudbuild triggers have tags added.',
    apis: ['cloudbuild:triggers'],

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

        async.each(regions.cloudbuild, function(region, rcb){
            let triggers = helpers.addSource(cache, source,
                ['cloudbuild' ,'triggers', region]);

            if (!triggers) return rcb();

            if (triggers.err || !triggers.data) {
                helpers.addResult(results, 3, 'Unable to query Cloud Build triggers', region, null, null, triggers.err);
                return rcb();
            }

            if (!triggers.data.length) {
                helpers.addResult(results, 0, 'No Cloud Build triggers found', region);
                return rcb();
            }


            triggers.data.forEach(trigger => {
                let resource = helpers.createResourceName('triggers', trigger.name, project, 'location', region);

                if (trigger.tags && trigger.tags.length) {
                    helpers.addResult(results, 0,
                        `${trigger.tags.length} tags found for Cloud Build trigger`, region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Cloud Build trigger does not have any tags', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};