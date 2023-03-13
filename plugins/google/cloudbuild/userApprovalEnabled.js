var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'User Approval Enabled',
    category: 'CloudBuild',
    domain: 'Application Integration',
    description: 'Ensure User Approval is enabled for all cloud build triggers.',
    more_info: 'The Approval setting ensures that build gets executed only after being approved by an user who has ‘Cloud Build Approver’ role for the project. As a security best practice, ensure user approval is enabled for all build triggers.',
    link: 'https://cloud.google.com/build/docs/securing-builds/gate-builds-on-approval',
    recommended_action: 'Ensure all cloud build triggers have user approval enabled.',
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

                if (trigger.approvalConfig && trigger.approvalConfig.approvalRequired) {
                    helpers.addResult(results, 0,
                        'Cloud Build trigger has user approval enabled', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Cloud Build trigger does not have user approval enabled', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
