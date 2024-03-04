var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Comment Control Enabled',
    category: 'CloudBuild',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensure Comment Control is enabled for all cloud build triggers.',
    more_info: 'Comment control is a configuration which determines if the build will be automatically executed by Github Pull requests trigger. As a security best practice, enable the comment control to ensure that builds are not executed automatically by pull request created by any contributor, and only gets executed when the owner or collaborator comments /gcbrun on the pull request.',
    link: 'https://cloud.google.com/build/docs/automating-builds/create-manage-triggers',
    recommended_action: 'Ensure all cloudbuild triggers have comment control enabled.',
    apis: ['cloudbuild:triggers'],
    realtime_triggers: ['devtools.cloudbuild.CloudBuild.CreateBuildTrigger','devtools.cloudbuild.CloudBuild.UpdateBuildTrigger','devtools.cloudbuild.CloudBuild.DeleteBuildTrigger'],
    
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

                if (trigger.github && trigger.github['pullRequest']) {
                    if (trigger.github['pullRequest'] && trigger.github['pullRequest'].commentControl) {
                        helpers.addResult(results, 0,
                            'Cloud Build trigger has comment control enabled', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Cloud Build trigger does not have comment control enabled', region, resource);
                    }
                } else {
                    helpers.addResult(results, 0,
                        'Cloud Build trigger is not a pull request trigger', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};