var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Specific Source Branch',
    category: 'CloudBuild',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensure cloud build triggers are configured with specific source branch.',
    more_info: 'When creating cloud build triggers with Push or Pull repository events, ensure you specify the specific source branch within the repository. The regular expression .* will trigger this build for changes on any branch.',
    link: 'https://cloud.google.com/build/docs/automating-builds/create-manage-triggers',
    recommended_action: 'Ensure all cloud build triggers with Push or Pull events have a source branch specified.',
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
                if (trigger.github && (trigger.github['pullRequest'] || trigger.github['push'])) {
                    let triggerType = trigger.github['pullRequest'] ? 'pullRequest' : 'push';
                    let triggerRegex = trigger.github[triggerType].branch || trigger.github[triggerType].tag;
                    if (triggerRegex && triggerRegex !== '.*') {
                        helpers.addResult(results, 0,
                            'Cloud Build trigger has specific source branch or tag', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Cloud Build trigger does not have specific source branch or tag', region, resource);
                    }
                } else {
                    helpers.addResult(results, 0,
                        'Cloud Build trigger is not a push or pull trigger', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};