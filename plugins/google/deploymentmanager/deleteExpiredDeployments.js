var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Delete Expired Deployments',
    category: 'Deployment Manager',
    description: 'Ensure that Cloud Deployment Manager deployment are deleted after desired number of days from their creation time.',
    more_info: 'Cloud Deployment Manager deployments should be deleted after desired time period from their creation time as determined by your governance rules.',
    link: 'https://cloud.google.com/deployment-manager/docs/deployments/deleting-deployments',
    recommended_action: 'Delete expired deoplyments from Deployment Manager',
    apis: ['deployments:list', 'projects:get'],
    settings: {
        deployments_expiration_time: {
            name: 'Deployments Expiration Time',
            description: 'Number of days from creation of depoyment after which it should be considered expired',
            regex: '^.*$',
            default: false
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        var config = {
            deployments_expiration_time: settings.deployments_expiration_time || this.settings.deployments_expiration_time.default
        };
        
        if (config.deployments_expiration_time === false) return callback(null, results, source);
        
        config.deployments_expiration_time = parseInt(config.deployments_expiration_time);

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.deployments, function(region, rcb){
            let deployments = helpers.addSource(cache, source,
                ['deployments', 'list', region]);

            if (!deployments) return rcb();

            if (deployments.err || !deployments.data) {
                helpers.addResult(results, 3, 'Unable to query Deployment Manager deployments: ' + helpers.addError(deployments), region, null, null, deployments.err);
                return rcb();
            }

            if (!deployments.data.length) {
                helpers.addResult(results, 0, 'No Deployment Manager deployments found', region);
                return rcb();
            }

            deployments.data.forEach(deployment => {
                if (!deployment.name || !deployment.insertTime) return;

                let resource = helpers.createResourceName('deployments', deployment.name, project, 'global');
                let insertTime = deployment.insertTime;
                let now = new Date();

                let difference = Math.round((new Date(now).getTime() - new Date(insertTime).getTime())/(24*60*60*1000));

                if (difference > config.deployments_expiration_time) {
                    helpers.addResult(results, 2,
                        `Deployment Manager deployment was created ${difference} days ago and has expired`, region, resource);    
                } else {
                    helpers.addResult(results, 0,
                        `Deployment Manager deployment was created ${difference} days ago`, region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};