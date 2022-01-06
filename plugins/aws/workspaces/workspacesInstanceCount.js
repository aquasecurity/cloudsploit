var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'WorkSpaces Instance Count',
    category: 'WorkSpaces',
    domain: 'Identity Access and Management',
    description: 'Ensure that the number of Amazon WorkSpaces provisioned in your AWS account has not reached set limit.',
    more_info: 'In order to manage your WorkSpaces compute resources efficiently and prevent unexpected charges on your AWS bill, monitor and configure limits for the maximum number of WorkSpaces instances provisioned within your AWS account.',
    recommended_action: 'Ensure that number of WorkSpaces created within your AWS account is within set limit',
    link: 'https://docs.aws.amazon.com/workspaces/latest/adminguide/workspaces-limits.html',
    apis: ['WorkSpaces:describeWorkspaces'],
    settings: {
        workspace_instance_limit: {
            name: 'Limit for the number of WorkSpaces instances.',
            description: 'Desired threshold for the number of WorkSpace instances in AWS account.',
            regex: '/[0-9]+/',
            default: '50'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var workspace_instance_limit = parseInt(settings.workspace_instance_limit || this.settings.workspace_instance_limit.default);
        var instanceCount = 0;

        async.each(regions.workspaces, function(region, rcb){
            var listWorkspaces = helpers.addSource(cache, source, ['workspaces', 'describeWorkspaces', region]);

            if (!listWorkspaces) {
                return rcb();
            }

            if (!listWorkspaces || listWorkspaces.err || !listWorkspaces.data) {
                helpers.addResult(results, 3,
                    'Unable to list Workspaces: ' + helpers.addError(listWorkspaces), region);
                return rcb();
            }
            
            if (!listWorkspaces.data.length) {
                helpers.addResult(results, 0,
                    'No WorkSpaces instances found', region);
                return rcb();
            }

            instanceCount += listWorkspaces.data.length;

            rcb();
        }, function(){
            if (instanceCount > workspace_instance_limit){
                helpers.addResult(results, 2, `WorkSpaces Instance count is ${instanceCount} of ${workspace_instance_limit} desired threshold`, 'global');
            } else {
                helpers.addResult(results, 0, `WorkSpaces Instance count is ${instanceCount} of ${workspace_instance_limit} desired threshold`, 'global');
            }

            callback(null, results, source);
        });
    }
};
