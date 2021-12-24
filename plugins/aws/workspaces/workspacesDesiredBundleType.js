var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'WorkSpaces Desired Bundle Type',
    category: 'WorkSpaces',
    domain: 'Identity Access and Management',
    description: 'Ensure that AWS WorkSpaces bundles are of desired types.',
    more_info: 'A bundle in AWS WorkSpaces defines the hardware and software for AWS WorkSpaces. You can create a WorkSpaces instance using a predefined or custom bundle. Setting a limit to the types that can be used will help you control billing and address internal compliance requirements.',
    recommended_action: 'Ensure that WorkSpaces instances are using desired bundle types',
    link: 'https://docs.aws.amazon.com/workspaces/latest/adminguide/amazon-workspaces-bundles.html',
    apis: ['WorkSpaces:describeWorkspaces'],
    settings: {
        desired_bundle_type: {
            name: 'Workspaces desired bundle type.',
            description: 'Plugin results will become aggregated once this value is breached',
            default: 'STANDARD'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var desired_bundle_type = settings.desired_bundle_type || this.settings.desired_bundle_type.default;

        async.each(regions.workspaces, function(region, rcb){
            var listWorkspaces = helpers.addSource(cache, source, ['workspaces', 'describeWorkspaces', region]);

            if (!listWorkspaces) {
                return rcb();
            }

            if (listWorkspaces.err) {
                helpers.addResult(
                    results, 3, 'Unable to query for WorkSpaces information: ' + helpers.addError(listWorkspaces), region);
                return rcb();
            }

            if (!listWorkspaces.data.length) {
                helpers.addResult(
                    results, 0, 'No Workspaces found.', region);
                return rcb();
            }

            var bundleTypes = listWorkspaces.data.map(({ WorkspaceProperties }) => WorkspaceProperties.ComputeTypeName );
            var currentBundleTypes = [...new Set(bundleTypes)]; // get unique bundle types
            var isDesiredBundleUsed = currentBundleTypes.length === 1 &&  currentBundleTypes[0].toUpperCase() === desired_bundle_type;

            if (!isDesiredBundleUsed){
                helpers.addResult(results, 2, 'Workspaces bundle is not of desired type', region);
            } else {
                helpers.addResult(results, 0, 'Workspaces bundle is of desired type', region);
            }

            return rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
