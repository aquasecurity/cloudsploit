const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Resource Location Matches Resource Group',
    category: 'Azure Policy',
    description: 'Ensures a policy is configured to audit that deployed resource locations match their resource group locations',
    more_info: 'Using Azure Policy to monitor resource location compliance helps ensure that new resources are not launched into locations that do not match their resource group.',
    recommended_action: 'Enable the built-in Azure Policy definition: Audit resource location matches resource group location',
    link: 'https://docs.microsoft.com/en-us/azure/governance/policy/assign-policy-portal',
    apis: ['policyAssignments:list', 'resourceGroups:list', 'resources:list'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        let resourceLocationPolicyAssignment = {};
        let allowedLocations = [];

        let resourceGroups = [];

        let resourceLocationsNotMatched = '';

        function getResourceGroup(resource){
            let resourceGroupInitIndex = resource.id.indexOf('/resourceGroups/') > -1 ? resource.id.indexOf('/resourceGroups/') : resource.id.indexOf('/resourcegroups/');
            var resourceGroupIndex = resourceGroupInitIndex + '/resourceGroups/'.length;
            var resourceGroupEndIndex = resource.id.indexOf('/', resourceGroupIndex);
            var resourceGroupName = resource.id.substring(resourceGroupIndex, resourceGroupEndIndex);
            var resourceGroupId = resource.id.substring(0, resourceGroupEndIndex);

            resource.resourceGroupName = resourceGroupName;
            resource.resourceGroupId = resourceGroupId;
        }

        function getResourceGroupLocation(resource) {
            return resourceGroups.find((resourceGroup) => {
                return resourceGroup.name.toLowerCase()==resource.resourceGroupName.toLowerCase();
            });
        }

        for (location in locations.resourceGroups) {
            let resourceGroupsList = helpers.addSource(cache, source, ['resourceGroups', 'list', locations.resourceGroups[location]]);
            if (resourceGroupsList &&
                resourceGroupsList.data &&
                resourceGroupsList.data.length > 0) {
                for (r in resourceGroupsList.data){
                    resourceGroups.push(resourceGroupsList.data[r]);
                }
            }
        }

        const policyAssignments = helpers.addSource(cache, source,
            ['policyAssignments', 'list', 'global']);

        if (!policyAssignments) return rcb();

        if (!policyAssignments || policyAssignments.err || !policyAssignments.data) {
            helpers.addResult(results, 3,
                'Unable to query for Policy Assignments: ' + helpers.addError(policyAssignments), 'global');
            return callback();
        }

        if (!policyAssignments.data.length) {
            helpers.addResult(results, 2, 'No existing Policy Assignments found', 'global');
            return callback();
        }

        if (policyAssignments &&
            policyAssignments.data) {
            resourceLocationPolicyAssignment = policyAssignments.data.find((policyAssignment) => {
                if (policyAssignment.displayName) return policyAssignment.displayName.includes("Audit resource location matches resource group location");
            });
        }

        if (resourceLocationPolicyAssignment) {
            for (location in locations.resources) {
                let resources = helpers.addSource(cache, source, ['resources', 'list', locations.resources[location]]);

                if (resources &&
                    resources.data &&
                    resources.data.length > 0) {
                    for (r in resources.data) {
                        getResourceGroup(resources.data[r]);
                        var resG = getResourceGroupLocation(resources.data[r]);
                        resources.data[r].resourceGroupLocation = resG.location;
                        if (resources.data[r].resourceGroupLocation != resources.data[r].location && resources.data[r].location!='global') {
                            helpers.addResult(results, 2,
                                "The resource: " + resources.data[r].name + " is located at: " + resources.data[r].location + " not matching the resource group: " + resources.data[r].resourceGroupName + " located at: " + resources.data[r].resourceGroupLocation, resources.data[r].location, resources.data[r].id);
                        } else if (resources.data[r].location!='global') {
                            helpers.addResult(results, 0,
                                "The resource: " + resources.data[r].name + " is located at: " + resources.data[r].location + " matching the resource group location", resources.data[r].location, resources.data[r].id);
                        }
                    }
                }
            }

            helpers.addResult(results, 0,
                'The policy to audit matching resource location to resource group location is assigned', 'global');
        } else {
            helpers.addResult(results, 2,
                'No existing assignment for the resource location matches resource group location policy', 'global');
        }

        callback(null, results, source);
    }
};