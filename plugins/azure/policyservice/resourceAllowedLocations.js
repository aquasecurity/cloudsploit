const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Resources Allowed Locations',
    category: 'Azure Policy',
    description: 'Ensures deployed resources and resource groups belong to the list set in the Allowed locations for resource groups policy.',
    more_info: 'Monitoring changes to resources follows Security and Compliance best practices. Being able to track resource location changes adds a level of accountability.',
    recommended_action: '1. Navigate to the Policy service. 2. Select the Assignments blade. 3. Click on Assign Policy. 4. Click to search a Policy definition, search for and select: Allowed locations for resource groups. 5. Under Parameters, select your Allowed locations. 6. Click on Assign.',
    link: 'https://docs.microsoft.com/en-us/azure/governance/policy/assign-policy-portal',
    apis: ['policyAssignments:list', 'resourceGroups:list', 'resources:list'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        let allowedLocationsPolicyAssignment = {};
        let allowedLocations = [];

        let resourceLocationsInUse = [];
        let resourceGroupsLocationsInUse = [];

        let resourceLocationsNotAllowed = '';
        let resourceGroupsLocationsNotAllowed = '';

        for (location in locations.resources) {
            let resource = helpers.addSource(cache, source, ['resources', 'list', locations.resources[location]]);
            if (resource &&
                resource.data &&
                resource.data.length > 0) {
                resourceLocationsInUse.push(locations.resources[location]);
            }
        }

        for (location in locations.resourceGroups) {
            let resourceGroup = helpers.addSource(cache, source, ['resourceGroups', 'list', locations.resourceGroups[location]]);
            if (resourceGroup &&
                resourceGroup.data &&
                resourceGroup.data.length > 0) {
                resourceGroupsLocationsInUse.push(locations.resourceGroups[location]);
            }
        }

        const policyAssignments = helpers.addSource(cache, source,
            ['policyAssignments', 'list', 'global']);

        if (!policyAssignments) return rcb();

        if (policyAssignments.err || !policyAssignments.data) {
            helpers.addResult(results, 3,
                'Unable to query Policy Assignments: ' + helpers.addError(policyAssignments), 'global');
            return callback();
        }

        if (!policyAssignments.data.length) {
            helpers.addResult(results, 1, 'No existing Policy Assignments', 'global');
            return callback();
        }

        if (policyAssignments &&
            policyAssignments.data) {
            allowedLocationsPolicyAssignment = policyAssignments.data.find((policyAssignment) => {
                return policyAssignment.displayName.includes("Allowed locations for resource groups");
            });
        }

        if (allowedLocationsPolicyAssignment &&
            (allowedLocationsPolicyAssignment.parameters == undefined ||
                allowedLocationsPolicyAssignment.parameters.listOfAllowedLocations == undefined ||
                allowedLocationsPolicyAssignment.parameters.listOfAllowedLocations.value == undefined ||
                allowedLocationsPolicyAssignment.parameters.listOfAllowedLocations.value.length == 0)
        ) {
            helpers.addResult(results, 1,
                'No existing allowed locations for resource groups Policy Assignments', 'global');
        } else {
            allowedLocations = allowedLocationsPolicyAssignment.parameters.listOfAllowedLocations.value;
        }

        for (let loc in resourceLocationsInUse) {
            if (allowedLocations.indexOf(resourceGroupsLocationsInUse[loc]) < 0) {
                resourceLocationsNotAllowed += resourceLocationsInUse[loc] + ", ";
            }
        }

        for (let loc in resourceGroupsLocationsInUse) {
            if (allowedLocations.indexOf(resourceGroupsLocationsInUse[loc]) < 0) {
                resourceGroupsLocationsNotAllowed += resourceGroupsLocationsInUse[loc] + ", ";
            }
        }

        if (resourceLocationsNotAllowed != '') {
            helpers.addResult(results, 2,
                'The following un-allowed locations have resources deployed: ' + resourceLocationsNotAllowed.slice(0, -10) + '.', 'global');
        } else {
            helpers.addResult(results, 0,
                'All deployed resources belong to allowed locations per policy.', 'global');
        }

        if (resourceGroupsLocationsNotAllowed != '') {
            helpers.addResult(results, 2,
                'The following un-allowed locations have resource groups deployed: ' + resourceGroupsLocationsNotAllowed.slice(0, -2) + '.', 'global');
        } else {
            helpers.addResult(results, 0,
                'All deployed resource groups belong to allowed locations per policy.', 'global');
        }

        callback(null, results, source);
    }
};