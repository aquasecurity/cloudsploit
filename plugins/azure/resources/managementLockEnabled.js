const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Management Lock Enabled',
    category: 'Resources',
    description: 'Ensures that resources tagged as locked are actually locked',
    more_info: 'Enabling Management Locks ensures that critical resources cannot be inadvertently modified or deleted.',
    recommended_action: '1. Go to Resources. 2. Select the resource. 3. Select the Locks blade under settings on the left side. 4. Add a lock 5. Enter the Tags Blade and  add cloudsploitLock as a tag with true as its value.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-lock-resources',
    apis: ['resources:list', 'managementLocks:listAtSubscriptionLevel'],
    settings: {
        tag: {
            name: 'Management Lock Tag',
            description: 'This tag will be required to indicate that the management lock is enabled.',
            default: 'cloudsploitLock',
            regex: '^.{2,125}$'
        }
    },
    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        const config = {
            tag: settings.tag || this.settings.tag.default
        };

        async.each(locations.managementLocks, (location, rcb) => {
            const managementLocks = helpers.addSource(cache, source, 
                ['managementLocks', 'listAtSubscriptionLevel', location]);

            if (!managementLocks) return rcb();

            if (managementLocks.err || !managementLocks.data) {
                helpers.addResult(results, 3,
                    'Unable to query Management Locks: ' + helpers.addError(managementLocks),location);
                return rcb();
            }

            if (!managementLocks.data.length) {
                helpers.addResult(results, 0, 'No Management Locks', location);
                return rcb();
            }

            var myLockedResourceObj = {};

            managementLocks.data.forEach(managementLock => {
                var myLockedResource = managementLock.id.split('/');
                var resourceLength = myLockedResource.length;

                if (!myLockedResourceObj[myLockedResource[resourceLength - 6]]) {
                    myLockedResourceObj[myLockedResource[resourceLength - 6]] = [];
                }
                myLockedResourceObj[myLockedResource[resourceLength - 6]].push(myLockedResource[resourceLength - 5]);
            });

            async.each(locations.resources, (loc, lcb) => {
                const resources = helpers.addSource(cache, source, 
                    ['resources', 'list', loc]);

                if (!resources) return lcb();

                if (resources.err || !resources.data) {
                    helpers.addResult(results, 3,
                        'Unable to query Resources: ' + helpers.addError(resources),loc);
                    return lcb();
                }

                if (!resources.data.length) return lcb();
                
                async.each(resources.data, (resource, resCb) => {
                    if (!resource.tags) return resCb();
                    if (!resource.tags[config.tag]) return resCb();
                    var myResource = resource.id.split('/');
                    if (myLockedResourceObj[myResource[myResource.length-2]] && 
                        myLockedResourceObj[myResource[myResource.length-2]] == myResource[myResource.length-1]) {
                        helpers.addResult(results, 0,
                            'Resource has Management Lock Enabled', loc, resource.id);
                        return resCb();        
                    } else {
                        helpers.addResult(results, 2,
                            'Resource does not have Management Lock Enabled', loc, resource.id);
                        return resCb();        
                    }

                }, function() {
                    lcb();
                });
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
