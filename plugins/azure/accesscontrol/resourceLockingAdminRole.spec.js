var expect = require('chai').expect;
var resourceLockingAdminRole = require('./resourceLockingAdminRole');

const roleDefinitions = [
    {
        id: '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/providers/Microsoft.Authorization/roleDefinitions/df35608f-8e9a-443b-87e1-212a14ed664e',
        type: 'Microsoft.Authorization/roleDefinitions',
        name: 'df35608f-8e9a-443b-87e1-212a14ed664e',
        roleName: 'Aqua Cloud',
        roleType: 'CustomRole',
        description: '',
        assignableScopes: [ '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e' ],
        permissions: [{
            actions: [
              'Microsoft.Advisor/recommendations/read',
              'Microsoft.Authorization/*/read',
              'Microsoft.Authorization/policyAssignments/read',
              'Microsoft.Authorization/policySetDefinitions/read',
              'Microsoft.Compute/disks/read'
            ],
            notActions: []
        }],
        createdOn: '2020-06-17T16:34:47.0443409Z',
        updatedOn: '2020-06-17T16:34:47.0443409Z',
        createdBy: '3fc56a96-2173-49c5-b915-08886e7fafa3',
        updatedBy: '3fc56a96-2173-49c5-b915-08886e7fafa3'
      },
      {
        id: '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/providers/Microsoft.Authorization/roleDefinitions/967d4523-3d6e-53b6-a7b9-c4fff5f6c779',
        type: 'Microsoft.Authorization/roleDefinitions',
        name: '967d4523-3d6e-53b6-a7b9-c4fff5f6c779',
        roleName: 'test111',
        roleType: 'CustomRole',
        description: 'tewsart123423r',
        assignableScopes: [
          '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/deleteASAP'
        ],
        permissions: [{
            actions: [
              'Microsoft.Advisor/recommendations/read',
              'Microsoft.Authorization/locks/read',
              'Microsoft.Authorization/locks/write',
              'Microsoft.Authorization/locks/delete'
            ],
            notActions: []
        }],
        createdOn: '2020-06-17T18:34:37.9137978Z',
        updatedOn: '2020-06-17T18:34:37.9137978Z',
        createdBy: '3fc56a96-2173-49c5-b915-08886e7fafa3',
        updatedBy: '3fc56a96-2173-49c5-b915-08886e7fafa3'
      }
];

const createCache = (err, data) => {
    return {
        roleDefinitions: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('resourceLockingAdminRole', function() {
    describe('run', function() {
        it('should give passing result if no role definitions', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No role definitions found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(null, []);
            resourceLockingAdminRole.run(cache, {}, callback);
        });

        it('should give failing result if permissions to create custom owner roles enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Resource locking administrator role is not enabled for current subscription');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(null, [roleDefinitions[0]]);
            resourceLockingAdminRole.run(cache, {}, callback);
        });

        it('should give passing result if there are no permissions to create custom owner roles enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Resource locking administrator role is enabled for current subscription');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(null, [roleDefinitions[1]]);
            resourceLockingAdminRole.run(cache, {}, callback);
        })
    })
});
