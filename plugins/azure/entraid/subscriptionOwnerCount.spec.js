var expect = require('chai').expect;
var subscriptionOwnerCount = require('./subscriptionOwnerCount.js');

const roleDefinitions = [
    {
        "id": "/subscriptions/123/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        "roleName": "Owner",
        "roleType": "BuiltInRole"
    },
    {
        "id": "/subscriptions/123/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
        "roleName": "Contributor",
        "roleType": "BuiltInRole"
    }
];

const ownerAssignment = (name, principalId, scope, principalType) => {
    return {
        "id": '/subscriptions/123/providers/Microsoft.Authorization/roleAssignments/' + name,
        "name": name,
        "roleDefinitionId": "/subscriptions/123/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        "principalId": principalId,
        "principalType": principalType || "User",
        "scope": scope
    };
};

const contributorAssignment = {
    "id": "/subscriptions/123/providers/Microsoft.Authorization/roleAssignments/contrib",
    "name": "contrib",
    "roleDefinitionId": "/subscriptions/123/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
    "principalId": "99999999-9999-9999-9999-999999999999",
    "principalType": "User",
    "scope": "/subscriptions/123"
};

const createCache = (definitions, assignments, definitionsErr, assignmentsErr) => {
    return {
        roleDefinitions: {
            list: {
                'global': {
                    data: definitions,
                    err: definitionsErr
                }
            }
        },
        aad: {
            listRoleAssignments: {
                'global': {
                    data: assignments,
                    err: assignmentsErr
                }
            }
        }
    };
};

describe('subscriptionOwnerCount', function () {
    describe('run', function () {

        it('should give unknown result if unable to query for role definitions', function (done) {
            const cache = createCache(null, [], ['error'], null);
            subscriptionOwnerCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for role definitions');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for role assignments', function (done) {
            const cache = createCache(roleDefinitions, null, null, ['error']);
            subscriptionOwnerCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for role assignments');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if no Owner role definition found', function (done) {
            const cache = createCache([roleDefinitions[1]], [contributorAssignment], null, null);
            subscriptionOwnerCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Owner role definition found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if the number of owners is within range', function (done) {
            const assignments = [
                ownerAssignment('a', '1', '/subscriptions/123'),
                ownerAssignment('b', '2', '/subscriptions/123')
            ];
            const cache = createCache(roleDefinitions, assignments, null, null);
            subscriptionOwnerCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Subscription has 2 owners');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if there are fewer owners than the minimum', function (done) {
            const assignments = [ownerAssignment('a', '1', '/subscriptions/123')];
            const cache = createCache(roleDefinitions, assignments, null, null);
            subscriptionOwnerCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('fewer than the desired minimum');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if there are more owners than the maximum', function (done) {
            const assignments = [
                ownerAssignment('a', '1', '/subscriptions/123'),
                ownerAssignment('b', '2', '/subscriptions/123', 'Group'),
                ownerAssignment('c', '3', '/subscriptions/123', 'ServicePrincipal'),
                ownerAssignment('d', '4', '/providers/Microsoft.Management/managementGroups/mg1')
            ];
            const cache = createCache(roleDefinitions, assignments, null, null);
            subscriptionOwnerCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('more than the desired maximum');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should not count owner assignments scoped below the subscription', function (done) {
            const assignments = [
                ownerAssignment('a', '1', '/subscriptions/123'),
                ownerAssignment('b', '2', '/subscriptions/123'),
                ownerAssignment('c', '3', '/subscriptions/123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/test')
            ];
            const cache = createCache(roleDefinitions, assignments, null, null);
            subscriptionOwnerCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Subscription has 2 owners');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});
