var expect = require('chai').expect;
var userAccessAdminRestricted = require('./userAccessAdminRestricted.js');

const roleDefinitions = [
    {
        "id": "/subscriptions/123/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
        "type": "Microsoft.Authorization/roleDefinitions",
        "name": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
        "roleName": "User Access Administrator",
        "roleType": "BuiltInRole"
    },
    {
        "id": "/subscriptions/123/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
        "type": "Microsoft.Authorization/roleDefinitions",
        "name": "b24988ac-6180-42a0-ab88-20f7382dd24c",
        "roleName": "Contributor",
        "roleType": "BuiltInRole"
    }
];

const roleAssignments = [
    {
        "id": "/subscriptions/123/providers/Microsoft.Authorization/roleAssignments/0d25e3ef-59f3-4a95-9c4f-471b97cdeae9",
        "type": "Microsoft.Authorization/roleAssignments",
        "name": "0d25e3ef-59f3-4a95-9c4f-471b97cdeae9",
        "roleDefinitionId": "/subscriptions/123/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
        "principalId": "158a9a70-2e04-4def-829c-239922b43dc8",
        "principalType": "User",
        "scope": "/subscriptions/123"
    },
    {
        "id": "/subscriptions/123/providers/Microsoft.Authorization/roleAssignments/1a35e3ef-59f3-4a95-9c4f-471b97cdeaf0",
        "type": "Microsoft.Authorization/roleAssignments",
        "name": "1a35e3ef-59f3-4a95-9c4f-471b97cdeaf0",
        "roleDefinitionId": "/subscriptions/123/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
        "principalId": "258a9a70-2e04-4def-829c-239922b43dc9",
        "principalType": "User",
        "scope": "/subscriptions/123"
    }
];

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

describe('userAccessAdminRestricted', function () {
    describe('run', function () {

        it('should give unknown result if unable to query for role definitions', function (done) {
            const cache = createCache(null, roleAssignments, ['error'], null);
            userAccessAdminRestricted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for role definitions');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for role assignments', function (done) {
            const cache = createCache(roleDefinitions, null, null, ['error']);
            userAccessAdminRestricted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for role assignments');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if no User Access Administrator role definition found', function (done) {
            const cache = createCache([roleDefinitions[1]], roleAssignments, null, null);
            userAccessAdminRestricted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No User Access Administrator role definition found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if User Access Administrator role is not assigned', function (done) {
            const cache = createCache(roleDefinitions, [roleAssignments[1]], null, null);
            userAccessAdminRestricted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('User Access Administrator role is not assigned');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if User Access Administrator role is assigned', function (done) {
            const cache = createCache(roleDefinitions, roleAssignments, null, null);
            userAccessAdminRestricted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('User Access Administrator role is assigned');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});
