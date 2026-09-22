var expect = require('chai').expect;
var disabledUserRoleAssignments = require('./disabledUserRoleAssignments.js');

const users = [
    {
        "id": "bb19fc40-d2c4-40a7-a990-9399ee840888",
        "displayName": "Enabled User",
        "userPrincipalName": "enabled@example.com",
        "userType": "Member",
        "accountEnabled": true
    },
    {
        "id": "1d50af91-73f6-45f8-95ff-d21aec6d5d56",
        "displayName": "Disabled User With Roles",
        "userPrincipalName": "disabled1@example.com",
        "userType": "Member",
        "accountEnabled": false
    },
    {
        "id": "8a4c3288-1317-42ef-a8f7-ec60ab455e0a",
        "displayName": "Disabled User Without Roles",
        "userPrincipalName": "disabled2@example.com",
        "userType": "Member",
        "accountEnabled": false
    }
];

const roleAssignments = [
    {
        "id": "/subscriptions/123/providers/Microsoft.Authorization/roleAssignments/0d25e3ef-59f3-4a95-9c4f-471b97cdeae9",
        "name": "0d25e3ef-59f3-4a95-9c4f-471b97cdeae9",
        "roleDefinitionId": "/subscriptions/123/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
        "principalId": "1d50af91-73f6-45f8-95ff-d21aec6d5d56",
        "principalType": "User",
        "scope": "/subscriptions/123"
    }
];

const createCache = (userList, assignments, usersErr, assignmentsErr) => {
    return {
        users: {
            list: {
                'global': {
                    data: userList,
                    err: usersErr
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

describe('disabledUserRoleAssignments', function () {
    describe('run', function () {

        it('should give unknown result if unable to query for users', function (done) {
            const cache = createCache(null, roleAssignments, ['error'], null);
            disabledUserRoleAssignments.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for users');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for role assignments', function (done) {
            const cache = createCache(users, null, null, ['error']);
            disabledUserRoleAssignments.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for role assignments');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if no disabled user accounts found', function (done) {
            const cache = createCache([users[0]], roleAssignments, null, null);
            disabledUserRoleAssignments.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No disabled user accounts found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if disabled user account does not have role assignments', function (done) {
            const cache = createCache([users[2]], roleAssignments, null, null);
            disabledUserRoleAssignments.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Disabled user account does not have role assignments');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if disabled user account has role assignments', function (done) {
            const cache = createCache([users[1]], roleAssignments, null, null);
            disabledUserRoleAssignments.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Disabled user account has role assignments');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});
