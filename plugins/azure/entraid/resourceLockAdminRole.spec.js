var expect = require('chai').expect;
var resourceLockAdminRole = require('./resourceLockAdminRole.js');

const roleDefinitions = [
    {
        "id": "/subscriptions/123/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111",
        "roleName": "Resource Lock Administrator",
        "roleType": "CustomRole",
        "permissions": [
            {
                "actions": ["Microsoft.Authorization/locks/*"],
                "notActions": []
            }
        ]
    },
    {
        "id": "/subscriptions/123/providers/Microsoft.Authorization/roleDefinitions/22222222-2222-2222-2222-222222222222",
        "roleName": "Owner2",
        "roleType": "CustomRole",
        "permissions": [
            {
                "actions": ["*"],
                "notActions": []
            }
        ]
    },
    {
        "id": "/subscriptions/123/providers/Microsoft.Authorization/roleDefinitions/33333333-3333-3333-3333-333333333333",
        "roleName": "Locks Contributor",
        "roleType": "BuiltInRole",
        "permissions": [
            {
                "actions": ["Microsoft.Authorization/locks/*"],
                "notActions": []
            }
        ]
    }
];

const createCache = (definitions, err) => {
    return {
        roleDefinitions: {
            list: {
                'global': {
                    data: definitions,
                    err: err
                }
            }
        }
    };
};

describe('resourceLockAdminRole', function () {
    describe('run', function () {

        it('should give unknown result if unable to query for role definitions', function (done) {
            const cache = createCache(null, ['error']);
            resourceLockAdminRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for role definitions');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if no role definitions found', function (done) {
            const cache = createCache([], null);
            resourceLockAdminRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No role definitions found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if a custom role for administering resource locks exists', function (done) {
            const cache = createCache([roleDefinitions[0]], null);
            resourceLockAdminRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Custom role for administering resource locks exists');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if only a wildcard custom role grants lock permissions', function (done) {
            const cache = createCache([roleDefinitions[1]], null);
            resourceLockAdminRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No custom role for administering resource locks found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if only a built-in role grants lock permissions', function (done) {
            const cache = createCache([roleDefinitions[2]], null);
            resourceLockAdminRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No custom role for administering resource locks found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});
