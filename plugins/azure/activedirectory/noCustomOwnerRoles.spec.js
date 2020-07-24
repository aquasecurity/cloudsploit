var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./noCustomOwnerRoles');

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

describe('noCustomOwnerRoles', function() {
    describe('run', function() {
        it('should give passing result if no role definitions', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No role definitions found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            auth.run(cache, {}, callback);
        });

        it('should give failing result if permissions to create custom owner roles enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Permission to create custom owner roles is not enabled');
                expect(results[0].region).to.equal('global');
                expect(results[1].status).to.equal(2);
                expect(results[1].message).to.include('Permission to create custom owner roles enabled');
                expect(results[1].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/providers/Microsoft.Authorization/roleDefinitions/8311e382-0749-4cb8-b61a-304f252e45ec",
                        "name": "8311e382-0749-4cb8-b61a-304f252e45ec",
                        "type": "Microsoft.Authorization/roleDefinitions",
                        "roleName": "AcrPush",
                        "description": "acr push",
                        "roleType": "CustomRole",
                        "permissions": [
                            {
                                "actions": [
                                    "Microsoft.ContainerRegistry/registries/pull/read",
                                    "Microsoft.ContainerRegistry/registries/push/write"
                                ],
                                "notActions": [],
                                "dataActions": [],
                                "notDataActions": []
                            }
                        ],
                        "assignableScopes": [
                            "/"
                        ],
                        "location": "global"
                    },
                    {
                        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/providers/Microsoft.Authorization/roleDefinitions/8311e382-0749-4cb8-b61a-304f252e45ec",
                        "name": "8311e382-0749-4cb8-b61a-304f252e45ec",
                        "type": "Microsoft.Authorization/roleDefinitions",
                        "roleName": "AcrPush",
                        "description": "acr push",
                        "roleType": "CustomRole",
                        "permissions": [
                            {
                                "actions": [
                                    "*",
                                    "Microsoft.ContainerRegistry/registries/push/write"
                                ],
                                "notActions": [],
                                "dataActions": [],
                                "notDataActions": []
                            }
                        ],
                        "assignableScopes": [
                            "/"
                        ],
                        "location": "global"
                    }
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if there are no permissions to create custom owner roles enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Permission to create custom owner roles is not enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/providers/Microsoft.Authorization/roleDefinitions/8311e382-0749-4cb8-b61a-304f252e45ec",
                        "name": "8311e382-0749-4cb8-b61a-304f252e45ec",
                        "type": "Microsoft.Authorization/roleDefinitions",
                        "roleName": "AcrPush",
                        "description": "acr push",
                        "roleType": "CustomRole",
                        "permissions": [
                            {
                                "actions": [
                                    "Microsoft.ContainerRegistry/registries/pull/read",
                                    "Microsoft.ContainerRegistry/registries/push/write"
                                ],
                                "notActions": [],
                                "dataActions": [],
                                "notDataActions": []
                            }
                        ],
                        "assignableScopes": [
                            "/"
                        ],
                        "location": "global"
                    }
                ]
            );

            auth.run(cache, {}, callback);
        })
    })
})