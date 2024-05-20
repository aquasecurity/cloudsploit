var expect = require('chai').expect;
var frontDoorManagedIdentity = require('./frontDoorManagedIdentity');

const profiles = [
    {
        "id": "/subscriptions/234/resourcegroups/sadeedrg/providers/Microsoft.Cdn/profiles/test-profile",
        "type": "Microsoft.Cdn/profiles",
        "name": "test-profile",
        "location": "Global",
        "kind": "frontdoor",
        "tags": {},
        "sku": {
            "name": "Standard_Microsoft"
        },
        "properties": {
            "resourceState": "Active",
            "provisioningState": "Succeeded"
        },
        "identity": {
            "type": "SystemAssigned"
          }
    },
    {
        "id": "/subscriptions/234/resourcegroups/sadeedrg/providers/Microsoft.Cdn/profiles/test-profile",
        "type": "Microsoft.Cdn/profiles",
        "name": "test-profile",
        "location": "Global",
        "kind": "frontdoor",
        "tags": {},
        "sku": {
            "name": "Standard_Microsoft"
        },
        "properties": {
            "resourceState": "Active",
            "provisioningState": "Succeeded"
        },
        "identity": {
            "type": "None"
        }
    }
];


const createCache = (profiles) => {
    return {
        profiles: {
            list: {
                'global': {
                    data: profiles
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        profiles: {
            list: {
                'global': {}
            }
        }
    };
};

describe('frontDoorManagedIdentity', function () {
    describe('run', function () {

        it('should give pass result if No existing Azure Front Door profiles found', function (done) {
            const cache = createCache([]);
            frontDoorManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Azure Front Door profiles found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if Unable to query Front Door profiles:', function (done) {
            const cache = createErrorCache();
            frontDoorManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Front Door profiles:');
                expect(results[0].region).to.equal('global');
                done();
            });
        });


        it('should give passing result if Access Log are enabled for Azure Front Door', function (done) {
            const cache = createCache([profiles[0]]);
            frontDoorManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Front Door profile has managed identity enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if Access logging is not enabled for Azure Front Door', function (done) {
            const cache = createCache([profiles[1]]);
            frontDoorManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Front Door profile does not have managed identity enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});