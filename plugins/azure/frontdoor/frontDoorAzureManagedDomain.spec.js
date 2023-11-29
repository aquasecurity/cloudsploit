var expect = require('chai').expect;
var frontDoorAzureManagedDomain = require('./frontDoorAzureManagedDomain.js');

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
        }
    },
    {
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/meerab-rg/providers/Microsoft.Cdn/profiles/mehak-fd",
        "type": "Microsoft.Cdn/profiles",
        "name": "mehak-fd",
        "location": "Global",
        "kind": "frontdoor",
        "tags": {},
        "sku": {
            "name": "Premium_AzureFrontDoor"
        },
        "properties": {
            "originResponseTimeoutSeconds": 60,
            "frontDoorId": "40590271-c2c4-4264-8061-45b884a91a70",
            "resourceState": "Active",
            "provisioningState": "Succeeded"
        }
    }
];


const customDomain = [
    {
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/meerab-rg/providers/Microsoft.Cdn/profiles/mehak-fd/customdomains/test-naim-app-srvenv-appserviceenvironment-net",
        "type": "Microsoft.Cdn/profiles/customdomains",
        "name": "test-naim-app-srvenv-appserviceenvironment-net",
        "hostName": "test.naim-app-srvenv.appserviceenvironment.net",
        "tlsSettings": {
            "certificateType": "ManagedCertificate",
            "minimumTlsVersion": "TLS12",
            "secret": null
        },
        "validationProperties": {
            "validationToken": "mh0nl1m0syywj6m6bt5s9hksxw1sk4h9",
            "expirationDate": "2023-08-07T20:07:11.5302594+00:00"
        },
        "azureDnsZone": {
            "id": "/subscriptions/a7ddb462-bd4a-4c99-bda2-e008b2ab62f8/resourceGroups/naim-resources/providers/Microsoft.Network/dnszones/naim-app-srvenv.appserviceenvironment.net"
        },
        "domainValidationState": "Pending",
        "preValidatedCustomDomainResourceId": null,
        "provisioningState": "Succeeded",
        "deploymentStatus": "NotStarted"
    },
    {

    },
    {
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/meerab-rg/providers/Microsoft.Cdn/profiles/mehak-fd/customdomains/test-naim-app-srvenv-appserviceenvironment-net",
        "type": "Microsoft.Cdn/profiles/customdomains",
        "name": "test-naim-app-srvenv-appserviceenvironment-net",
        "hostName": "test.naim-app-srvenv.appserviceenvironment.net",
        "tlsSettings": {
            "certificateType": "ManagedCertificate",
            "minimumTlsVersion": "TLS1",
            "secret": null
        },
        "validationProperties": {
            "validationToken": "mh0nl1m0syywj6m6bt5s9hksxw1sk4h9",
            "expirationDate": "2023-08-07T20:07:11.5302594+00:00"
        },
        "azureDnsZone": null,
        "domainValidationState": "Pending",
        "preValidatedCustomDomainResourceId": null,
        "provisioningState": "Succeeded",
        "deploymentStatus": "NotStarted"
    },
]

const createCache = (profiles, customDomains) => {
    let customDomain = {};
    if (profiles.length) {
        customDomain[profiles[0].id] = {
            data: customDomains
        };
    }


    return {
        profiles: {
            list: {
                'global': {
                    data: profiles
                }
            }
        },
        customDomain: {
            listByFrontDoorProfiles: {
                'global': customDomain
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key == 'profile') {
        return {
            profiles: {
                list: {
                    'global': {}
                }
            }
        };
    } else if (key === 'customDomains') {
        return {
            profiles: {
                list: {
                    'global': {
                        data: [profiles[0]]
                    }
                }
            },
            customDomains: {
                listByFrontDoorProfiles: {
                    'global': {}
                }
            }
        };
    } else {
        const profileId = (profiles && profiles.length) ? profiles[0].id : null;
        const customDomains = (customDomains && customDomains.length) ? customDomains[0].id : null;
        return {
            profiles: {
                list: {
                    'global': {
                        data: [profiles[0]]
                    }
                }
            },
            diagnosticSettings: {
                customDomains: {
                    'global': {
                        data: {}
                    }
                }
            }
        };
    }
};

describe('frontDoorAzureManagedDomain', function () {
    describe('run', function () {

        it('should give unknown if Unable to query Azure Front Door profiles:', function (done) {
            const cache = createErrorCache('profile');
            frontDoorAzureManagedDomain.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Azure Front Door profiles');
                expect(results[0].region).to.equal('global');
                done();
            });
        });


        it('should give unknown if Unable to query Front Door custom domains:', function (done) {
            const cache = createErrorCache('customDomains');
            frontDoorAzureManagedDomain.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Front Door custom domains:');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give pass if No existing Front Door custom domains found', function (done) {
            const cache = createCache([profiles[0]], customDomain[1]);
            frontDoorAzureManagedDomain.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Front Door custom domains found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give pass result if AFD profile custom domain is using Azure managed DNS', function (done) {
            const cache = createCache([profiles[2]], [customDomain[0]]);
            frontDoorAzureManagedDomain.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Front Door profile custom domains are using Azure managed DNS');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give fail result if AFD profile custom domain is not using Azure managed DNS', function (done) {
            const cache = createCache([profiles[2]], [customDomain[2]]);
            frontDoorAzureManagedDomain.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Front Door profile custom domains are not using Azure managed DNS:');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});