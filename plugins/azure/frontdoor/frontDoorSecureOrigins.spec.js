var expect = require('chai').expect;
var frontDoorSecureOrigin = require('./frontDoorSecureOrigins.js');

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

const originGroups = [
    {
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/meerab-rg/providers/Microsoft.Cdn/profiles/mehak-fd/origingroups/default-origin-group",
        "type": "Microsoft.Cdn/profiles/origingroups",
        "name": "default-origin-group",
        "properties": {
            "loadBalancingSettings": {
                "sampleSize": 4,
                "successfulSamplesRequired": 3,
                "additionalLatencyInMilliseconds": 50
            },
            "healthProbeSettings": {
                "probePath": "/",
                "probeRequestType": "HEAD",
                "probeProtocol": "Http",
                "probeIntervalInSeconds": 100
            },
            "trafficRestorationTimeToHealedOrNewEndpointsInMinutes": null,
            "sessionAffinityState": "Disabled",
            "provisioningState": "Succeeded",
            "deploymentStatus": "NotStarted"
        }
    },
]

const origins = [
    {
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/meerab-rg/providers/Microsoft.Cdn/profiles/mehak-fd/origingroups/default-origin-group/origins/default-origin",
        "type": "Microsoft.Cdn/profiles/origingroups/origins",
        "name": "default-origin",
        "originGroupName": "default-origin-group",
        "hostName": "abdullah306.blob.core.windows.net",
        "httpPort": 80,
        "httpsPort": 443,
        "originHostHeader": "abdullah306.blob.core.windows.net",
        "priority": 1,
        "weight": 1000,
        "enabledState": "Enabled",
        "sharedPrivateLinkResource": {
            "privateLink": {
                "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourceGroups/meerab-rg/providers/Microsoft.Storage/storageAccounts/abdullah306"
            },
            "groupId": "blob",
            "privateLinkLocation": "eastus",
            "status": null,
            "requestMessage": "yes",
            "enforceCertificateNameCheck": true,
            "provisioningState": "Succeeded",
            "deploymentStatus": "NotStarted"
        }
    },
    {
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/cloudsploit-dev/providers/Microsoft.Cdn/profiles/omer-cdn-profile-test/origingroups/default-origin-group/origins/default-origin",
        "type": "Microsoft.Cdn/profiles/origingroups/origins",
        "name": "default-origin",
        "properties": {
            "originGroupName": "default-origin-group",
            "hostName": "omer-app-service.azurewebsites.net",
            "httpPort": 80,
            "httpsPort": 443,
            "originHostHeader": "omer-app-service.azurewebsites.net",
            "priority": 1,
            "weight": 1000,
            "enabledState": "Enabled",
            "sharedPrivateLinkResource": null,
            "enforceCertificateNameCheck": true,
            "provisioningState": "Succeeded",
            "deploymentStatus": "NotStarted"
        }
    },
    {
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/cloudsploit-dev/providers/Microsoft.Cdn/profiles/omer-cdn-profile-test/origingroups/default-origin-group/origins/default-origin",
        "type": "Microsoft.Cdn/profiles/origingroups/origins",
        "name": "default-origin-group-2",
        "properties": {
            "originGroupName": "default-origin-group-2",
            "hostName": "omer-app-service.azurewebsites.net",
            "httpPort": 80,
            "httpsPort": 443,
            "originHostHeader": "omer-app-service.azurewebsites.net",
            "priority": 1,
            "weight": 1000,
            "enabledState": "Enabled",
            "sharedPrivateLinkResource": null,
            "enforceCertificateNameCheck": true,
            "provisioningState": "Succeeded",
            "deploymentStatus": "NotStarted"
        }
    }
]

const createCache = (profiles, originGroups, origins) => {
    let containers = {};
    if (profiles.length) {
        containers[profiles[0].id] = {
            data: originGroups
        };
    }

    let origin = {};
    if (originGroups.length) {
        origin[originGroups[0].id] = {
            data: origins
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
        afdOriginGroups: {
            listByProfile: {
                'global': containers
            }
        },
        afdOrigin: {
            listByOriginGroups: {
                'global': origin
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
    } else if (key === 'noprofile') {
        return {
            profiles: {
                list: {
                    'global': {
                        data: {}
                    }
                }
            }
        };
    }
    else if (key === 'origingroups') {
        return {
            profiles: {
                list: {
                    'global': {
                        data: [profiles[0]]
                    }
                }
            },
            afdOriginGroups: {
                listByProfile: {
                    'global': {}
                }
            }
        };
    } else {
        const profileId = (profiles && profiles.length) ? profiles[0].id : null;
        const originGroup = (originGroups && originGroups.length) ? originGroups[0].id : null;
        return {
            profiles: {
                list: {
                    'global': {
                        data: [profiles[0]]
                    }
                }
            },
            afdOriginGroups: {
                listByProfile: {
                    'global': {
                        [profileId]: {
                            data: [originGroup[0]]
                        }
                    }
                }
            },
            afdOrigin: {
                listByOriginGroups: {
                    'global': {
                    }
                }
            }
        };
    }
};

describe('frontDoorSecureOrigin', function () {
    describe('run', function () {
        it('should give pass result if No existing Azure Front Door profiles found', function (done) {
            const cache = createErrorCache('noprofile');
            frontDoorSecureOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Azure Front Door profiles found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown if Unable to query Azure Front Door profiles', function (done) {
            const cache = createErrorCache('profile');
            frontDoorSecureOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Azure Front Door profiles');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if Unable to query Azure Front Door Origin Groups', function (done) {
            const cache = createErrorCache('origingroups');
            frontDoorSecureOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Azure Front Door Origin Groups');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if Unable to query Azure Front Door Origin', function (done) {
            const cache = createErrorCache('origin');
            frontDoorSecureOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Azure Front Door Origin');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give fail result if Front Door Profile origins are using insecure origins', function (done) {
            const cache = createCache([profiles[0]], [originGroups[0]], [origins[1],origins[2]]);
            frontDoorSecureOrigin.run(cache, {}, (err, results) => {

                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Front Door Profile origins are using insecure origins in following origin groups');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
        it('should give pass result if Front Door Profile origins are using secure origins', function (done) {
            const cache = createCache([profiles[0]], [originGroups[0]], [origins[0]]);
            frontDoorSecureOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Front Door Profile origins are using secure origin');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});