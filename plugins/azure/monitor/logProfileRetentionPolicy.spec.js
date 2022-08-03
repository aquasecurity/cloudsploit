var expect = require('chai').expect;
var logProfileRetentionPolicy = require('./logProfileRetentionPolicy');

const logProfile = [
    {
        "id": "/subscriptions/1234/providers/microsoft.insights/logprofiles/test",
        "type": null,
        "name": "default",
        "location": null,
        "kind": null,
        "tags": null,
        "identity": null,
        "storageAccountId": "/subscriptions/1234/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Storage/storageAccounts/devstoragetwo",
        "serviceBusRuleId": null,
        "locations": [
          "australiacentral",
          "australiacentral2",
          "australiaeast",
          "australiasoutheast",
          "brazilsouth",
          "canadacentral",
          "canadaeast",
          "centralindia",
          "centralus",
          "eastasia",
          "eastus",
          "eastus2",
          "francecentral",
          "francesouth",
          "japaneast",
          "japanwest",
          "koreacentral",
          "koreasouth",
          "northcentralus",
          "northeurope",
          "southafricanorth",
          "southafricawest",
          "southcentralus",
          "southindia",
          "southeastasia",
          "uaecentral",
          "uaenorth",
          "uksouth",
          "ukwest",
          "westcentralus",
          "westeurope",
          "westindia",
          "westus",
          "westus2",
          "westus3",
          "eastus2euap",
          "centraluseuap",
          "jioindiawest",
          "jioindiacentral",
          "swedencentral",
          "germanywestcentral",
          "germanycentral",
          "germanynortheast",
          "germanynorth",
          "norwayeast",
          "switzerlandnorth",
          "norwaywest",
          "switzerlandwest",
          "brazilsoutheast",
          "global"
        ],
        "categories": [
          "Write",
          "Delete",
          "Action"
        ],
        "retentionPolicy": {
          "enabled": true,
          "days": 366
        }
    },
    {
        "id": "/subscriptions/1234/providers/microsoft.insights/logprofiles/default",
        "type": null,
        "name": "default",
        "location": null,
        "kind": null,
        "tags": null,
        "identity": null,
        "storageAccountId": "/subscriptions/1234/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Storage/storageAccounts/devstoragetwo",
        "serviceBusRuleId": null,
        "retentionPolicy": {
          "enabled": true,
          "days": 82
        }
    },
    {
        "id": "/subscriptions/1234/providers/microsoft.insights/logprofiles/default",
        "type": null,
        "name": "default",
        "location": null,
        "kind": null,
        "tags": null,
        "identity": null,
        "storageAccountId": "/subscriptions/1234/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Storage/storageAccounts/devstoragetwo",
        "serviceBusRuleId": null,
    },
    {
        "id": "/subscriptions/1234/providers/microsoft.insights/logprofiles/default",
        "type": null,
        "name": "default",
        "location": null,
        "kind": null,
        "tags": null,
        "identity": null,
        "storageAccountId": "/subscriptions/1234/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Storage/storageAccounts/devstoragetwo",
        "serviceBusRuleId": null,
        "retentionPolicy": {
        }
    },
];

const createCache = (logProfile) => {
    let settings = {};
    if (logProfile) {
        settings['data'] = logProfile;
    }
    return {
        logProfiles: {
            list: {
                'global': settings
            }
        }
    };
};

describe('logProfileRetentionPolicy', function() {
    describe('run', function() {
        it('should give passing result if No existing Log Profiles found', function(done) {
            const cache = createCache([]);
            logProfileRetentionPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing Log Profiles found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if Unable to query for Log Profiles', function(done) {
            const cache = createCache();
            logProfileRetentionPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Log Profiles');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if The Log Profile retention policy is sufficient', function(done) {
            const cache = createCache([logProfile[0]]);
            logProfileRetentionPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The Log Profile retention policy');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if The Log Profile retention policy is not sufficient', function(done) {
            const cache = createCache([logProfile[1]]);
            logProfileRetentionPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The Log Profile retention policy');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if The Log Profile does not have a retention policy', function(done) {
            const cache = createCache([logProfile[2]]);
            logProfileRetentionPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The Log Profile does not have a retention policy');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if The Log Profile retention policy is not enabled', function(done) {
            const cache = createCache([logProfile[3]]);
            logProfileRetentionPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The Log Profile retention policy is not enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});
