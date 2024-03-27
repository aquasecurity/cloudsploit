var expect = require("chai").expect;
var domainManagedIdentity = require("./domainManagedIdentity");

const domains = [
    {
      "id": "/subscriptions/1234/resourceGroups/examplerg/providers/Microsoft.EventGrid/domains/exampledomain1",
      "location": "eastus",
      "name": "exampledomain1",
      "publicNetworkAccess": "Enabled",
      "identity": {
        "type": "None",
        "principalId": null,
        "tenantId": null,
        "userAssignedIdentities": null
      },
    },
    {
      "id": "/subscriptions/1234/resourceGroups/examplerg/providers/Microsoft.EventGrid/domains/exampledomain1",
      "location": "eastus",
      "name": "exampledomain1",
      "publicNetworkAccess": "Disabled",
      "identity": {
        "type": "SystemAssigned",
        "principalId": "12345",
        "tenantId": "1243567",
        "userAssignedIdentities": null
      },
    }
]
const createCache = (data) => {
  return {
    eventGrid: {
      listDomains: {
        'eastus': {
          data: data,
        },
      },
    },
  };
};

describe("domainManagedIdentity", function () {
  describe("run", function () {
    it("should give passing result if no domain found", function (done) {
        const cache = createCache([]);
        domainManagedIdentity.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.include("No Event Grid domains found");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });

    it("should give unknown result if unable to query for domains", function (done) {
        const cache = createCache(null);
        domainManagedIdentity.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(3);
            expect(results[0].message).to.include("Unable to query for Event Grid domains:");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });

    it("should give failing result if event grid domain does not have managed identity enabled", function (done) {
        const cache = createCache([domains[0]]);
        domainManagedIdentity.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(2);
            expect(results[0].message).to.include("Event Grid domain does not have managed identity enabled");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });

    it("should give passing result if event grid domain has managed identity enabled", function (done) {
        const cache = createCache([domains[1]]);
        domainManagedIdentity.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.include("Event Grid domain has managed identity enabled");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });
  });
});
