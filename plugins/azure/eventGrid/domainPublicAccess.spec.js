var expect = require("chai").expect;
var domainPublicAccess = require("./domainPublicAccess");

const domains = [
    {
      "properties": {
        "endpoint": "https://exampledomain1.westus2-1.eventgrid.azure.net/api/events",
        "provisioningState": "Succeeded"
      },
      "id": "/subscriptions/8f6b6269-84f2-4d09-9e31-1127efcd1e40/resourceGroups/examplerg/providers/Microsoft.EventGrid/domains/exampledomain1",
      "location": "westus2",
      "name": "exampledomain1",
      "publicNetworkAccess": "Enabled"
    },
    {
    "properties": {
        "endpoint": "https://exampledomain1.westus2-1.eventgrid.azure.net/api/events",
        "provisioningState": "Succeeded"
      },
      "id": "/subscriptions/8f6b6269-84f2-4d09-9e31-1127efcd1e40/resourceGroups/examplerg/providers/Microsoft.EventGrid/domains/exampledomain1",
      "location": "westus2",
      "name": "exampledomain1",
      "publicNetworkAccess": "Disabled"
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

describe("domainPublicAccess", function () {
  describe("run", function () {
    it("should give Passing result if no domain found", function (done) {
        const cache = createCache([]);
        domainPublicAccess.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.include("No Event Grid domains found");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });

    it("should give unknown result if unable to query for domains", function (done) {
        const cache = createCache(null);
        domainPublicAccess.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(3);
            expect(results[0].message).to.include("Unable to query for Event Grid domains:");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });

    it("should give failing result if public access enabled for domains", function (done) {
        const cache = createCache([domains[0]]);
        domainPublicAccess.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(2);
            expect(results[0].message).to.include("Event Grid domain has public network access enabled");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });

    it("should give passing result if public access not enabled for domains", function (done) {
        const cache = createCache([domains[1]]);
        domainPublicAccess.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.include("Event Grid domain does not have public network access enabled");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });
  });
});
