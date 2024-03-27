var expect = require("chai").expect;
var domainLocalAuthDisabled = require("./domainLocalAuthDisabled");

const domains = [
    {
      "endpoint": "https://exampledomain1.westus2-1.eventgrid.azure.net/api/events",
      "provisioningState": "Succeeded",
      "id": "/subscriptions/8f6b6269-84f2-4d09-9e31-1127efcd1e40/resourceGroups/examplerg/providers/Microsoft.EventGrid/domains/exampledomain1",
      "location": "eastus",
      "name": "exampledomain1",
      "publicNetworkAccess": "Enabled",
      "disableLocalAuth": false,

    },
    {
      "id": "/subscriptions/8f6b6269-84f2-4d09-9e31-1127efcd1e40/resourceGroups/examplerg/providers/Microsoft.EventGrid/domains/exampledomain1",
      "location": "eastus",
      "name": "exampledomain1",
      "publicNetworkAccess": "Disabled",
      "disableLocalAuth": true,

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

describe("domainLocalAuthDisabled", function () {
  describe("run", function () {
    it("should give Passing result if no domain found", function (done) {
        const cache = createCache([]);
        domainLocalAuthDisabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.include("No Event Grid domains found");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });

    it("should give unknown result if unable to query for domains", function (done) {
        const cache = createCache(null);
        domainLocalAuthDisabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(3);
            expect(results[0].message).to.include("Unable to query for Event Grid domains:");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });

    it("should give passing result if Event Grid domain has local authentication disabled", function (done) {
        const cache = createCache([domains[1]]);
        domainLocalAuthDisabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.include("Event Grid domain has local authentication disabled");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });

    it("should give passing result if Event Grid domain has local authentication enabled", function (done) {
        const cache = createCache([domains[0]]);
        domainLocalAuthDisabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(2);
            expect(results[0].message).to.include("Event Grid domain has local authentication enabled");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });
  });
});
