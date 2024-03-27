var expect = require("chai").expect;
var domainMinimumTlsVersion = require("./domainMinimumTlsVersion");

const domains = [
    {
      "endpoint": "https://exampledomain1.westus2-1.eventgrid.azure.net/api/events",
      "provisioningState": "Succeeded",
      "id": "/subscriptions/1234/resourceGroups/examplerg/providers/Microsoft.EventGrid/domains/exampledomain1",
      "location": "westus2",
      "name": "exampledomain1",
      "publicNetworkAccess": "Enabled",
      "minimumTlsVersionAllowed": "1.2",
    },
    {
    "properties": {
        "endpoint": "https://exampledomain1.westus2-1.eventgrid.azure.net/api/events",
        "provisioningState": "Succeeded"
      },
      "id": "/subscriptions/1234/resourceGroups/examplerg/providers/Microsoft.EventGrid/domains/exampledomain1",
      "location": "westus2",
      "name": "exampledomain1",
      "publicNetworkAccess": "Disabled",
      "minimumTlsVersionAllowed": "1.1",
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

describe("domainMinimumTlsVersion", function () {
  describe("run", function () {
    it("should give passing result if no domain found", function (done) {
        const cache = createCache([]);
        domainMinimumTlsVersion.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.include("No Event Grid domains found");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });

    it("should give unknown result if unable to query for domains", function (done) {
        const cache = createCache(null);
        domainMinimumTlsVersion.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(3);
            expect(results[0].message).to.include("Unable to query for Event Grid domains:");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });

    it("should give passing result if Event Grid domain is using TLS version 1.2", function (done) {
        const cache = createCache([domains[0]]);
        domainMinimumTlsVersion.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.include("Event Grid domain is using TLS version 1.2");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });

    it("should give failing result if event grid domain is not using desired tls version", function (done) {
        const cache = createCache([domains[1]]);
        domainMinimumTlsVersion.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(2);
            expect(results[0].message).to.include("Event Grid domain is using TLS version 1.1 instead of version 1.2");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });

    it("should give passing result if event grid domain is using desired tls version with setting value set to 1.1", function (done) {
        const cache = createCache([domains[1]]);
        domainMinimumTlsVersion.run(cache, {event_grid_domain_min_tls_version: 1.1}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.include("Event Grid domain is using TLS version 1.1");
            expect(results[0].region).to.equal("eastus");
            done();
        });
    });
  });
});
