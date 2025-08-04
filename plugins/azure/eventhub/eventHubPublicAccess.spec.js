var expect = require("chai").expect;
var eventHubPublicAccess = require("./eventHubPublicAccess");

const eventHubs = [
  {
    kind: "v12.0",
    location: "eastus",
    tags: {},
    id: "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub'",
    name: "testHub",
    type: "Microsoft.EventHub/Namespaces",
    location: "East US",
    tags: {},
    minimumTlsVersion: "1.2",
    publicNetworkAccess: "Disabled",
    disableLocalAuth: true,
    zoneRedundant: true,
    isAutoInflateEnabled: false,
    maximumThroughputUnits: 0,
    kafkaEnabled: false,
  },
  {
    kind: "v12.0",
    location: "eastus",
    tags: {},
    id: "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub'",
    name: "testHub",
    type: "Microsoft.EventHub/Namespaces",
    location: "East US",
    tags: {},
    minimumTlsVersion: "1.1",
    publicNetworkAccess: "Enabled",
    disableLocalAuth: true,
    zoneRedundant: true,
    isAutoInflateEnabled: false,
    maximumThroughputUnits: 0,
    kafkaEnabled: false,
  },
  {
    kind: "v12.0",
    location: "eastus",
    tags: {},
    id: "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub'",
    name: "testHub2",
    type: "Microsoft.EventHub/Namespaces",
    location: "East US",
    tags: {},
    sku: {
      name: "Basic",
      tier: "Basic",
      capacity: 1,
    },
    minimumTlsVersion: "1.2",
    publicNetworkAccess: "Enabled",
    disableLocalAuth: true,
    isAutoInflateEnabled: false,
    maximumThroughputUnits: 0,
    kafkaEnabled: false,
  },
  {
    kind: "v12.0",
    location: "eastus",
    tags: {},
    id: "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub3'",
    name: "testHub3",
    type: "Microsoft.EventHub/Namespaces",
    location: "East US",
    tags: {},
    minimumTlsVersion: "1.2",
    publicNetworkAccess: "Enabled",
    disableLocalAuth: true,
    zoneRedundant: true,
    isAutoInflateEnabled: false,
    maximumThroughputUnits: 0,
    kafkaEnabled: false,
  },
  {
    kind: "v12.0",
    location: "eastus",
    tags: {},
    name: "testHub4",
    type: "Microsoft.EventHub/Namespaces",
    location: "East US",
    tags: {},
    minimumTlsVersion: "1.2",
    publicNetworkAccess: "Enabled",
    disableLocalAuth: true,
    zoneRedundant: true,
    isAutoInflateEnabled: false,
    maximumThroughputUnits: 0,
    kafkaEnabled: false,
  },
];

const networkRuleSets = [
  {
    id: "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub3/networkrulesets/default",
    name: "default",
    type: "Microsoft.EventHub/namespaces/networkrulesets",
    defaultAction: "Allow",
    virtualNetworkRules: [],
    ipRules: [
      {
        ipMask: "192.168.1.0/24",
        action: "Allow",
      },
    ],
  },
  {
    id: "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub/networkrulesets/default",
    name: "default",
    type: "Microsoft.EventHub/namespaces/networkrulesets",
    defaultAction: "Deny",
    virtualNetworkRules: [],
    ipRules: [],
  },
];

const createCache = (hub, networkRuleSet) => {
  let cache = {
    eventHub: {
      listEventHub: {
        eastus: {
          data: hub,
        },
      },
    },
  };

  if (networkRuleSet) {
    cache.eventHub.listNetworkRuleSet = {};
    if (Array.isArray(hub) && hub.length > 0) {
      for (let eventHub of hub) {
        if (eventHub.id) {
          cache.eventHub.listNetworkRuleSet[eventHub.id] = {
            eastus: {
              data: networkRuleSet,
            },
          };
        }
      }
    }
  }

  return cache;
};

const createErrorCache = () => {
  return {
    eventHub: {
      listEventHub: {
        eastus: {
          err: "error",
        },
      },
    },
  };
};

const createNetworkRuleSetErrorCache = (hub) => {
  let cache = {
    eventHub: {
      listEventHub: {
        eastus: {
          data: hub,
        },
      },
      listNetworkRuleSet: {},
    },
  };

  if (Array.isArray(hub) && hub.length > 0) {
    for (let eventHub of hub) {
      if (eventHub.id) {
        cache.eventHub.listNetworkRuleSet[eventHub.id] = {
          eastus: {
            err: "Unable to query network rule sets",
          },
        };
      }
    }
  }

  return cache;
};

describe("eventHubPublicAccess", function () {
  describe("run", function () {
    it("should give passing result if no event hub found", function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].message).to.include("No Event Hubs namespaces found");
        expect(results[0].region).to.equal("eastus");
        done();
      };

      const cache = createCache([]);
      eventHubPublicAccess.run(cache, {}, callback);
    });

    it("should give failing result if event hub is publicly accessible", function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include(
          "Event Hubs namespace is publicly accessible"
        );
        expect(results[0].region).to.equal("eastus");
        done();
      };

      const cache = createCache([eventHubs[1]]);
      eventHubPublicAccess.run(cache, {}, callback);
    });

    it("should give passing result if eventHub is not publicly accessible", function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].message).to.include(
          "Event Hubs namespace is not publicly accessible"
        );
        expect(results[0].region).to.equal("eastus");
        done();
      };

      const cache = createCache([eventHubs[0]]);
      eventHubPublicAccess.run(cache, {}, callback);
    });

    it("should give passing result if eventHub is of basic tier", function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].message).to.include(
          "Event Hubs namespace tier is basic"
        );
        expect(results[0].region).to.equal("eastus");
        done();
      };

      const cache = createCache([eventHubs[2]]);
      eventHubPublicAccess.run(cache, {}, callback);
    });

    it("should give unknown result if unable to query for event hubs", function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(3);
        expect(results[0].message).to.include(
          "Unable to query for Event Hubs namespaces:"
        );
        expect(results[0].region).to.equal("eastus");
        done();
      };

      const cache = createErrorCache();
      eventHubPublicAccess.run(cache, {}, callback);
    });

    it("should give failing result when check_selected_networks is enabled and IP rules are configured", function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include(
          "Event Hubs namespace is publicly accessible"
        );
        expect(results[0].region).to.equal("eastus");
        done();
      };

      const cache = createCache([eventHubs[3]], networkRuleSets[0]);
      eventHubPublicAccess.run(
        cache,
        { check_selected_networks: true },
        callback
      );
    });

    it("should give passing result when check_selected_networks is enabled and no IP rules are configured", function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].message).to.include(
          "Event Hubs namespace is not publicly accessible"
        );
        expect(results[0].region).to.equal("eastus");
        done();
      };

      const cache = createCache([eventHubs[0]], networkRuleSets[1]);
      eventHubPublicAccess.run(
        cache,
        { check_selected_networks: true },
        callback
      );
    });

    it("should give unknown result when check_selected_networks is enabled but unable to query network rule sets", function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(3);
        expect(results[0].message).to.include(
          "Unable to query Event Hubs network rule set:"
        );
        expect(results[0].region).to.equal("eastus");
        done();
      };

      const cache = createNetworkRuleSetErrorCache([eventHubs[1]]);
      eventHubPublicAccess.run(
        cache,
        { check_selected_networks: true },
        callback
      );
    });

    it("should skip event hub without ID", function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(0);
        done();
      };

      const cache = createCache([eventHubs[4]]);
      eventHubPublicAccess.run(cache, {}, callback);
    });

    it("should handle mixed scenarios correctly", function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(3);

        // First result: Basic tier (should pass)
        expect(results[0].status).to.equal(0);
        expect(results[0].message).to.include(
          "Event Hubs namespace tier is basic"
        );

        // Second result: Enabled with no IP rules when check_selected_networks is true (should pass)
        expect(results[1].status).to.equal(0);
        expect(results[1].message).to.include(
          "Event Hubs namespace is not publicly accessible"
        );

        // Third result: Enabled with IP rules when check_selected_networks is true (should fail)
        expect(results[2].status).to.equal(2);
        expect(results[2].message).to.include(
          "Event Hubs namespace is publicly accessible"
        );

        done();
      };

      // Mix of different event hubs with network rule sets
      const mixedCache = {
        eventHub: {
          listEventHub: {
            eastus: {
              data: [eventHubs[2], eventHubs[0], eventHubs[3]], // basic tier, disabled, enabled with IP rules
            },
          },
          listNetworkRuleSet: {
            [eventHubs[0].id]: {
              eastus: {
                data: networkRuleSets[1], // no IP rules
              },
            },
            [eventHubs[3].id]: {
              eastus: {
                data: networkRuleSets[0], // with IP rules
              },
            },
          },
        },
      };

      eventHubPublicAccess.run(
        mixedCache,
        { check_selected_networks: true },
        callback
      );
    });
  });
});
