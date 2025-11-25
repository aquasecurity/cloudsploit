var expect = require('chai').expect;
var eventHubPublicAccess = require('./eventHubPublicAccess');

const eventHubs = [
    {
        kind: "v12.0",
        location: "eastus",
        tags: {},
        id: "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub",
        name: "testHub",
        type: "Microsoft.EventHub/Namespaces",
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
        id: "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub",
        name: "testHub",
        type: "Microsoft.EventHub/Namespaces",
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
        id: "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub",
        name: "testHub2",
        type: "Microsoft.EventHub/Namespaces",
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
        id: "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub",
        name: "testHub",
        type: "Microsoft.EventHub/Namespaces",
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
        id: "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub",
        name: "testHub",
        type: "Microsoft.EventHub/Namespaces",
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
        id: "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub/networkrulesets/default",
        name: "default",
        type: "Microsoft.EventHub/Namespaces/NetworkRuleSets",
        location: "eastus",
        publicNetworkAccess: "Enabled",
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
        type: "Microsoft.EventHub/Namespaces/NetworkRuleSets",
        location: "eastus",
        publicNetworkAccess: "Enabled",
        defaultAction: "Deny",
        virtualNetworkRules: [],
        ipRules: [
            {
                ipMask: "102.18.161.9",
                action: "Allow"
            }
        ],
    },
    {
        id: "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub/networkrulesets/default",
        name: "default",
        type: "Microsoft.EventHub/Namespaces/NetworkRuleSets",
        location: "eastus",
        publicNetworkAccess: "Enabled",
        defaultAction: "Allow",
        virtualNetworkRules: [],
        ipRules: [
        ],
    },
];

const createCache = (eventHub, networkRuleSet) => {
    const id = eventHub && eventHub.length ? eventHub[0].id : null;
    return {
        eventHub: {
            listEventHub: {
                'eastus': {
                    data: eventHub
                }
            },
            listNetworkRuleSet: {
                'eastus': {
                    [id]: {
                        data: networkRuleSet
                    }
                }
            }
        }
    };
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
            listNetworkRuleSet: {
                eastus: {}
            }
        },
    };

    if (Array.isArray(hub) && hub.length > 0) {
        for (let eventHub of hub) {
            if (eventHub.id) {
                cache.eventHub.listNetworkRuleSet.eastus[eventHub.id] = {
                    err: "Unable to query network rule sets",
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

        it("should give passing result when check_selected_networks is enabled and IP rules are configured", function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include(
                    "Event Hubs namespace is not publicly accessible"
                );
                expect(results[0].region).to.equal("eastus");
                done();
            };

            const cache = createCache([eventHubs[3]], networkRuleSets[1]);
            eventHubPublicAccess.run(
                cache,
                { check_selected_networks: true },
                callback
            );
        });

        it("should give failing result when check_selected_networks is enabled and no IP rules are configured", function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include(
                    "Event Hubs namespace is publicly accessible"
                );
                expect(results[0].region).to.equal("eastus");
                done();
            };

            const cache = createCache([eventHubs[5]], networkRuleSets[2]);
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

    });
});
