var expect = require("chai").expect;
var publicIpAddressLoggingEnabled = require("./publicIpAddressLoggingEnabled");

const activityLogAlerts = [
    {
        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourceGroups/Default-ActivityLogAlerts/providers/microsoft.insights/activityLogAlerts/NSG2",
        "name": "NSG2",
        "type": "Microsoft.Insights/ActivityLogAlerts",
        "location": "global",
        "tags": {},
        "scopes": [
            "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a"
        ],
        "enabled": true,
        "condition": {
            "allOf": [
                {
                    "field": "category",
                    "equals": "Admninistrative"
                },
                {
                    "field": "operationName",
                    "equals": "Microsoft.Network/publicIPAddresses/"
                }
            ]
        },
        "actions": {
            "actionGroups": [
                {
                    "actionGroupId": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/testactiong",
                    "webhookProperties": {}
                }
            ]
        }
    },
    {
        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourceGroups/Default-ActivityLogAlerts/providers/microsoft.insights/activityLogAlerts/NSG2",
        "name": "NSG2",
        "type": "Microsoft.Insights/ActivityLogAlerts",
        "location": "global",
        "tags": {},
        "scopes": [
            "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a"
        ],
        "enabled": true,
        "condition": {
            "allOf": [
                {
                    "field": "category",
                    "equals": "Admninistrative"
                },
                {
                    "field": "operationName",
                    "equals": "Microsoft.Network/publicIPAddresses/write"
                },
                {
                    "field": "operationName",
                    "equals": "Microsoft.Network/publicIPAddresses/delete"
                }
            ]
        },
        "actions": {
            "actionGroups": [
                {
                    "actionGroupId": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/testactiong",
                    "webhookProperties": {}
                }
            ]
        }
    },
    {
        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourceGroups/Default-ActivityLogAlerts/providers/microsoft.insights/activityLogAlerts/NSG2",
        "name": "NSG2",
        "type": "Microsoft.Insights/ActivityLogAlerts",
        "location": "global",
        "tags": {},
        "scopes": [
            "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a"
        ],
        "enabled": true,
        "condition": {
            "allOf": [
                {
                    "field": "category",
                    "equals": "Admninistrative"
                },
                {
                    "field": "operationName",
                    "equals": "Microsoft.Network/publicIPAddresses/write"
                }
            ]
        },
        "actions": {
            "actionGroups": [
                {
                    "actionGroupId": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/testactiong",
                    "webhookProperties": {}
                }
            ]
        }
    },
    {
        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourceGroups/Default-ActivityLogAlerts/providers/microsoft.insights/activityLogAlerts/NSG2",
        "name": "NSG2",
        "type": "Microsoft.Insights/ActivityLogAlerts",
        "location": "global",
        "tags": {},
        "scopes": [
            "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a"
        ],
        "enabled": true,
        "condition": {
            "allOf": [
                {
                    "field": "category",
                    "equals": "Admninistrative"
                },
                {
                    "field": "operationName",
                    "equals": "Microsoft.Network/publicIPAddresses/delete"
                }
            ]
        },
        "actions": {
            "actionGroups": [
                {
                    "actionGroupId": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/testactiong",
                    "webhookProperties": {}
                }
            ]
        }
    }
];

const createCache = (err, data) => {
  return {
    activityLogAlerts: {
      listBySubscriptionId: {
        global: {
          err: err,
          data: data,
        },
      },
    },
  };
};

describe("publicIpAddressLoggingEnabled", function () {
  describe("run", function () {
    it("should give failing result if no activity log alerts found", function (done) {
        const cache = createCache(null, []);
        publicIpAddressLoggingEnabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(2);
            expect(results[0].message).to.include("No existing Activity Alerts found");
            expect(results[0].region).to.equal("global");
            done();
        });
    });

    it("should give unknown result if unable to query for Activity alerts", function (done) {
        const cache = createCache(null);
        publicIpAddressLoggingEnabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(3);
            expect(results[0].message).to.include("Unable to query for Activity Alerts");
            expect(results[0].region).to.equal("global");
            done();
        });
    });

    it("should give failing result if Public Ip Address create/update and delete is not enabled", function (done) {
        const cache = createCache(null, [activityLogAlerts[0]]);
        publicIpAddressLoggingEnabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(2);
            expect(results[0].message).to.include("Log Alert for Public IP Addresses write and delete is not enabled");
            expect(results[0].region).to.equal("global");
            done();
        });
    });

    it("should give failing and passing results if Public IP Addresses delete is not enaled but write is enabled", function (done) {
        const cache = createCache(null, [activityLogAlerts[2]]);
        publicIpAddressLoggingEnabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(2);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.include("Log alert for Public IP Addresses write is enabled");
            expect(results[0].region).to.equal("global");
            expect(results[1].status).to.equal(2);
            expect(results[1].message).to.include("Log Alert for Public IP Addresses delete is not enabled");
            expect(results[0].region).to.equal("global");
            done();
        });
    });

    it("should give failing and passing results if Public IP Addresses write is not enaled but delete is enabled", function (done) {
        const cache = createCache(null, [activityLogAlerts[3]]);
        publicIpAddressLoggingEnabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(2);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.include("Log alert for Public IP Addresses delete is enabled");
            expect(results[0].region).to.equal("global");
            expect(results[1].status).to.equal(2);
            expect(results[1].message).to.include("Log alert for Public IP Addresses write is not enabled");
            expect(results[0].region).to.equal("global");
            done();
        });
    });

    it("should give passing result if Public IP Addresses create/update and delete is enabled", function (done) {
        const cache = createCache(null, [activityLogAlerts[1]]);
        publicIpAddressLoggingEnabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.include("Log Alert for Public IP Addresses write and delete is enabled");
            expect(results[0].region).to.equal("global");
            done();
        });
    });
  });
});
