var expect = require("chai").expect;
var mysqlFlexibleServerLoggingEnabled = require("./mysqlFlexibleServerLoggingEnabled");

const activityLogAlerts = [
    {
        "id": "/subscriptions/12345/resourceGroups/Default-ActivityLogAlerts/providers/microsoft.insights/activityLogAlerts/NSG2",
        "name": "NSG2",
        "type": "Microsoft.Insights/ActivityLogAlerts",
        "location": "global",
        "tags": {},
        "scopes": [
            "/subscriptions/123456"
        ],
        "enabled": true,
        "condition": {
            "allOf": [
                {
                    "field": "category",
                    "equals": "Security"
                },
                {
                    "field": "operationName",
                    "equals": "Microsoft.DBforMySQL/flexibleservers/"
                }
            ]
        },
        "actions": {
            "actionGroups": [
                {
                    "actionGroupId": "/subscriptions/123456/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/testactiong",
                    "webhookProperties": {}
                }
            ]
        }
    },
    {
        "id": "/subscriptions/123456/resourceGroups/Default-ActivityLogAlerts/providers/microsoft.insights/activityLogAlerts/NSG2",
        "name": "NSG2",
        "type": "Microsoft.Insights/ActivityLogAlerts",
        "location": "global",
        "tags": {},
        "scopes": [
            "/subscriptions/123456"
        ],
        "enabled": true,
        "condition": {
            "allOf": [
                {
                    "field": "category",
                    "equals": "Security"
                },
                {
                    "field": "operationName",
                    "equals": "Microsoft.DBforMySQL/flexibleServers/write"
                },
                {
                    "field": "operationName",
                    "equals": "Microsoft.DBforMySQL/flexibleServers/delete"
                }
            ]
        },
        "actions": {
            "actionGroups": [
                {
                    "actionGroupId": "/subscriptions/123456/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/testactiong",
                    "webhookProperties": {}
                }
            ]
        }
    },
    {
        "id": "/subscriptions/123456/resourceGroups/Default-ActivityLogAlerts/providers/microsoft.insights/activityLogAlerts/NSG2",
        "name": "NSG2",
        "type": "Microsoft.Insights/ActivityLogAlerts",
        "location": "global",
        "tags": {},
        "scopes": [
            "/subscriptions/123456"
        ],
        "enabled": true,
        "condition": {
            "allOf": [
                {
                    "field": "category",
                    "equals": "Security"
                },
                {
                    "field": "operationName",
                    "equals": "Microsoft.DBforMySQL/flexibleServers/write"
                }
            ]
        },
        "actions": {
            "actionGroups": [
                {
                    "actionGroupId": "/subscriptions/123456/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/testactiong",
                    "webhookProperties": {}
                }
            ]
        }
    },
    {
        "id": "/subscriptions/123456/resourceGroups/Default-ActivityLogAlerts/providers/microsoft.insights/activityLogAlerts/NSG2",
        "name": "NSG2",
        "type": "Microsoft.Insights/ActivityLogAlerts",
        "location": "global",
        "tags": {},
        "scopes": [
            "/subscriptions/123456"
        ],
        "enabled": true,
        "condition": {
            "allOf": [
                {
                    "field": "category",
                    "equals": "Security"
                },
                {
                    "field": "operationName",
                    "equals": "Microsoft.DBforMySQL/flexibleServers/delete"
                }
            ]
        },
        "actions": {
            "actionGroups": [
                {
                    "actionGroupId": "/subscriptions/123456/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/testactiong",
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

describe("mysqlFlexibleServerLoggingEnabled", function () {
  describe("run", function () {
    it("should give failing result if no activity log alerts found", function (done) {
        const cache = createCache(null, []);
        mysqlFlexibleServerLoggingEnabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(2);
            expect(results[0].message).to.include("No existing Activity Alerts found");
            expect(results[0].region).to.equal("global");
            done();
        });
    });

    it("should give unknown result if unable to query for Activity alerts", function (done) {
        const cache = createCache(null);
        mysqlFlexibleServerLoggingEnabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(3);
            expect(results[0].message).to.include("Unable to query for Activity Alerts");
            expect(results[0].region).to.equal("global");
            done();
        });
    });

    it("should give failing result if MySQL Flexible Server write and delete is not enabled", function (done) {
        const cache = createCache(null, [activityLogAlerts[0]]);
        mysqlFlexibleServerLoggingEnabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(2);
            expect(results[0].message).to.include(
                "Log Alert for MySQL Flexible Server write and delete is not enabled"
            );
            expect(results[0].region).to.equal("global");
            done();
        });
    });

    it("should give failing and passing results if MySQL Flexible Server delete is not enaled but write is enabled", function (done) {
        const cache = createCache(null, [activityLogAlerts[2]]);
        mysqlFlexibleServerLoggingEnabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(2);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.include(
                "Log alert for MySQL Flexible Server write is enabled"
            );
            expect(results[0].region).to.equal("global");
            expect(results[1].status).to.equal(2);
            expect(results[1].message).to.include(
                "Log Alert for MySQL Flexible Server delete is not enabled"
            );
            expect(results[0].region).to.equal("global");
            done();
        });
    });

    it("should give failing and passing results if MySQL Flexible Server write is not enaled but delete is enabled", function (done) {
        const cache = createCache(null, [activityLogAlerts[3]]);
        mysqlFlexibleServerLoggingEnabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(2);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.include(
                "Log alert for MySQL Flexible Server delete is enabled"
            );
            expect(results[0].region).to.equal("global");
            expect(results[1].status).to.equal(2);
            expect(results[1].message).to.include(
                "Log alert for MySQL Flexible Server write is not enabled"
            );
            expect(results[0].region).to.equal("global");
            done();
        });
    });

    it("should give passing result if MySQL Flexible Server Database write and delete is enabled", function (done) {
        const cache = createCache(null, [activityLogAlerts[1]]);
        mysqlFlexibleServerLoggingEnabled.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.include(
                "Log Alert for MySQL Flexible Server write and delete is enabled"
            );
            expect(results[0].region).to.equal("global");
            done();
        });
    });
  });
});
