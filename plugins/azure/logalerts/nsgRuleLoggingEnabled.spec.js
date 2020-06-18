var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./nsgRuleLoggingEnabled');

const createCache = (err, data) => {
    return {
        activityLogAlerts: {
            listBySubscriptionId: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('nsgRuleLoggingEnabled', function() {
    describe('run', function() {
        it('should give failing result if no activity log alerts found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing Activity Alerts found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            auth.run(cache, {}, callback);
        });

        it('should give failing result if nsg rule write not enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(2);
                expect(results[1].message).to.include('Log alert for Network Security Groups rule write is not enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
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
                                    "equals": "Security"
                                },
                                {
                                    "field": "operationName",
                                    "equals": "Microsoft.Network/networkSecurityGroups/securityRules/delete"
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
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should give failing result if nsg rule delete not enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(2);
                expect(results[1].message).to.include('Log Alert for Network Security Groups rule delete is not enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
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
                                    "equals": "Security"
                                },
                                {
                                    "field": "operationName",
                                    "equals": "Microsoft.Network/networkSecurityGroups/securityRules/write"
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
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if nsg rule write enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Log alert for Network Security Groups rule write is enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
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
                                    "equals": "Security"
                                },
                                {
                                    "field": "operationName",
                                    "equals": "Microsoft.Network/networkSecurityGroups/securityRules/write"
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
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if nsg rule delete enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Log alert for Network Security Groups rule delete is enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
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
                                    "equals": "Security"
                                },
                                {
                                    "field": "operationName",
                                    "equals": "Microsoft.Network/networkSecurityGroups/securityRules/delete"
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
                ]
            );

            auth.run(cache, {}, callback);
        });
    })
});