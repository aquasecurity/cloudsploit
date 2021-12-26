var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./sqlConfigurationLogging');

const createCache = (err, data, adata) => {
    return {
        metrics: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        },
        alertPolicies: {
            list: {
                'global': {
                    err: err,
                    data: adata
                }
            }
        }

    }
};

describe('sqlConfigurationLogging', function () {
    describe('run', function () {

        it('should give passing result if no metrics are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No log metrics found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
                []
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no alert policies are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No log alert policies found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                ['data'],
                []
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if log alert for sql configuration changes are enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Log alert for SQL configuration changes is enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "sqlConfigLogging",
                        "description": "Ensure log metric filter and alerts exists for Project Ownership assignments/changes",
                        "filter": "protoPayload.methodName=\"cloudsql.instances.update\"",
                        "metricDescriptor": {
                            "name": "projects/rosy-red-12345/metricDescriptors/logging.googleapis.com/user/sqlConfigLogging",
                            "metricKind": "DELTA",
                            "valueType": "INT64",
                            "unit": "1",
                            "description": "Ensure log metric filter and alerts exists for Project Ownership assignments/changes",
                            "type": "logging.googleapis.com/user/sqlConfigLogging"
                        },
                        "createTime": "2019-11-07T02:11:39.940887528Z",
                        "updateTime": "2019-11-07T19:19:18.101740507Z"
                    },
                    {
                        "name": "test1",
                        "filter": "resource.type=\"audited_resource\"\n",
                        "metricDescriptor": {
                            "name": "projects/rosy-red-12345/metricDescriptors/logging.googleapis.com/user/test1",
                            "metricKind": "DELTA",
                            "valueType": "DISTRIBUTION",
                            "type": "logging.googleapis.com/user/test1"
                        },
                        "valueExtractor": "EXTRACT(protoPayload.authorizationInfo.permission)",
                        "bucketOptions": {
                            "exponentialBuckets": {
                                "numFiniteBuckets": 64,
                                "growthFactor": 2,
                                "scale": 0.01
                            }
                        },
                        "createTime": "2019-11-07T01:58:47.997858699Z",
                        "updateTime": "2019-11-07T01:58:47.997858699Z"
                    }
                ],
                [
                    {
                        "name": "projects/rosy-red-12345/alertPolicies/16634295467069924965",
                        "displayName": "Threshold = user/",
                        "combiner": "OR",
                        "creationRecord": {
                            "mutateTime": "2019-11-07T19:07:11.377731588Z",
                            "mutatedBy": "giovanni@cloudsploit.com"
                        },
                        "mutationRecord": {
                            "mutateTime": "2019-11-07T19:07:11.377731588Z",
                            "mutatedBy": "giovanni@cloudsploit.com"
                        },
                        "conditions": [
                            {
                                "conditionThreshold": {
                                    "filter": "metric.type=\"logging.googleapis.com/user/sqlConfigLogging\" resource.type=\"metric\"",
                                    "comparison": "COMPARISON_GT",
                                    "thresholdValue": 0.001,
                                    "duration": "60s",
                                    "trigger": {
                                        "count": 1
                                    },
                                    "aggregations": [
                                        {
                                            "alignmentPeriod": "60s",
                                            "perSeriesAligner": "ALIGN_RATE"
                                        }
                                    ]
                                },
                                "displayName": "logging/user/sqlConfigLogging",
                                "name": "projects/rosy-red-12345/alertPolicies/16634295467069924965/conditions/16634295467069924590"
                            }
                        ],
                        "enabled": true
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if log alert for sql configuration changes are not enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Log metric for SQL configuration changes not found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "ProjectOwnershipAssignmentsChanges",
                        "description": "Ensure log metric filter and alerts exists for Project Ownership assignments/changes",
                        "filter": "(protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\") AND (ProjectOwnership OR projectOwnerInvitee) OR (protoPayload.serviceData.policyDelta.bindingDeltas.action=\"REMOVE\" AND protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\") OR (protoPayload.serviceData.policyDelta.bindingDeltas.action=\"ADD\" AND protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\")",
                        "metricDescriptor": {
                            "name": "projects/rosy-red-12345/metricDescriptors/logging.googleapis.com/user/ProjectOwnershipAssignmentsChanges",
                            "metricKind": "DELTA",
                            "valueType": "INT64",
                            "unit": "1",
                            "description": "Ensure log metric filter and alerts exists for Project Ownership assignments/changes",
                            "type": "logging.googleapis.com/user/ProjectOwnershipAssignmentsChanges"
                        },
                        "createTime": "2019-11-07T02:11:39.940887528Z",
                        "updateTime": "2019-11-07T19:19:18.101740507Z"
                    },
                    {
                        "name": "test1",
                        "filter": "resource.type=\"audited_resource\"\n",
                        "metricDescriptor": {
                            "name": "projects/rosy-red-12345/metricDescriptors/logging.googleapis.com/user/test1",
                            "metricKind": "DELTA",
                            "valueType": "DISTRIBUTION",
                            "type": "logging.googleapis.com/user/test1"
                        },
                        "valueExtractor": "EXTRACT(protoPayload.authorizationInfo.permission)",
                        "bucketOptions": {
                            "exponentialBuckets": {
                                "numFiniteBuckets": 64,
                                "growthFactor": 2,
                                "scale": 0.01
                            }
                        },
                        "createTime": "2019-11-07T01:58:47.997858699Z",
                        "updateTime": "2019-11-07T01:58:47.997858699Z"
                    }
                ],
                [
                    {
                        "name": "projects/rosy-red-12345/alertPolicies/16634295467069924965",
                        "displayName": "Threshold = user/",
                        "combiner": "OR",
                        "creationRecord": {
                            "mutateTime": "2019-11-07T19:07:11.377731588Z",
                            "mutatedBy": "giovanni@cloudsploit.com"
                        },
                        "mutationRecord": {
                            "mutateTime": "2019-11-07T19:07:11.377731588Z",
                            "mutatedBy": "giovanni@cloudsploit.com"
                        },
                        "conditions": [
                            {
                                "conditionThreshold": {
                                    "filter": "metric.type=\"logging.googleapis.com/user/loggingChanges\" resource.type=\"metric\"",
                                    "comparison": "COMPARISON_GT",
                                    "thresholdValue": 0.001,
                                    "duration": "60s",
                                    "trigger": {
                                        "count": 1
                                    },
                                    "aggregations": [
                                        {
                                            "alignmentPeriod": "60s",
                                            "perSeriesAligner": "ALIGN_RATE"
                                        }
                                    ]
                                },
                                "displayName": "logging/user/ProjectOwnershipAssignmentsChanges",
                                "name": "projects/rosy-red-12345/alertPolicies/16634295467069924965/conditions/16634295467069924590"
                            }
                        ],
                        "enabled": true
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
});
