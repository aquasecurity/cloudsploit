var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./auditLoggingEnabled');

const createCache = (err, data) => {
    return {
        projects: {
            getIamPolicy: {
                'global': {
                    err: err,
                    data: data
                }
            },
        },
    }
};

describe('auditLoggingEnabled', function () {
    describe('run', function () {
        it('should give passing result if no iam policies are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No IAM policies found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result audit logging is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Audit logging is enabled on the project');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "version": 1,
                        "etag": "BwWXpk/552U=",
                        "auditConfigs": [
                            {
                                "service": "allServices",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ",
                                    },
                                    {
                                        "logType": "DATA_READ",
                                    },
                                    {
                                        "logType": "DATA_WRITE",
                                    }
                                ]
                            },
                            {
                                "service": "compute.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "accessapproval.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudasset.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudbilling.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudbuild.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "composer.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dlp.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dataproc.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "datastore.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudfunctions.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "healthcare.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "iap.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudiot.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudkms.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "ml.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "managedidentities.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "redis.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "pubsub.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudresourcemanager.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "runtimeconfig.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "sourcerepo.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "spanner.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudsql.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudtasks.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "tpu.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "translate.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "customerusagedataprocessing.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dialogflow.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "firebase.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "gcmcontextualcampaign-pa.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "genomics.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "appengine.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "deploymentmanager.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dns.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "storage.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "iam.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "identitytoolkit.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "container.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "vpcaccess.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "servicebroker.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "serviceusage.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "clouddebugger.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "clouderrorreporting.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "logging.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "monitoring.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudprofiler.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudtrace.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if audit logs are not properly configured', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Audit logging is not properly configured on the project');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "version": 1,
                        "etag": "BwWXpk/552U=",
                        "auditConfigs": [
                            {
                                "service": "allServices",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ",
                                        "exemptedMembers": [
                                            "serviceAccount:giovanni@right-weather-281330.iam.gserviceaccount.com"
                                        ]
                                    },
                                    {
                                        "logType": "DATA_WRITE",
                                        "exemptedMembers": [
                                            "serviceAccount:giovanni@right-weather-281330.iam.gserviceaccount.com"
                                        ]
                                    }
                                ]
                            },
                            {
                                "service": "compute.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "accessapproval.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudasset.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudbilling.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudbuild.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "composer.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dlp.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dataproc.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "datastore.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudfunctions.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "healthcare.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "iap.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudiot.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudkms.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "ml.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "managedidentities.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "redis.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "pubsub.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudresourcemanager.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "runtimeconfig.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "sourcerepo.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "spanner.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudsql.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudtasks.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "tpu.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "translate.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "customerusagedataprocessing.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dialogflow.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "firebase.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "gcmcontextualcampaign-pa.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "genomics.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "appengine.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "deploymentmanager.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dns.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "storage.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "iam.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "identitytoolkit.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "container.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "vpcaccess.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "servicebroker.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "serviceusage.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "clouddebugger.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "clouderrorreporting.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "logging.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "monitoring.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudprofiler.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudtrace.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if audit logging is not configured', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Audit logging is not enabled on the project');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "version": 1,
                        "etag": "BwWXpk/552U=",
                        "auditConfigs": [
                            {
                                "service": "compute.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "accessapproval.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudasset.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudbilling.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudbuild.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "composer.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dlp.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dataproc.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "datastore.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudfunctions.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "healthcare.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "iap.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudiot.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudkms.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "ml.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "managedidentities.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "redis.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "pubsub.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudresourcemanager.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "runtimeconfig.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "sourcerepo.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "spanner.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudsql.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudtasks.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "tpu.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "translate.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "customerusagedataprocessing.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dialogflow.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "firebase.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "gcmcontextualcampaign-pa.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "genomics.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "appengine.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "deploymentmanager.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dns.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "storage.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "iam.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "identitytoolkit.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "container.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "vpcaccess.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "servicebroker.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "serviceusage.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "clouddebugger.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "clouderrorreporting.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "logging.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "monitoring.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudprofiler.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudtrace.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if exempted members exist on a project', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Default audit configuration has exempted members');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "version": 1,
                        "etag": "BwWXpk/552U=",
                        "auditConfigs": [
                            {
                                "service": "allServices",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ",
                                        "exemptedMembers": [
                                            "serviceAccount:giovanni@right-weather-281330.iam.gserviceaccount.com"
                                        ]
                                    },
                                    {
                                        "logType": "DATA_READ",
                                        "exemptedMembers": [
                                            "serviceAccount:giovanni@right-weather-281330.iam.gserviceaccount.com"
                                        ]
                                    },
                                    {
                                        "logType": "DATA_WRITE",
                                        "exemptedMembers": [
                                            "serviceAccount:giovanni@right-weather-281330.iam.gserviceaccount.com"
                                        ]
                                    }
                                ]
                            },
                            {
                                "service": "compute.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "accessapproval.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudasset.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudbilling.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudbuild.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "composer.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dlp.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dataproc.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "datastore.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudfunctions.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "healthcare.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "iap.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudiot.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudkms.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "ml.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "managedidentities.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "redis.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "pubsub.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudresourcemanager.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "runtimeconfig.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "sourcerepo.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "spanner.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudsql.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudtasks.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "tpu.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "translate.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "customerusagedataprocessing.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dialogflow.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "firebase.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "gcmcontextualcampaign-pa.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "genomics.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "appengine.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "deploymentmanager.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "dns.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "storage.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "iam.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "identitytoolkit.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "container.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "vpcaccess.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "servicebroker.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "serviceusage.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "clouddebugger.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "clouderrorreporting.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "logging.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "monitoring.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudprofiler.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            },
                            {
                                "service": "cloudtrace.googleapis.com",
                                "auditLogConfigs": [
                                    {
                                        "logType": "ADMIN_READ"
                                    },
                                    {
                                        "logType": "DATA_READ"
                                    },
                                    {
                                        "logType": "DATA_WRITE"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
});
