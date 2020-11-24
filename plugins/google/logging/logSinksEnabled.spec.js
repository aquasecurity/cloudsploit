var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./logSinksEnabled');

const createCache = (err, data, adata) => {
    return {
        sinks: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        },
        buckets: {
            list: {
                'global': {
                    err: err,
                    data: adata
                }
            }
        }

    }
};

describe('logSinksEnabled', function () {
    describe('run', function () {

        it('should give passing result if no sinks are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No sinks found');
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

        it('should give passing result if the log sink is properly configured', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The log sink is properly configured');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "bigquerytest1",
                        "destination": "bigquery.googleapis.com/projects/free-ocean-281330/datasets/bigquerytest1",
                        "filter": "resource.type=\"all_resources\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-544288@gcp-sa-logging.iam.gserviceaccount.com",
                        "bigqueryOptions": {},
                        "createTime": "2019-11-19T18:56:10.471870987Z",
                        "updateTime": "2019-11-19T18:56:10.471870987Z"
                    },
                    {
                        "name": "logBucketStorage",
                        "destination": "storage.googleapis.com/ggtestbucketsink",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-489680@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-13T01:14:03.507757634Z",
                        "updateTime": "2019-11-13T01:14:03.507757634Z"
                    },
                    {
                        "name": "pubsubtest1",
                        "destination": "pubsub.googleapis.com/projects/free-ocean-281330/topics/giotest1",
                        "filter": "resource.type=\"audited_resource\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-527679@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-19T18:55:34.931762919Z",
                        "updateTime": "2019-11-19T18:55:34.931762919Z"
                    },
                    {
                        "name": "testexport11",
                        "destination": "storage.googleapis.com/bbbucket12324536",
                        "filter": "resource.type=\"iam_role\" AND protoPayload.methodName=\"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-910275@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-18T23:44:48.080576987Z",
                        "updateTime": "2019-11-18T23:44:48.080576987Z"
                    }
                ],
                [
                    {
                        "kind": "storage#bucket",
                        "id": "bbbucket12324536",
                        "selfLink": "https://www.googleapis.com/storage/v1/b/bbbucket12324536",
                        "projectNumber": "281330800432",
                        "name": "bbbucket12324536",
                        "metageneration": "2",
                        "location": "US",
                        "defaultEventBasedHold": false,
                        "storageClass": "STANDARD",
                        "etag": "CAI=",
                        "iamConfiguration": {
                            "bucketPolicyOnly": {
                                "enabled": false
                            },
                            "uniformBucketLevelAccess": {
                                "enabled": false
                            }
                        },
                        "locationType": "multi-region",
                        "timeCreated": "2019-11-18T23:44:39.003Z",
                        "updated": "2019-11-18T23:44:48.959Z"
                    },
                    {
                        "kind": "storage#bucket",
                        "id": "ggtestbucketsink",
                        "selfLink": "https://www.googleapis.com/storage/v1/b/ggtestbucketsink",
                        "projectNumber": "281330800432",
                        "name": "ggtestbucketsink",
                        "metageneration": "3",
                        "location": "US-EAST1",
                        "versioning": {
                            "enabled": true
                        },
                        "defaultEventBasedHold": false,
                        "storageClass": "STANDARD",
                        "etag": "CAM=",
                        "iamConfiguration": {
                            "bucketPolicyOnly": {
                                "enabled": false
                            },
                            "uniformBucketLevelAccess": {
                                "enabled": false
                            }
                        },
                        "locationType": "region",
                        "timeCreated": "2019-11-13T01:13:31.640Z",
                        "updated": "2019-11-13T01:28:25.063Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if bucket versioning is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include('Log bucket versioning is enabled');
                expect(results[1].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "bigquerytest1",
                        "destination": "bigquery.googleapis.com/projects/free-ocean-281330/datasets/bigquerytest1",
                        "filter": "resource.type=\"all_resources\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-544288@gcp-sa-logging.iam.gserviceaccount.com",
                        "bigqueryOptions": {},
                        "createTime": "2019-11-19T18:56:10.471870987Z",
                        "updateTime": "2019-11-19T18:56:10.471870987Z"
                    },
                    {
                        "name": "logBucketStorage",
                        "destination": "storage.googleapis.com/ggtestbucketsink",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-489680@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-13T01:14:03.507757634Z",
                        "updateTime": "2019-11-13T01:14:03.507757634Z"
                    },
                    {
                        "name": "pubsubtest1",
                        "destination": "pubsub.googleapis.com/projects/free-ocean-281330/topics/giotest1",
                        "filter": "resource.type=\"audited_resource\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-527679@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-19T18:55:34.931762919Z",
                        "updateTime": "2019-11-19T18:55:34.931762919Z"
                    },
                    {
                        "name": "testexport11",
                        "destination": "storage.googleapis.com/bbbucket12324536",
                        "filter": "resource.type=\"iam_role\" AND protoPayload.methodName=\"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-910275@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-18T23:44:48.080576987Z",
                        "updateTime": "2019-11-18T23:44:48.080576987Z"
                    }
                ],
                [
                    {
                        "kind": "storage#bucket",
                        "id": "bbbucket12324536",
                        "selfLink": "https://www.googleapis.com/storage/v1/b/bbbucket12324536",
                        "projectNumber": "281330800432",
                        "name": "bbbucket12324536",
                        "metageneration": "2",
                        "location": "US",
                        "defaultEventBasedHold": false,
                        "storageClass": "STANDARD",
                        "etag": "CAI=",
                        "iamConfiguration": {
                            "bucketPolicyOnly": {
                                "enabled": false
                            },
                            "uniformBucketLevelAccess": {
                                "enabled": false
                            }
                        },
                        "locationType": "multi-region",
                        "timeCreated": "2019-11-18T23:44:39.003Z",
                        "updated": "2019-11-18T23:44:48.959Z"
                    },
                    {
                        "kind": "storage#bucket",
                        "id": "ggtestbucketsink",
                        "selfLink": "https://www.googleapis.com/storage/v1/b/ggtestbucketsink",
                        "projectNumber": "281330800432",
                        "name": "ggtestbucketsink",
                        "metageneration": "3",
                        "location": "US-EAST1",
                        "versioning": {
                            "enabled": true
                        },
                        "defaultEventBasedHold": false,
                        "storageClass": "STANDARD",
                        "etag": "CAM=",
                        "iamConfiguration": {
                            "bucketPolicyOnly": {
                                "enabled": false
                            },
                            "uniformBucketLevelAccess": {
                                "enabled": false
                            }
                        },
                        "locationType": "region",
                        "timeCreated": "2019-11-13T01:13:31.640Z",
                        "updated": "2019-11-13T01:28:25.063Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if bucket versioning is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[1].status).to.equal(2);
                expect(results[1].message).to.include('Log bucket versioning is disabled');
                expect(results[1].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "bigquerytest1",
                        "destination": "bigquery.googleapis.com/projects/free-ocean-281330/datasets/bigquerytest1",
                        "filter": "resource.type=\"all_resources\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-544288@gcp-sa-logging.iam.gserviceaccount.com",
                        "bigqueryOptions": {},
                        "createTime": "2019-11-19T18:56:10.471870987Z",
                        "updateTime": "2019-11-19T18:56:10.471870987Z"
                    },
                    {
                        "name": "logBucketStorage",
                        "destination": "storage.googleapis.com/ggtestbucketsink",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-489680@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-13T01:14:03.507757634Z",
                        "updateTime": "2019-11-13T01:14:03.507757634Z"
                    },
                    {
                        "name": "pubsubtest1",
                        "destination": "pubsub.googleapis.com/projects/free-ocean-281330/topics/giotest1",
                        "filter": "resource.type=\"audited_resource\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-527679@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-19T18:55:34.931762919Z",
                        "updateTime": "2019-11-19T18:55:34.931762919Z"
                    },
                    {
                        "name": "testexport11",
                        "destination": "storage.googleapis.com/bbbucket12324536",
                        "filter": "resource.type=\"iam_role\" AND protoPayload.methodName=\"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-910275@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-18T23:44:48.080576987Z",
                        "updateTime": "2019-11-18T23:44:48.080576987Z"
                    }
                ],
                [
                    {
                        "kind": "storage#bucket",
                        "id": "bbbucket12324536",
                        "selfLink": "https://www.googleapis.com/storage/v1/b/bbbucket12324536",
                        "projectNumber": "281330800432",
                        "name": "bbbucket12324536",
                        "metageneration": "2",
                        "location": "US",
                        "defaultEventBasedHold": false,
                        "storageClass": "STANDARD",
                        "etag": "CAI=",
                        "iamConfiguration": {
                            "bucketPolicyOnly": {
                                "enabled": false
                            },
                            "uniformBucketLevelAccess": {
                                "enabled": false
                            }
                        },
                        "locationType": "multi-region",
                        "timeCreated": "2019-11-18T23:44:39.003Z",
                        "updated": "2019-11-18T23:44:48.959Z"
                    },
                    {
                        "kind": "storage#bucket",
                        "id": "ggtestbucketsink",
                        "selfLink": "https://www.googleapis.com/storage/v1/b/ggtestbucketsink",
                        "projectNumber": "281330800432",
                        "name": "ggtestbucketsink",
                        "metageneration": "3",
                        "location": "US-EAST1",
                        "versioning": {
                            "enabled": false
                        },
                        "defaultEventBasedHold": false,
                        "storageClass": "STANDARD",
                        "etag": "CAM=",
                        "iamConfiguration": {
                            "bucketPolicyOnly": {
                                "enabled": false
                            },
                            "uniformBucketLevelAccess": {
                                "enabled": false
                            }
                        },
                        "locationType": "region",
                        "timeCreated": "2019-11-13T01:13:31.640Z",
                        "updated": "2019-11-13T01:28:25.063Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if no buckets found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No log bucket found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "bigquerytest1",
                        "destination": "bigquery.googleapis.com/projects/free-ocean-281330/datasets/bigquerytest1",
                        "filter": "resource.type=\"all_resources\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-544288@gcp-sa-logging.iam.gserviceaccount.com",
                        "bigqueryOptions": {},
                        "createTime": "2019-11-19T18:56:10.471870987Z",
                        "updateTime": "2019-11-19T18:56:10.471870987Z"
                    },
                    {
                        "name": "logBucketStorage",
                        "destination": "storage.googleapis.com/ggtestbucketsink",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-489680@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-13T01:14:03.507757634Z",
                        "updateTime": "2019-11-13T01:14:03.507757634Z"
                    },
                    {
                        "name": "pubsubtest1",
                        "destination": "pubsub.googleapis.com/projects/free-ocean-281330/topics/giotest1",
                        "filter": "resource.type=\"audited_resource\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-527679@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-19T18:55:34.931762919Z",
                        "updateTime": "2019-11-19T18:55:34.931762919Z"
                    },
                    {
                        "name": "testexport11",
                        "destination": "storage.googleapis.com/bbbucket12324536",
                        "filter": "resource.type=\"iam_role\" AND protoPayload.methodName=\"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-910275@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-18T23:44:48.080576987Z",
                        "updateTime": "2019-11-18T23:44:48.080576987Z"
                    }
                ],
                []
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if the log bucket does not exist', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The log bucket: ggtestbucketsink does not exist');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "bigquerytest1",
                        "destination": "bigquery.googleapis.com/projects/free-ocean-281330/datasets/bigquerytest1",
                        "filter": "resource.type=\"all_resources\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-544288@gcp-sa-logging.iam.gserviceaccount.com",
                        "bigqueryOptions": {},
                        "createTime": "2019-11-19T18:56:10.471870987Z",
                        "updateTime": "2019-11-19T18:56:10.471870987Z"
                    },
                    {
                        "name": "logBucketStorage",
                        "destination": "storage.googleapis.com/ggtestbucketsink",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-489680@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-13T01:14:03.507757634Z",
                        "updateTime": "2019-11-13T01:14:03.507757634Z"
                    },
                    {
                        "name": "pubsubtest1",
                        "destination": "pubsub.googleapis.com/projects/free-ocean-281330/topics/giotest1",
                        "filter": "resource.type=\"audited_resource\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-527679@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-19T18:55:34.931762919Z",
                        "updateTime": "2019-11-19T18:55:34.931762919Z"
                    },
                    {
                        "name": "testexport11",
                        "destination": "storage.googleapis.com/bbbucket12324536",
                        "filter": "resource.type=\"iam_role\" AND protoPayload.methodName=\"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-910275@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-18T23:44:48.080576987Z",
                        "updateTime": "2019-11-18T23:44:48.080576987Z"
                    }
                ],
                [
                    {
                        "kind": "storage#bucket",
                        "id": "bbbucket12324536",
                        "selfLink": "https://www.googleapis.com/storage/v1/b/bbbucket12324536",
                        "projectNumber": "281330800432",
                        "name": "bbbucket12324536",
                        "metageneration": "2",
                        "location": "US",
                        "defaultEventBasedHold": false,
                        "storageClass": "STANDARD",
                        "etag": "CAI=",
                        "iamConfiguration": {
                            "bucketPolicyOnly": {
                                "enabled": false
                            },
                            "uniformBucketLevelAccess": {
                                "enabled": false
                            }
                        },
                        "locationType": "multi-region",
                        "timeCreated": "2019-11-18T23:44:39.003Z",
                        "updated": "2019-11-18T23:44:48.959Z"
                    },
                ]
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if the log sink is not enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No log sinks are enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "bigquerytest1",
                        "destination": "bigquery.googleapis.com/projects/free-ocean-281330/datasets/bigquerytest1",
                        "filter": "resource.type=\"all_resources\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-544288@gcp-sa-logging.iam.gserviceaccount.com",
                        "bigqueryOptions": {},
                        "createTime": "2019-11-19T18:56:10.471870987Z",
                        "updateTime": "2019-11-19T18:56:10.471870987Z"
                    },
                    {
                        "name": "pubsubtest1",
                        "destination": "pubsub.googleapis.com/projects/free-ocean-281330/topics/giotest1",
                        "filter": "resource.type=\"audited_resource\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-527679@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-19T18:55:34.931762919Z",
                        "updateTime": "2019-11-19T18:55:34.931762919Z"
                    },
                    {
                        "name": "testexport11",
                        "destination": "storage.googleapis.com/bbbucket12324536",
                        "filter": "resource.type=\"iam_role\" AND protoPayload.methodName=\"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\"",
                        "outputVersionFormat": "V2",
                        "writerIdentity": "serviceAccount:p281330800432-910275@gcp-sa-logging.iam.gserviceaccount.com",
                        "createTime": "2019-11-18T23:44:48.080576987Z",
                        "updateTime": "2019-11-18T23:44:48.080576987Z"
                    }
                ],
                [
                    {
                        "kind": "storage#bucket",
                        "id": "bbbucket12324536",
                        "selfLink": "https://www.googleapis.com/storage/v1/b/bbbucket12324536",
                        "projectNumber": "281330800432",
                        "name": "bbbucket12324536",
                        "metageneration": "2",
                        "location": "US",
                        "defaultEventBasedHold": false,
                        "storageClass": "STANDARD",
                        "etag": "CAI=",
                        "iamConfiguration": {
                            "bucketPolicyOnly": {
                                "enabled": false
                            },
                            "uniformBucketLevelAccess": {
                                "enabled": false
                            }
                        },
                        "locationType": "multi-region",
                        "timeCreated": "2019-11-18T23:44:39.003Z",
                        "updated": "2019-11-18T23:44:48.959Z"
                    },
                    {
                        "kind": "storage#bucket",
                        "id": "ggtestbucketsink",
                        "selfLink": "https://www.googleapis.com/storage/v1/b/ggtestbucketsink",
                        "projectNumber": "281330800432",
                        "name": "ggtestbucketsink",
                        "metageneration": "3",
                        "location": "US-EAST1",
                        "versioning": {
                            "enabled": true
                        },
                        "defaultEventBasedHold": false,
                        "storageClass": "STANDARD",
                        "etag": "CAM=",
                        "iamConfiguration": {
                            "bucketPolicyOnly": {
                                "enabled": false
                            },
                            "uniformBucketLevelAccess": {
                                "enabled": false
                            }
                        },
                        "locationType": "region",
                        "timeCreated": "2019-11-13T01:13:31.640Z",
                        "updated": "2019-11-13T01:28:25.063Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
});
