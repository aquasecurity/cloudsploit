var expect = require('chai').expect;
var plugin = require('./dataflowHangedJobs');

let failDate = new Date();
failDate.setHours(failDate.getHours() - 7);

const createCache = (err, data) => {
    return {
        jobs: {
            list: {
                'us-east1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('dataflowHangedJobs', function () {
    describe('run', function () {
        it('should give unknown result if a jobs error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Dataflow jobs');
                expect(results[0].region).to.equal('us-east1');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no Dataflow jobs are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Dataflow jobs found');
                expect(results[0].region).to.equal('us-east1');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if the Dataflow job has completed', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Dataflow job has completed');
                expect(results[0].region).to.equal('us-east1');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "2021-07-28_06_24_04-9234006834741851541",
                        "projectId": "test-dev-aqua",
                        "name": "test_job",
                        "type": "JOB_TYPE_BATCH",
                        "currentState": "JOB_STATE_DONE",
                        "currentStateTime": "2021-07-28T13:28:20.757358Z",
                        "createTime": "2021-07-28T13:24:06.416139Z",
                        "location": "us-central1",
                        "jobMetadata": {
                          "sdkVersion": {
                            "version": "2.29.0",
                            "versionDisplayName": "Apache Beam SDK for Java",
                            "sdkSupportStatus": "SUPPORTED"
                          }
                        },
                        "startTime": "2021-07-28T13:24:06.416139Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if the Dataflow job is in same state for less than set hours', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Dataflow job is in JOB_STATE_RUNNING');
                expect(results[0].region).to.equal('us-east1');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "2021-07-28_06_24_04-9234006834741851541",
                        "projectId": "test-dev-aqua",
                        "name": "test_job",
                        "type": "JOB_TYPE_BATCH",
                        "currentState": "JOB_STATE_RUNNING",
                        "currentStateTime": new Date(),
                        "createTime": "2021-07-28T13:24:06.416139Z",
                        "location": "us-central1",
                        "jobMetadata": {
                          "sdkVersion": {
                            "version": "2.29.0",
                            "versionDisplayName": "Apache Beam SDK for Java",
                            "sdkSupportStatus": "SUPPORTED"
                          }
                        },
                        "startTime": "2021-07-28T13:24:06.416139Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if the Dataflow job is in same state for more than set hours', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Dataflow job is in JOB_STATE_RUNNING');
                expect(results[0].region).to.equal('us-east1');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "2021-07-28_06_24_04-9234006834741851541",
                        "projectId": "test-dev-aqua",
                        "name": "test_job",
                        "type": "JOB_TYPE_BATCH",
                        "currentState": "JOB_STATE_RUNNING",
                        "currentStateTime": failDate,
                        "createTime": "2021-07-28T13:24:06.416139Z",
                        "location": "us-central1",
                        "jobMetadata": {
                          "sdkVersion": {
                            "version": "2.29.0",
                            "versionDisplayName": "Apache Beam SDK for Java",
                            "sdkSupportStatus": "SUPPORTED"
                          }
                        },
                        "startTime": "2021-07-28T13:24:06.416139Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });
    })
});