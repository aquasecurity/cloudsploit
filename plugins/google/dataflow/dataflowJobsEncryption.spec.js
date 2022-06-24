var expect = require('chai').expect;
var plugin = require('./dataflowJobsEncryption');

const cryptoKeys = [
    {
        name: "projects/test-dev-aqua/locations/global/keyRings/test-kr/cryptoKeys/test-key-2",
        primary: {
            name: "projects/test-dev-aqua/locations/global/keyRings/test-kr/cryptoKeys/test-key-1/cryptoKeyVersions/1",
            state: "DESTROYED",
            createTime: "2021-06-17T08:01:36.739860492Z",
            destroyEventTime: "2021-06-18T11:17:00.798768Z",
            protectionLevel: "SOFTWARE",
            algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION",
            generateTime: "2021-06-17T08:01:36.739860492Z",
        },
        purpose: "ENCRYPT_DECRYPT",
        createTime: "2021-06-17T08:01:36.739860492Z",
        nextRotationTime: "2021-09-14T19:00:00Z",
        rotationPeriod: "7776000s",
        versionTemplate: {
            protectionLevel: "SOFTWARE",
            algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION",
        },
    }
];

const jobs = [
    {
        id: '2021-07-29_00_17_04-11865074052061045884',
        projectId: 'test-dev-aqua',
        name: 'test-made2',
        type: 'JOB_TYPE_BATCH',
        environment: {
          userAgent: {
            name: 'Apache Beam SDK for Java',
            'fnapi.environment.major.version': '8',
            'os.name': 'Linux',
            version: '2.29.0',
            'legacy.environment.major.version': '8',
            'os.version': '4.15.0-smp-913.27.0.0',
            'java.version': '11.0.11',
            'java.vendor': 'Google Inc.',
            'os.arch': 'amd64',
            'container.version': 'beam-2.29.0'
          },
          shuffleMode: 'SERVICE_BASED'
        },
        currentState: 'JOB_STATE_DONE',
        currentStateTime: '2021-07-29T07:22:00.002168Z',
        createTime: '2021-07-29T07:17:07.832499Z',
        location: 'europe-west1',
    },
    {
        id: '2021-07-29_00_17_04-11865074052061045884',
        projectId: 'test-dev-aqua',
        name: 'test-made2',
        type: 'JOB_TYPE_BATCH',
        environment: {
          userAgent: {
            name: 'Apache Beam SDK for Java',
            'fnapi.environment.major.version': '8',
            'os.name': 'Linux',
            version: '2.29.0',
            'legacy.environment.major.version': '8',
            'os.version': '4.15.0-smp-913.27.0.0',
            'java.version': '11.0.11',
            'java.vendor': 'Google Inc.',
            'os.arch': 'amd64',
            'container.version': 'beam-2.29.0'
          },
          serviceKmsKeyName: 'projects/test-dev-aqua/locations/global/keyRings/test-kr/cryptoKeys/test-key-2',
          shuffleMode: 'SERVICE_BASED'
        },
        currentState: 'JOB_STATE_DONE',
        currentStateTime: '2021-07-29T07:22:00.002168Z',
        createTime: '2021-07-29T07:17:07.832499Z',
        location: 'europe-west1',
    },
    {
        id: '2021-07-29_00_17_04-11865074052061045884',
        projectId: 'test-dev-aqua',
        name: 'test-made2',
        type: 'JOB_TYPE_STREAMING',
        environment: {
          userAgent: {
            name: 'Apache Beam SDK for Java',
            'fnapi.environment.major.version': '8',
            'os.name': 'Linux',
            version: '2.29.0',
            'legacy.environment.major.version': '8',
            'os.version': '4.15.0-smp-913.27.0.0',
            'java.version': '11.0.11',
            'java.vendor': 'Google Inc.',
            'os.arch': 'amd64',
            'container.version': 'beam-2.29.0'
          },
          shuffleMode: 'SERVICE_BASED'
        },
        currentState: 'JOB_STATE_DONE',
        currentStateTime: '2021-07-29T07:22:00.002168Z',
        createTime: '2021-07-29T07:17:07.832499Z',
        location: 'europe-west1',
    }
];

const createCache = (getJobs, errJobs, listKeys, errKeys) => {
    return {
        jobs: {
            get: {
                'us-east1': {
                    err: errJobs,
                    data: getJobs
                }
            }
        },
        cryptoKeys: {
            list: {
                'global': {
                    err: errKeys,
                    data: listKeys
                }
            }
        }
    }
};

describe('dataflowJobsEncryption', function () {
    describe('run', function () {
        it('should give passing result if no Dataflow jobs found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Dataflow jobs found');
                expect(results[0].region).to.equal('us-east1');
                done()
            };

            const cache = createCache(
                [],
                null,
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if Dataflow job is encrypted with desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('greater than or equal to');
                expect(results[0].region).to.equal('us-east1');
                done()
            };

            const cache = createCache(
                [jobs[1]],
                null,
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if Dataflow job is not of JOB_TYPE_BATCH type', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('CMEK is not supported');
                expect(results[0].region).to.equal('us-east1');
                done()
            };

            const cache = createCache(
                [jobs[2]],
                null,
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if Dataflow job is not encrypted with desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('which is less than');
                expect(results[0].region).to.equal('us-east1');
                done()
            };

            const cache = createCache(
                [jobs[0]],
                null,
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for Dataflow jobs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Dataflow jobs');
                expect(results[0].region).to.equal('us-east1');
                done()
            };

            const cache = createCache(
                [],
                {message: 'error'},
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        });
    })
});

